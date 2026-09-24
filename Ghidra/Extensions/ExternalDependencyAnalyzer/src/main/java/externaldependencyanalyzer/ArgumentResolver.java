/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package externaldependencyanalyzer;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers constant integer and pointer arguments at call sites. PCode-based constant
 * propagation ({@link SymbolicPropogator}) is tried first; a bounded backward walk over the
 * instructions of the same function is the fallback.
 */
final class ArgumentResolver {

	/** A resolved argument. {@code pcode} is false when the fallback heuristic produced it. */
	record Resolved(long value, boolean pcode) {
	}

	private static final int MAX_ARGS = 8;
	private static final int MAX_BACKWARD_INSTRUCTIONS = 40;
	private static final long MAX_PROPAGATED_FUNCTION_BYTES = 256 * 1024;

	private final Program program;
	private final TaskMonitor monitor;
	private final Register[] argRegisters;
	private final Map<Address, SymbolicPropogator> propagators = new HashMap<>();
	private final Set<Address> propagationFailed = new HashSet<>();

	ArgumentResolver(Program program, TaskMonitor monitor) {
		this.program = program;
		this.monitor = monitor;
		this.argRegisters = computeArgumentRegisters(program);
	}

	boolean supportsRegisterArguments() {
		return argRegisters.length > 0;
	}

	private static Register[] computeArgumentRegisters(Program program) {
		try {
			PrototypeModel model = program.getCompilerSpec().getDefaultCallingConvention();
			if (model == null) {
				return new Register[0];
			}
			DataType[] types = new DataType[MAX_ARGS + 1];
			types[0] = VoidDataType.dataType;
			for (int i = 1; i <= MAX_ARGS; i++) {
				types[i] = new PointerDataType(program.getDataTypeManager());
			}
			VariableStorage[] storage = model.getStorageLocations(program, types, false);
			List<Register> regs = new ArrayList<>();
			for (int i = 1; i < storage.length; i++) {
				Register r = storage[i] != null ? storage[i].getRegister() : null;
				if (r == null) {
					break;
				}
				regs.add(r);
			}
			return regs.toArray(new Register[0]);
		}
		catch (RuntimeException e) {
			Msg.warn(ArgumentResolver.class, "Calling convention not available: " + e.getMessage());
			return new Register[0];
		}
	}

	Resolved resolve(Instruction callInstr, Function function, int argIndex)
			throws CancelledException {
		if (argIndex < 0 || argIndex >= argRegisters.length || function == null) {
			return null;
		}
		Register reg = argRegisters[argIndex];
		Resolved r = resolveWithPropagation(callInstr, function, reg);
		if (r != null) {
			return r;
		}
		return resolveByBackwardWalk(callInstr, function, reg);
	}

	private Resolved resolveWithPropagation(Instruction callInstr, Function function,
			Register reg) throws CancelledException {
		Address entry = function.getEntryPoint();
		if (propagationFailed.contains(entry)) {
			return null;
		}
		SymbolicPropogator prop = propagators.get(entry);
		if (prop == null) {
			if (function.getBody().getNumAddresses() > MAX_PROPAGATED_FUNCTION_BYTES) {
				propagationFailed.add(entry);
				return null;
			}
			try {
				prop = new SymbolicPropogator(program);
				prop.setParamRefCheck(false);
				prop.setReturnRefCheck(false);
				prop.setStoredRefCheck(false);
				prop.flowConstants(entry, function.getBody(), new ContextEvaluatorAdapter(),
					false, monitor);
				propagators.put(entry, prop);
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (RuntimeException e) {
				Msg.debug(this, "Constant propagation failed in " +
					DependencyScanner.functionName(function));
				propagationFailed.add(entry);
				return null;
			}
		}
		try {
			SymbolicPropogator.Value v = prop.getRegisterValue(callInstr.getAddress(), reg);
			if (v == null || v.isRegisterRelativeValue()) {
				return null;
			}
			return new Resolved(v.getValue(), true);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private Resolved resolveByBackwardWalk(Instruction callInstr, Function function,
			Register reg) {
		Instruction cur = callInstr.getPrevious();
		int steps = 0;
		while (cur != null && steps++ < MAX_BACKWARD_INSTRUCTIONS &&
			function.getBody().contains(cur.getAddress())) {
			if (writesRegister(cur, reg)) {
				return valueWrittenBy(cur, reg);
			}
			if (cur.getFlowType().isCall() || cur.getFlowType().isJump()) {
				return null;
			}
			cur = cur.getPrevious();
		}
		return null;
	}

	private static boolean writesRegister(Instruction instr, Register reg) {
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && overlaps(r, reg)) {
				return true;
			}
		}
		return false;
	}

	private static boolean overlaps(Register a, Register b) {
		return a.equals(b) || a.contains(b) || b.contains(a) ||
			a.getBaseRegister().equals(b.getBaseRegister());
	}

	private Resolved valueWrittenBy(Instruction instr, Register reg) {
		int loadSize = loadSize(instr);
		for (Reference ref : instr.getReferencesFrom()) {
			RefType type = ref.getReferenceType();
			if (!ref.isMemoryReference() || !ref.getToAddress().isMemoryAddress() ||
				type.isFlow()) {
				continue;
			}
			if (type.isWrite()) {
				return null;
			}
			if (type.isRead() || loadSize > 0) {
				return constantLoadedFrom(ref.getToAddress(), loadSize > 0 ? loadSize
						: program.getDefaultPointerSize());
			}
			return new Resolved(ref.getToAddress().getOffset(), false);
		}
		String mnemonic = instr.getMnemonicString().toLowerCase(Locale.ROOT);
		int n = instr.getNumOperands();
		if ((mnemonic.equals("xor") || mnemonic.equals("eor")) && n >= 2) {
			Object[] a = instr.getOpObjects(0);
			Object[] b = instr.getOpObjects(n - 1);
			if (a.length == 1 && b.length == 1 && a[0].equals(b[0])) {
				return new Resolved(0, false);
			}
		}
		if (loadSize == 0 && (mnemonic.startsWith("mov") || mnemonic.equals("li") ||
			mnemonic.equals("ldr") || mnemonic.equals("lea"))) {
			for (int i = 1; i < n; i++) {
				for (Object o : instr.getOpObjects(i)) {
					if (o instanceof Scalar s) {
						return new Resolved(s.getUnsignedValue(), false);
					}
					if (o instanceof Register r && (r.getName().equals("wzr") ||
						r.getName().equals("xzr"))) {
						return new Resolved(0, false);
					}
				}
			}
		}
		for (PcodeOp op : instr.getPcode()) {
			if (op.getOpcode() == PcodeOp.COPY && op.getOutput() != null &&
				op.getOutput().isRegister()) {
				Register out = program.getRegister(op.getOutput());
				Varnode in = op.getInput(0);
				if (out != null && overlaps(out, reg) && in.isConstant()) {
					return new Resolved(in.getOffset(), false);
				}
			}
		}
		return null;
	}

	private static int loadSize(Instruction instr) {
		for (PcodeOp op : instr.getPcode()) {
			if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null) {
				return op.getOutput().getSize();
			}
		}
		return 0;
	}

	private Resolved constantLoadedFrom(Address addr, int size) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized() || block.isWrite() || size < 1 || size > 8 ||
			block.getEnd().subtract(addr) < size - 1) {
			return null;
		}
		byte[] buf = new byte[size];
		try {
			if (memory.getBytes(addr, buf) != size) {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		long v = 0;
		for (int i = 0; i < size; i++) {
			int idx = memory.isBigEndian() ? i : size - 1 - i;
			v = (v << 8) | (buf[idx] & 0xffL);
		}
		return new Resolved(v, false);
	}
}
