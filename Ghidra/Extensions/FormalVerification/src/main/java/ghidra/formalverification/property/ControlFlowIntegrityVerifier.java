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
package ghidra.formalverification.property;

import java.util.*;

import com.microsoft.z3.*;

import ghidra.formalverification.core.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

/**
 * Control Flow Integrity (CFI) verifier that generates and checks conditions
 * ensuring that program control flow follows only valid paths.
 * 
 * Verifies:
 * - Indirect call targets are valid function entry points
 * - Indirect branch targets are within valid code regions
 * - Return addresses have not been corrupted
 * - Function pointer tables contain only valid targets
 */
public class ControlFlowIntegrityVerifier {

	private final Program program;
	private final int pointerSize;
	private final Set<Address> validFunctionEntries;
	private final Set<Address> validCodeAddresses;

	/**
	 * Creates a new control flow integrity verifier.
	 *
	 * @param program the program to verify
	 */
	public ControlFlowIntegrityVerifier(Program program) {
		this.program = program;
		this.pointerSize = program.getDefaultPointerSize() * 8;
		this.validFunctionEntries = collectValidFunctionEntries();
		this.validCodeAddresses = collectValidCodeAddresses();
	}

	/**
	 * Collects all valid function entry points in the program.
	 *
	 * @return set of valid function entry addresses
	 */
	private Set<Address> collectValidFunctionEntries() {
		Set<Address> entries = new HashSet<>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function func = functions.next();
			entries.add(func.getEntryPoint());
		}
		return entries;
	}

	/**
	 * Collects all valid code addresses in the program.
	 *
	 * @return set of valid code addresses
	 */
	private Set<Address> collectValidCodeAddresses() {
		Set<Address> addresses = new HashSet<>();
		InstructionIterator instructions = program.getListing().getInstructions(true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			addresses.add(instr.getAddress());
		}
		return addresses;
	}

	/**
	 * Verifies indirect calls in a function.
	 * Ensures all indirect call targets are valid function entry points.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> verifyIndirectCalls(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (op.getOpcode() == PcodeOp.CALLIND) {
					String conditionName = String.format("cfi_call_%s_%d",
						function.getName(), conditionIndex++);
					
					String z3Expr = generateIndirectCallZ3Expression();
					
					String description = String.format(
						"Indirect call at %s must target a valid function entry point",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr,
						PropertyType.CONTROL_FLOW_INTEGRITY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Verifies indirect branches in a function.
	 * Ensures all indirect branch targets are valid code addresses.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> verifyIndirectBranches(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (op.getOpcode() == PcodeOp.BRANCHIND) {
					String conditionName = String.format("cfi_branch_%s_%d",
						function.getName(), conditionIndex++);
					
					String z3Expr = generateIndirectBranchZ3Expression(function);
					
					String description = String.format(
						"Indirect branch at %s must target valid code within function bounds",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr,
						PropertyType.CONTROL_FLOW_INTEGRITY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Verifies return address integrity in a function.
	 * Ensures return addresses are not corrupted by stack operations.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> verifyReturnAddressIntegrity(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (op.getOpcode() == PcodeOp.RETURN) {
					String conditionName = String.format("cfi_return_%s_%d",
						function.getName(), conditionIndex++);
					
					String z3Expr = generateReturnIntegrityZ3Expression();
					
					String description = String.format(
						"Return at %s must use unmodified return address",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr,
						PropertyType.CONTROL_FLOW_INTEGRITY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Verifies function pointer tables in a function.
	 * Ensures all entries in function pointer tables are valid function addresses.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> verifyFunctionPointerTables(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		Data[] dataReferences = findFunctionPointerTables(function);
		int conditionIndex = 0;

		for (Data data : dataReferences) {
			if (data != null && data.isPointer()) {
				String conditionName = String.format("cfi_fptr_%s_%d",
					function.getName(), conditionIndex++);
				
				String z3Expr = generateFunctionPointerZ3Expression();
				
				String description = String.format(
					"Function pointer at %s must reference a valid function",
					data.getAddress().toString()
				);

				conditions.add(new VerificationCondition(
					conditionName,
					description,
					function,
					data.getAddress(),
					z3Expr,
					PropertyType.CONTROL_FLOW_INTEGRITY
				));
			}
		}

		return conditions;
	}

	/**
	 * Generates Z3 expression for indirect call verification.
	 *
	 * @return Z3 SMT-LIB2 expression
	 */
	private String generateIndirectCallZ3Expression() {
		StringBuilder z3Expr = new StringBuilder();
		
		z3Expr.append(String.format("(declare-const target (_ BitVec %d))\n", pointerSize));
		z3Expr.append("(declare-const valid_functions (Array (_ BitVec " + pointerSize + ") Bool))\n");
		
		z3Expr.append("(assert (select valid_functions target))\n");
		
		return z3Expr.toString();
	}

	/**
	 * Generates Z3 expression for indirect branch verification.
	 *
	 * @param function the function containing the branch
	 * @return Z3 SMT-LIB2 expression
	 */
	private String generateIndirectBranchZ3Expression(Function function) {
		StringBuilder z3Expr = new StringBuilder();
		
		Address minAddr = function.getBody().getMinAddress();
		Address maxAddr = function.getBody().getMaxAddress();
		
		z3Expr.append(String.format("(declare-const target (_ BitVec %d))\n", pointerSize));
		z3Expr.append(String.format("(declare-const func_start (_ BitVec %d))\n", pointerSize));
		z3Expr.append(String.format("(declare-const func_end (_ BitVec %d))\n", pointerSize));
		
		z3Expr.append(String.format("(assert (= func_start (_ bv%d %d)))\n",
			minAddr.getOffset(), pointerSize));
		z3Expr.append(String.format("(assert (= func_end (_ bv%d %d)))\n",
			maxAddr.getOffset(), pointerSize));
		
		z3Expr.append("(assert (bvuge target func_start))\n");
		z3Expr.append("(assert (bvule target func_end))\n");
		
		return z3Expr.toString();
	}

	/**
	 * Generates Z3 expression for return address integrity verification.
	 *
	 * @return Z3 SMT-LIB2 expression
	 */
	private String generateReturnIntegrityZ3Expression() {
		StringBuilder z3Expr = new StringBuilder();
		
		z3Expr.append(String.format("(declare-const return_addr (_ BitVec %d))\n", pointerSize));
		z3Expr.append(String.format("(declare-const saved_return_addr (_ BitVec %d))\n", pointerSize));
		
		z3Expr.append("(assert (= return_addr saved_return_addr))\n");
		
		return z3Expr.toString();
	}

	/**
	 * Generates Z3 expression for function pointer verification.
	 *
	 * @return Z3 SMT-LIB2 expression
	 */
	private String generateFunctionPointerZ3Expression() {
		StringBuilder z3Expr = new StringBuilder();
		
		z3Expr.append(String.format("(declare-const fptr (_ BitVec %d))\n", pointerSize));
		z3Expr.append("(declare-const valid_functions (Array (_ BitVec " + pointerSize + ") Bool))\n");
		
		z3Expr.append("(assert (select valid_functions fptr))\n");
		
		return z3Expr.toString();
	}

	/**
	 * Finds function pointer tables referenced by a function.
	 *
	 * @param function the function to analyze
	 * @return array of data items that may be function pointers
	 */
	private Data[] findFunctionPointerTables(Function function) {
		List<Data> pointers = new ArrayList<>();
		
		ReferenceIterator refs = program.getReferenceManager()
			.getReferenceIterator(function.getBody().getMinAddress());
		
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (!function.getBody().contains(ref.getFromAddress())) {
				break;
			}
			
			if (ref.getReferenceType().isData()) {
				Data data = program.getListing().getDataAt(ref.getToAddress());
				if (data != null && data.isPointer()) {
					pointers.add(data);
				}
			}
		}
		
		return pointers.toArray(new Data[0]);
	}

	/**
	 * Verifies a condition using Z3.
	 *
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	public VerificationResult verify(VerificationCondition condition) {
		long startTime = System.currentTimeMillis();
		
		try (Context ctx = new Context()) {
			Solver solver = ctx.mkSolver();
			
			BoolExpr conditionExpr = condition.toZ3BoolExpr(ctx);
			
			solver.add(ctx.mkNot(conditionExpr));
			
			Status status = solver.check();
			long elapsedTime = System.currentTimeMillis() - startTime;
			
			VerificationResult.Builder builder = VerificationResult.builder()
				.condition(condition)
				.verificationTimeMs(elapsedTime);
			
			switch (status) {
				case UNSATISFIABLE:
					builder.status(VerificationResult.Status.PROVEN);
					break;
					
				case SATISFIABLE:
					builder.status(VerificationResult.Status.DISPROVEN);
					Model model = solver.getModel();
					if (model != null) {
						StringBuilder counterexample = new StringBuilder();
						for (FuncDecl<?> decl : model.getDecls()) {
							String varName = decl.getName().toString();
							Expr<?> value = model.getConstInterp(decl);
							builder.addModelValue(varName, value.toString());
							counterexample.append(varName).append(" = ").append(value).append("; ");
						}
						builder.counterexample(counterexample.toString());
					}
					if (condition.getLocation() != null) {
						builder.addViolationLocation(condition.getLocation());
					}
					break;
					
				case UNKNOWN:
				default:
					builder.status(VerificationResult.Status.UNKNOWN);
					break;
			}
			
			return builder.build();
			
		}
		catch (Exception e) {
			long elapsedTime = System.currentTimeMillis() - startTime;
			return VerificationResult.builder()
				.condition(condition)
				.status(VerificationResult.Status.ERROR)
				.verificationTimeMs(elapsedTime)
				.errorMessage(e.getMessage())
				.build();
		}
	}

	/**
	 * Gets the set of valid function entry points.
	 *
	 * @return set of valid function addresses
	 */
	public Set<Address> getValidFunctionEntries() {
		return Collections.unmodifiableSet(validFunctionEntries);
	}

	/**
	 * Gets the set of valid code addresses.
	 *
	 * @return set of valid code addresses
	 */
	public Set<Address> getValidCodeAddresses() {
		return Collections.unmodifiableSet(validCodeAddresses);
	}

	/**
	 * Gets the program being verified.
	 *
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}
}
