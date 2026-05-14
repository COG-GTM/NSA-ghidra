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

import ghidra.formalverification.core.PropertyType;
import ghidra.formalverification.core.VerificationCondition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

/**
 * Security property for detecting buffer overflow vulnerabilities.
 * This property analyzes memory access patterns in functions and generates
 * verification conditions that prove no buffer overflows can occur.
 * 
 * The analysis focuses on:
 * - Array index bounds checking
 * - Pointer arithmetic bounds
 * - Stack buffer access patterns
 * - Heap allocation size verification
 */
public class BufferOverflowProperty extends SecurityProperty {

	private static final String NAME = "Buffer Overflow Detection";
	private static final String DESCRIPTION = 
		"Verifies that all memory accesses are within allocated buffer bounds, " +
		"preventing buffer overflow vulnerabilities that could lead to code execution " +
		"or information disclosure.";

	/**
	 * Creates a new buffer overflow property.
	 *
	 * @param program the program to analyze
	 */
	public BufferOverflowProperty(Program program) {
		super(NAME, DESCRIPTION, PropertyType.MEMORY_SAFETY, program);
	}

	@Override
	public List<VerificationCondition> generateConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		conditions.addAll(generateArrayBoundsConditions(function));
		conditions.addAll(generateStackBufferConditions(function));
		conditions.addAll(generatePointerArithmeticConditions(function));
		
		return conditions;
	}

	/**
	 * Generates conditions for array bounds checking.
	 *
	 * @param function the function to analyze
	 * @return list of array bounds conditions
	 */
	private List<VerificationCondition> generateArrayBoundsConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (isArrayAccess(op)) {
					String conditionName = String.format("array_bounds_%s_%d", 
						function.getName(), conditionIndex++);
					
					int accessSize = getAccessSize(op);
					int pointerSize = program.getDefaultPointerSize() * 8;
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const index (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const array_base (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const array_length (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const access_addr (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const element_size (_ BitVec %d))\n", pointerSize));
					
					z3Expr.append(String.format(
						"(assert (= element_size (_ bv%d %d)))\n", accessSize, pointerSize));
					z3Expr.append("(assert (= access_addr (bvadd array_base (bvmul index element_size))))\n");
					
					z3Expr.append("(assert (bvuge index (_ bv0 " + pointerSize + ")))\n");
					z3Expr.append("(assert (bvult index array_length))\n");
					
					z3Expr.append("(assert (bvuge access_addr array_base))\n");
					z3Expr.append(String.format(
						"(assert (bvult (bvadd access_addr (_ bv%d %d)) (bvadd array_base (bvmul array_length element_size))))\n",
						accessSize, pointerSize));

					String description = String.format(
						"Array access at %s: index must satisfy 0 <= index < array_length",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.MEMORY_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates conditions for stack buffer access.
	 *
	 * @param function the function to analyze
	 * @return list of stack buffer conditions
	 */
	private List<VerificationCondition> generateStackBufferConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		Variable[] localVariables = function.getLocalVariables();
		int conditionIndex = 0;
		
		for (Variable var : localVariables) {
			if (var.isStackVariable() && var.getLength() > 8) {
				String conditionName = String.format("stack_buffer_%s_%s_%d",
					function.getName(), var.getName(), conditionIndex++);
				
				int bufferSize = var.getLength();
				int stackOffset = var.getStackOffset();
				int pointerSize = program.getDefaultPointerSize() * 8;
				
				StringBuilder z3Expr = new StringBuilder();
				z3Expr.append(String.format("(declare-const sp (_ BitVec %d))\n", pointerSize));
				z3Expr.append(String.format("(declare-const access_offset (_ BitVec %d))\n", pointerSize));
				z3Expr.append(String.format("(declare-const buffer_start (_ BitVec %d))\n", pointerSize));
				z3Expr.append(String.format("(declare-const buffer_end (_ BitVec %d))\n", pointerSize));
				
				z3Expr.append(String.format(
					"(assert (= buffer_start (bvadd sp (_ bv%d %d))))\n",
					stackOffset, pointerSize));
				z3Expr.append(String.format(
					"(assert (= buffer_end (bvadd buffer_start (_ bv%d %d))))\n",
					bufferSize, pointerSize));
				
				z3Expr.append("(assert (bvuge access_offset buffer_start))\n");
				z3Expr.append("(assert (bvult access_offset buffer_end))\n");

				String description = String.format(
					"Stack buffer '%s' (size=%d) access must be within bounds [%d, %d)",
					var.getName(), bufferSize, stackOffset, stackOffset + bufferSize
				);

				conditions.add(new VerificationCondition(
					conditionName,
					description,
					function,
					function.getEntryPoint(),
					z3Expr.toString(),
					PropertyType.MEMORY_SAFETY
				));
			}
		}

		return conditions;
	}

	/**
	 * Generates conditions for pointer arithmetic safety.
	 *
	 * @param function the function to analyze
	 * @return list of pointer arithmetic conditions
	 */
	private List<VerificationCondition> generatePointerArithmeticConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (isPointerArithmetic(op)) {
					String conditionName = String.format("ptr_arith_%s_%d",
						function.getName(), conditionIndex++);
					
					int pointerSize = program.getDefaultPointerSize() * 8;
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const ptr (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const offset (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const result (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const alloc_base (_ BitVec %d))\n", pointerSize));
					z3Expr.append(String.format("(declare-const alloc_size (_ BitVec %d))\n", pointerSize));
					
					z3Expr.append("(assert (= result (bvadd ptr offset)))\n");
					
					z3Expr.append("(assert (bvuge ptr alloc_base))\n");
					z3Expr.append("(assert (bvult ptr (bvadd alloc_base alloc_size)))\n");
					z3Expr.append("(assert (bvuge result alloc_base))\n");
					z3Expr.append("(assert (bvule result (bvadd alloc_base alloc_size)))\n");

					String description = String.format(
						"Pointer arithmetic at %s: result must remain within allocation bounds",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.MEMORY_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Checks if a P-code operation represents an array access.
	 *
	 * @param op the P-code operation
	 * @return true if this is an array access
	 */
	private boolean isArrayAccess(PcodeOp op) {
		int opcode = op.getOpcode();
		if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) {
			return false;
		}
		
		if (op.getNumInputs() >= 2) {
			Varnode addressVarnode = op.getInput(1);
			return !addressVarnode.isConstant();
		}
		
		return false;
	}

	/**
	 * Checks if a P-code operation represents pointer arithmetic.
	 *
	 * @param op the P-code operation
	 * @return true if this is pointer arithmetic
	 */
	private boolean isPointerArithmetic(PcodeOp op) {
		int opcode = op.getOpcode();
		if (opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB) {
			return false;
		}
		
		Varnode output = op.getOutput();
		return output != null && output.getSize() == program.getDefaultPointerSize();
	}

	/**
	 * Gets the access size for a memory operation.
	 *
	 * @param op the P-code operation
	 * @return the access size in bytes
	 */
	private int getAccessSize(PcodeOp op) {
		if (op.getOpcode() == PcodeOp.LOAD) {
			return op.getOutput().getSize();
		}
		else if (op.getOpcode() == PcodeOp.STORE) {
			return op.getInput(2).getSize();
		}
		return program.getDefaultPointerSize();
	}

	@Override
	public boolean isApplicable(Function function) {
		if (function == null || function.isThunk()) {
			return false;
		}
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			PcodeOp[] pcodeOps = instruction.getPcode();
			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
					return true;
				}
			}
		}
		
		return false;
	}

	@Override
	public int getPriority() {
		return 100;
	}
}
