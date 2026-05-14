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

/**
 * Security property for verifying arithmetic safety.
 * Ensures that arithmetic operations do not cause undefined behavior
 * such as integer overflow, division by zero, or signed overflow.
 */
public class ArithmeticSafetyProperty extends SecurityProperty {

	private static final String NAME = "Arithmetic Safety";
	private static final String DESCRIPTION = 
		"Verifies that arithmetic operations do not cause undefined behavior " +
		"such as integer overflow or division by zero.";

	/**
	 * Creates a new arithmetic safety property.
	 *
	 * @param program the program to analyze
	 */
	public ArithmeticSafetyProperty(Program program) {
		super(NAME, DESCRIPTION, PropertyType.ARITHMETIC_SAFETY, program);
	}

	@Override
	public List<VerificationCondition> generateConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		conditions.addAll(generateDivisionByZeroConditions(function));
		conditions.addAll(generateOverflowConditions(function));
		conditions.addAll(generateShiftConditions(function));
		
		return conditions;
	}

	/**
	 * Generates conditions for division by zero detection.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	private List<VerificationCondition> generateDivisionByZeroConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.INT_SDIV ||
					opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM) {
					
					Varnode divisor = op.getInput(1);
					int bitWidth = divisor.getSize() * 8;
					
					String conditionName = String.format("div_zero_%s_%d",
						function.getName(), conditionIndex++);
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const divisor (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(assert (not (= divisor (_ bv0 %d))))\n", bitWidth));
					
					String description = String.format(
						"Division at %s: divisor must not be zero",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.ARITHMETIC_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates conditions for integer overflow detection.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	private List<VerificationCondition> generateOverflowConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB ||
					opcode == PcodeOp.INT_MULT) {
					
					Varnode output = op.getOutput();
					if (output == null) {
						continue;
					}
					int bitWidth = output.getSize() * 8;
					
					String conditionName = String.format("overflow_%s_%d",
						function.getName(), conditionIndex++);
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const a (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(declare-const b (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(declare-const result (_ BitVec %d))\n", bitWidth));
					
					if (opcode == PcodeOp.INT_ADD) {
						z3Expr.append(String.format(
							"(declare-const extended_a (_ BitVec %d))\n", bitWidth + 1));
						z3Expr.append(String.format(
							"(declare-const extended_b (_ BitVec %d))\n", bitWidth + 1));
						z3Expr.append(String.format(
							"(declare-const extended_result (_ BitVec %d))\n", bitWidth + 1));
						z3Expr.append(String.format(
							"(assert (= extended_a ((_ zero_extend 1) a)))\n"));
						z3Expr.append(String.format(
							"(assert (= extended_b ((_ zero_extend 1) b)))\n"));
						z3Expr.append(String.format(
							"(assert (= extended_result (bvadd extended_a extended_b)))\n"));
						z3Expr.append(String.format(
							"(assert (= ((_ extract %d %d) extended_result) (_ bv0 1)))\n",
							bitWidth, bitWidth));
					}
					else if (opcode == PcodeOp.INT_SUB) {
						z3Expr.append("(assert (bvuge a b))\n");
					}
					else if (opcode == PcodeOp.INT_MULT) {
						z3Expr.append(String.format(
							"(declare-const extended_a (_ BitVec %d))\n", bitWidth * 2));
						z3Expr.append(String.format(
							"(declare-const extended_b (_ BitVec %d))\n", bitWidth * 2));
						z3Expr.append(String.format(
							"(declare-const extended_result (_ BitVec %d))\n", bitWidth * 2));
						z3Expr.append(String.format(
							"(assert (= extended_a ((_ zero_extend %d) a)))\n", bitWidth));
						z3Expr.append(String.format(
							"(assert (= extended_b ((_ zero_extend %d) b)))\n", bitWidth));
						z3Expr.append(String.format(
							"(assert (= extended_result (bvmul extended_a extended_b)))\n"));
						z3Expr.append(String.format(
							"(assert (= ((_ extract %d %d) extended_result) (_ bv0 %d)))\n",
							bitWidth * 2 - 1, bitWidth, bitWidth));
					}
					
					String opName = opcode == PcodeOp.INT_ADD ? "addition" :
						opcode == PcodeOp.INT_SUB ? "subtraction" : "multiplication";
					
					String description = String.format(
						"Integer %s at %s must not overflow",
						opName, addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.ARITHMETIC_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates conditions for shift operation safety.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	private List<VerificationCondition> generateShiftConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT ||
					opcode == PcodeOp.INT_SRIGHT) {
					
					Varnode value = op.getInput(0);
					Varnode amount = op.getInput(1);
					int valueBits = value.getSize() * 8;
					int amountBits = amount.getSize() * 8;
					
					String conditionName = String.format("shift_%s_%d",
						function.getName(), conditionIndex++);
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const shift_amount (_ BitVec %d))\n", amountBits));
					z3Expr.append(String.format("(assert (bvult shift_amount (_ bv%d %d)))\n",
						valueBits, amountBits));
					
					String description = String.format(
						"Shift at %s: shift amount must be less than bit width (%d)",
						addr.toString(), valueBits
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.ARITHMETIC_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	@Override
	public boolean isApplicable(Function function) {
		if (function == null || function.isThunk()) {
			return false;
		}
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			PcodeOp[] pcodeOps = instruction.getPcode();
			
			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				if (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.INT_SDIV ||
					opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM ||
					opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB ||
					opcode == PcodeOp.INT_MULT || opcode == PcodeOp.INT_LEFT ||
					opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT) {
					return true;
				}
			}
		}
		
		return false;
	}

	@Override
	public int getPriority() {
		return 80;
	}
}
