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
package ghidra.formalverification.core;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;

/**
 * Generates verification conditions from P-code operations.
 * This class analyzes the P-code representation of functions to extract
 * conditions that can be verified using the Z3 theorem prover.
 */
public class VerificationConditionGenerator {

	private final Program program;

	/**
	 * Creates a new verification condition generator.
	 *
	 * @param program the program to analyze
	 */
	public VerificationConditionGenerator(Program program) {
		this.program = program;
	}

	/**
	 * Generates verification conditions for a function based on the specified property type.
	 *
	 * @param function the function to analyze
	 * @param propertyType the type of property to verify
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> generateConditions(Function function, PropertyType propertyType) {
		List<VerificationCondition> conditions = new ArrayList<>();

		switch (propertyType) {
			case MEMORY_SAFETY:
				conditions.addAll(generateMemorySafetyConditions(function));
				break;
			case TYPE_SAFETY:
				conditions.addAll(generateTypeSafetyConditions(function));
				break;
			case CONTROL_FLOW_INTEGRITY:
				conditions.addAll(generateControlFlowConditions(function));
				break;
			case ARITHMETIC_SAFETY:
				conditions.addAll(generateArithmeticSafetyConditions(function));
				break;
		}

		return conditions;
	}

	/**
	 * Generates memory safety verification conditions.
	 * Analyzes LOAD and STORE operations to ensure bounds checking.
	 *
	 * @param function the function to analyze
	 * @return list of memory safety conditions
	 */
	private List<VerificationCondition> generateMemorySafetyConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
					Varnode addressVarnode = op.getInput(1);
					String conditionName = String.format("mem_bounds_%d", conditionIndex++);
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append("(declare-const addr (_ BitVec 64))\n");
					z3Expr.append("(declare-const base (_ BitVec 64))\n");
					z3Expr.append("(declare-const size (_ BitVec 64))\n");
					z3Expr.append("(assert (and (bvuge addr base) (bvult addr (bvadd base size))))\n");
					
					String description = String.format(
						"Memory access at %s must be within valid bounds",
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
	 * Generates type safety verification conditions.
	 *
	 * @param function the function to analyze
	 * @return list of type safety conditions
	 */
	private List<VerificationCondition> generateTypeSafetyConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) {
					String conditionName = String.format("type_cast_%d", conditionIndex++);
					
					Varnode input = op.getInput(0);
					Varnode output = op.getOutput();
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const input (_ BitVec %d))\n", input.getSize() * 8));
					z3Expr.append(String.format("(declare-const output (_ BitVec %d))\n", output.getSize() * 8));
					
					if (opcode == PcodeOp.INT_ZEXT) {
						z3Expr.append("(assert (= output ((_ zero_extend ");
						z3Expr.append((output.getSize() - input.getSize()) * 8);
						z3Expr.append(") input)))\n");
					}
					
					String description = String.format(
						"Type conversion at %s preserves value semantics",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.TYPE_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates control flow integrity verification conditions.
	 *
	 * @param function the function to analyze
	 * @return list of control flow conditions
	 */
	private List<VerificationCondition> generateControlFlowConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND) {
					String conditionName = String.format("cfi_indirect_%d", conditionIndex++);
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append("(declare-const target (_ BitVec 64))\n");
					z3Expr.append("(declare-const valid_targets (Array (_ BitVec 64) Bool))\n");
					z3Expr.append("(assert (select valid_targets target))\n");
					
					String description = String.format(
						"Indirect %s at %s targets only valid addresses",
						opcode == PcodeOp.CALLIND ? "call" : "branch",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr.toString(),
						PropertyType.CONTROL_FLOW_INTEGRITY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates arithmetic safety verification conditions.
	 *
	 * @param function the function to analyze
	 * @return list of arithmetic safety conditions
	 */
	private List<VerificationCondition> generateArithmeticSafetyConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				int opcode = op.getOpcode();
				
				if (opcode == PcodeOp.INT_DIV || opcode == PcodeOp.INT_SDIV ||
					opcode == PcodeOp.INT_REM || opcode == PcodeOp.INT_SREM) {
					String conditionName = String.format("div_zero_%d", conditionIndex++);
					
					Varnode divisor = op.getInput(1);
					int bitWidth = divisor.getSize() * 8;
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const divisor (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(assert (not (= divisor (_ bv0 %d))))\n", bitWidth));
					
					String description = String.format(
						"Division at %s has non-zero divisor",
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
				
				if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_MULT) {
					String conditionName = String.format("overflow_%d", conditionIndex++);
					
					Varnode output = op.getOutput();
					int bitWidth = output.getSize() * 8;
					
					StringBuilder z3Expr = new StringBuilder();
					z3Expr.append(String.format("(declare-const a (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(declare-const b (_ BitVec %d))\n", bitWidth));
					z3Expr.append(String.format("(declare-const result (_ BitVec %d))\n", bitWidth));
					
					if (opcode == PcodeOp.INT_ADD) {
						z3Expr.append("(assert (bvugt (bvadd a b) a))\n");
					}
					
					String description = String.format(
						"Arithmetic operation at %s does not overflow",
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
	 * Gets the program being analyzed.
	 *
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}
}
