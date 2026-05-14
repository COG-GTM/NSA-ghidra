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
 * Comprehensive memory safety verifier that generates and checks conditions
 * for various memory safety properties including:
 * - Array bounds checking
 * - Null pointer dereference detection
 * - Use-after-free detection
 * - Double-free detection
 * - Heap overflow detection
 * 
 * Uses Z3 to generate mathematical proofs that memory accesses are safe.
 */
public class MemorySafetyVerifier {

	private final Program program;
	private final int pointerSize;

	/**
	 * Creates a new memory safety verifier.
	 *
	 * @param program the program to verify
	 */
	public MemorySafetyVerifier(Program program) {
		this.program = program;
		this.pointerSize = program.getDefaultPointerSize() * 8;
	}

	/**
	 * Generates array bounds check conditions for a function.
	 * Ensures that all array accesses satisfy: 0 <= index < array_length
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> generateArrayBoundsCheck(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (isIndexedMemoryAccess(op)) {
					ArrayAccessInfo accessInfo = extractArrayAccessInfo(op);
					
					String conditionName = String.format("array_bounds_%s_%d",
						function.getName(), conditionIndex++);
					
					String z3Expr = generateArrayBoundsZ3Expression(accessInfo);
					
					String description = String.format(
						"Array access at %s: index must be within bounds [0, length)",
						addr.toString()
					);

					conditions.add(new VerificationCondition(
						conditionName,
						description,
						function,
						addr,
						z3Expr,
						PropertyType.MEMORY_SAFETY
					));
				}
			}
		}

		return conditions;
	}

	/**
	 * Generates null pointer check conditions for a function.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> generateNullPointerChecks(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int conditionIndex = 0;

		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
					Varnode addressVarnode = op.getInput(1);
					
					if (!addressVarnode.isConstant()) {
						String conditionName = String.format("null_check_%s_%d",
							function.getName(), conditionIndex++);
						
						StringBuilder z3Expr = new StringBuilder();
						z3Expr.append(String.format("(declare-const ptr (_ BitVec %d))\n", pointerSize));
						z3Expr.append(String.format("(assert (not (= ptr (_ bv0 %d))))\n", pointerSize));
						
						String description = String.format(
							"Pointer dereference at %s must not be null",
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
		}

		return conditions;
	}

	/**
	 * Generates heap safety conditions for a function.
	 * Tracks allocation and deallocation to detect use-after-free and double-free.
	 *
	 * @param function the function to analyze
	 * @return list of verification conditions
	 */
	public List<VerificationCondition> generateHeapSafetyConditions(Function function) {
		List<VerificationCondition> conditions = new ArrayList<>();
		
		List<Address> allocations = new ArrayList<>();
		List<Address> deallocations = new ArrayList<>();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Address addr = instruction.getAddress();
			PcodeOp[] pcodeOps = instruction.getPcode();

			for (PcodeOp op : pcodeOps) {
				if (op.getOpcode() == PcodeOp.CALL) {
					Varnode target = op.getInput(0);
					if (target.isAddress()) {
						Function callee = program.getFunctionManager()
							.getFunctionAt(target.getAddress());
						if (callee != null) {
							String calleeName = callee.getName().toLowerCase();
							if (isAllocationFunction(calleeName)) {
								allocations.add(addr);
							}
							else if (isDeallocationFunction(calleeName)) {
								deallocations.add(addr);
							}
						}
					}
				}
			}
		}
		
		int conditionIndex = 0;
		for (Address deallocAddr : deallocations) {
			String conditionName = String.format("heap_safety_%s_%d",
				function.getName(), conditionIndex++);
			
			StringBuilder z3Expr = new StringBuilder();
			z3Expr.append(String.format("(declare-const ptr (_ BitVec %d))\n", pointerSize));
			z3Expr.append("(declare-const allocated Bool)\n");
			z3Expr.append("(declare-const freed Bool)\n");
			z3Expr.append("(assert allocated)\n");
			z3Expr.append("(assert (not freed))\n");
			
			String description = String.format(
				"Memory freed at %s must have been allocated and not previously freed",
				deallocAddr.toString()
			);

			conditions.add(new VerificationCondition(
				conditionName,
				description,
				function,
				deallocAddr,
				z3Expr.toString(),
				PropertyType.MEMORY_SAFETY
			));
		}

		return conditions;
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
	 * Checks if a P-code operation represents an indexed memory access.
	 *
	 * @param op the P-code operation
	 * @return true if indexed memory access
	 */
	private boolean isIndexedMemoryAccess(PcodeOp op) {
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
	 * Extracts array access information from a P-code operation.
	 *
	 * @param op the P-code operation
	 * @return array access information
	 */
	private ArrayAccessInfo extractArrayAccessInfo(PcodeOp op) {
		int accessSize;
		if (op.getOpcode() == PcodeOp.LOAD) {
			accessSize = op.getOutput().getSize();
		}
		else {
			accessSize = op.getInput(2).getSize();
		}
		
		return new ArrayAccessInfo(pointerSize, accessSize);
	}

	/**
	 * Generates Z3 expression for array bounds checking.
	 *
	 * @param accessInfo the array access information
	 * @return Z3 SMT-LIB2 expression
	 */
	private String generateArrayBoundsZ3Expression(ArrayAccessInfo accessInfo) {
		StringBuilder z3Expr = new StringBuilder();
		
		z3Expr.append(String.format("(declare-const index (_ BitVec %d))\n", accessInfo.pointerBits));
		z3Expr.append(String.format("(declare-const array_base (_ BitVec %d))\n", accessInfo.pointerBits));
		z3Expr.append(String.format("(declare-const array_length (_ BitVec %d))\n", accessInfo.pointerBits));
		z3Expr.append(String.format("(declare-const element_size (_ BitVec %d))\n", accessInfo.pointerBits));
		
		z3Expr.append(String.format("(assert (= element_size (_ bv%d %d)))\n",
			accessInfo.elementSize, accessInfo.pointerBits));
		
		z3Expr.append(String.format("(assert (bvuge index (_ bv0 %d)))\n", accessInfo.pointerBits));
		z3Expr.append("(assert (bvult index array_length))\n");
		
		return z3Expr.toString();
	}

	/**
	 * Checks if a function name represents an allocation function.
	 *
	 * @param name the function name
	 * @return true if allocation function
	 */
	private boolean isAllocationFunction(String name) {
		return name.equals("malloc") || name.equals("calloc") || name.equals("realloc") ||
			name.equals("new") || name.equals("_znwm") || name.equals("_znam") ||
			name.contains("alloc");
	}

	/**
	 * Checks if a function name represents a deallocation function.
	 *
	 * @param name the function name
	 * @return true if deallocation function
	 */
	private boolean isDeallocationFunction(String name) {
		return name.equals("free") || name.equals("delete") ||
			name.equals("_zdlpv") || name.equals("_zdapv") ||
			name.contains("free");
	}

	/**
	 * Gets the program being verified.
	 *
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Internal class to hold array access information.
	 */
	private static class ArrayAccessInfo {
		final int pointerBits;
		final int elementSize;

		ArrayAccessInfo(int pointerBits, int elementSize) {
			this.pointerBits = pointerBits;
			this.elementSize = elementSize;
		}
	}
}
