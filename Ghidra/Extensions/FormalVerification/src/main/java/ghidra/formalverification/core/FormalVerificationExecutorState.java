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

import com.microsoft.z3.*;

import ghidra.formalverification.property.SecurityProperty;
import ghidra.pcode.emu.symz3.SymZ3PcodeArithmetic;
import ghidra.pcode.emu.symz3.state.SymZ3PcodeExecutorState;
import ghidra.pcode.exec.BytesPcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;

/**
 * Extended executor state for formal verification that combines symbolic execution
 * with Z3-based verification condition checking.
 * 
 * This class extends the SymZ3PcodeExecutorState to add formal verification capabilities,
 * allowing security properties to be mathematically proven using the Z3 theorem prover.
 */
public class FormalVerificationExecutorState extends SymZ3PcodeExecutorState {

	private final SecurityProperty securityProperty;
	private final VerificationConditionGenerator conditionGenerator;
	private final Program program;
	private final List<VerificationCondition> pendingConditions;
	private final List<VerificationResult> results;

	/**
	 * Creates a new formal verification executor state.
	 *
	 * @param language the language for the emulator
	 * @param concrete the concrete state piece
	 * @param cb callbacks for state changes
	 * @param program the program being analyzed
	 * @param securityProperty the security property to verify
	 */
	public FormalVerificationExecutorState(Language language, BytesPcodeExecutorStatePiece concrete,
			PcodeStateCallbacks cb, Program program, SecurityProperty securityProperty) {
		super(language, concrete, cb);
		this.program = program;
		this.securityProperty = securityProperty;
		this.conditionGenerator = new VerificationConditionGenerator(program);
		this.pendingConditions = new ArrayList<>();
		this.results = new ArrayList<>();
	}

	/**
	 * Verifies a function against the configured security property.
	 *
	 * @param function the function to verify
	 * @return list of verification results
	 */
	public List<VerificationResult> verifyFunction(Function function) {
		List<VerificationResult> functionResults = new ArrayList<>();
		
		List<VerificationCondition> conditions;
		if (securityProperty != null) {
			conditions = securityProperty.generateConditions(function);
		}
		else {
			conditions = conditionGenerator.generateConditions(function, PropertyType.MEMORY_SAFETY);
		}
		
		pendingConditions.addAll(conditions);
		
		for (VerificationCondition condition : conditions) {
			VerificationResult result = verifyCondition(condition);
			functionResults.add(result);
			results.add(result);
		}
		
		return functionResults;
	}

	/**
	 * Verifies a single verification condition using Z3.
	 *
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	private VerificationResult verifyCondition(VerificationCondition condition) {
		long startTime = System.currentTimeMillis();
		
		try (Context ctx = new Context()) {
			Solver solver = ctx.mkSolver();
			
			solver.push();
			
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
			
			solver.pop();
			
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
	 * Gets all verification results collected so far.
	 *
	 * @return list of verification results
	 */
	public List<VerificationResult> getResults() {
		return Collections.unmodifiableList(results);
	}

	/**
	 * Gets the pending verification conditions.
	 *
	 * @return list of pending conditions
	 */
	public List<VerificationCondition> getPendingConditions() {
		return Collections.unmodifiableList(pendingConditions);
	}

	/**
	 * Gets the security property being verified.
	 *
	 * @return the security property
	 */
	public SecurityProperty getSecurityProperty() {
		return securityProperty;
	}

	/**
	 * Gets the verification condition generator.
	 *
	 * @return the condition generator
	 */
	public VerificationConditionGenerator getConditionGenerator() {
		return conditionGenerator;
	}

	/**
	 * Gets the program being analyzed.
	 *
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Clears all collected results and pending conditions.
	 */
	public void clearResults() {
		results.clear();
		pendingConditions.clear();
	}

	/**
	 * Gets a summary of verification results.
	 *
	 * @return summary string
	 */
	public String getResultsSummary() {
		int proven = 0;
		int disproven = 0;
		int unknown = 0;
		int errors = 0;
		long totalTime = 0;
		
		for (VerificationResult result : results) {
			totalTime += result.getVerificationTimeMs();
			switch (result.getStatus()) {
				case PROVEN:
					proven++;
					break;
				case DISPROVEN:
					disproven++;
					break;
				case UNKNOWN:
				case TIMEOUT:
					unknown++;
					break;
				case ERROR:
					errors++;
					break;
			}
		}
		
		return String.format(
			"Verification Summary: %d proven, %d violations, %d unknown, %d errors (total time: %dms)",
			proven, disproven, unknown, errors, totalTime
		);
	}
}
