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
package ghidra.formalverification.engine;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import com.microsoft.z3.*;

import ghidra.formalverification.core.*;
import ghidra.formalverification.property.SecurityProperty;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Scalable verification engine that supports parallel verification of multiple functions.
 * Uses a pool of Z3 contexts and Java's ExecutorService for concurrent verification.
 * 
 * This engine is designed to handle large codebases efficiently by:
 * - Parallelizing verification across multiple CPU cores
 * - Managing Z3 context lifecycle to prevent resource exhaustion
 * - Supporting timeout-based verification to handle complex functions
 * - Providing progress monitoring and cancellation support
 */
public class ScalableVerificationEngine {

	private static final int DEFAULT_THREAD_COUNT = Runtime.getRuntime().availableProcessors();
	private static final long DEFAULT_TIMEOUT_MS = 5000;

	private final Program program;
	private final ExecutorService executorService;
	private final Z3ContextPool contextPool;
	private final long timeoutMs;
	private final int maxThreads;

	/**
	 * Creates a new scalable verification engine with default settings.
	 *
	 * @param program the program to verify
	 */
	public ScalableVerificationEngine(Program program) {
		this(program, DEFAULT_THREAD_COUNT, DEFAULT_TIMEOUT_MS);
	}

	/**
	 * Creates a new scalable verification engine with custom settings.
	 *
	 * @param program the program to verify
	 * @param maxThreads maximum number of parallel verification threads
	 * @param timeoutMs timeout for each verification in milliseconds
	 */
	public ScalableVerificationEngine(Program program, int maxThreads, long timeoutMs) {
		this.program = program;
		this.maxThreads = maxThreads;
		this.timeoutMs = timeoutMs;
		this.executorService = Executors.newFixedThreadPool(maxThreads);
		this.contextPool = new Z3ContextPool(maxThreads);
	}

	/**
	 * Verifies a set of functions asynchronously against a security property.
	 *
	 * @param functions the functions to verify
	 * @param property the security property to check
	 * @return a CompletableFuture containing the batch verification result
	 */
	public CompletableFuture<BatchVerificationResult> verifyAsync(Set<Function> functions,
			SecurityProperty property) {
		return verifyAsync(functions, property, TaskMonitor.DUMMY);
	}

	/**
	 * Verifies a set of functions asynchronously with progress monitoring.
	 *
	 * @param functions the functions to verify
	 * @param property the security property to check
	 * @param monitor task monitor for progress and cancellation
	 * @return a CompletableFuture containing the batch verification result
	 */
	public CompletableFuture<BatchVerificationResult> verifyAsync(Set<Function> functions,
			SecurityProperty property, TaskMonitor monitor) {
		
		return CompletableFuture.supplyAsync(() -> {
			BatchVerificationResult.Builder resultBuilder = BatchVerificationResult.builder()
				.property(property)
				.totalFunctions(functions.size());
			
			long startTime = System.currentTimeMillis();
			
			List<Function> applicableFunctions = functions.stream()
				.filter(f -> property.isApplicable(f))
				.collect(Collectors.toList());
			
			resultBuilder.applicableFunctions(applicableFunctions.size());
			
			monitor.initialize(applicableFunctions.size());
			monitor.setMessage("Verifying functions...");
			
			List<CompletableFuture<List<VerificationResult>>> futures = applicableFunctions.stream()
				.map(function -> CompletableFuture.supplyAsync(
					() -> verifyFunction(function, property, monitor),
					executorService))
				.collect(Collectors.toList());
			
			List<VerificationResult> allResults = new ArrayList<>();
			for (CompletableFuture<List<VerificationResult>> future : futures) {
				try {
					if (monitor.isCancelled()) {
						break;
					}
					List<VerificationResult> results = future.get(timeoutMs * 2, TimeUnit.MILLISECONDS);
					allResults.addAll(results);
					monitor.incrementProgress(1);
				}
				catch (TimeoutException e) {
					Msg.warn(this, "Verification timed out for a function");
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				}
				catch (ExecutionException e) {
					Msg.error(this, "Error during verification", e.getCause());
				}
			}
			
			long totalTime = System.currentTimeMillis() - startTime;
			resultBuilder.totalTimeMs(totalTime);
			
			for (VerificationResult result : allResults) {
				resultBuilder.addResult(result);
			}
			
			return resultBuilder.build();
		});
	}

	/**
	 * Verifies a single function synchronously.
	 *
	 * @param function the function to verify
	 * @param property the security property to check
	 * @param monitor task monitor for cancellation
	 * @return list of verification results
	 */
	private List<VerificationResult> verifyFunction(Function function, SecurityProperty property,
			TaskMonitor monitor) {
		List<VerificationResult> results = new ArrayList<>();
		
		if (monitor.isCancelled()) {
			return results;
		}
		
		List<VerificationCondition> conditions = property.generateConditions(function);
		
		Context ctx = contextPool.acquire();
		try {
			for (VerificationCondition condition : conditions) {
				if (monitor.isCancelled()) {
					break;
				}
				
				VerificationResult result = verifyConditionWithTimeout(ctx, condition);
				results.add(result);
			}
		}
		finally {
			contextPool.release(ctx);
		}
		
		return results;
	}

	/**
	 * Verifies a single condition with timeout support.
	 *
	 * @param ctx the Z3 context to use
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	private VerificationResult verifyConditionWithTimeout(Context ctx, VerificationCondition condition) {
		long startTime = System.currentTimeMillis();
		
		try {
			Solver solver = ctx.mkSolver();
			
			Params params = ctx.mkParams();
			params.add("timeout", (int) timeoutMs);
			solver.setParameters(params);
			
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
					if (elapsedTime >= timeoutMs) {
						builder.status(VerificationResult.Status.TIMEOUT);
					}
					else {
						builder.status(VerificationResult.Status.UNKNOWN);
					}
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
	 * Verifies multiple functions synchronously with parallel processing.
	 *
	 * @param functions the functions to verify
	 * @param property the security property to check
	 * @return batch verification result
	 */
	public BatchVerificationResult verify(Set<Function> functions, SecurityProperty property) {
		try {
			return verifyAsync(functions, property).get();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return BatchVerificationResult.builder()
				.property(property)
				.totalFunctions(functions.size())
				.build();
		}
		catch (ExecutionException e) {
			Msg.error(this, "Verification failed", e.getCause());
			return BatchVerificationResult.builder()
				.property(property)
				.totalFunctions(functions.size())
				.build();
		}
	}

	/**
	 * Shuts down the verification engine and releases resources.
	 */
	public void shutdown() {
		executorService.shutdown();
		try {
			if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
				executorService.shutdownNow();
			}
		}
		catch (InterruptedException e) {
			executorService.shutdownNow();
			Thread.currentThread().interrupt();
		}
		contextPool.shutdown();
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
	 * Gets the maximum number of threads.
	 *
	 * @return the max thread count
	 */
	public int getMaxThreads() {
		return maxThreads;
	}

	/**
	 * Gets the verification timeout in milliseconds.
	 *
	 * @return the timeout
	 */
	public long getTimeoutMs() {
		return timeoutMs;
	}

	/**
	 * Verifies a single condition.
	 *
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	public VerificationResult verifyCondition(VerificationCondition condition) {
		Context ctx = contextPool.acquire();
		try {
			return verifyConditionWithTimeout(ctx, condition);
		}
		finally {
			contextPool.release(ctx);
		}
	}

	/**
	 * Pool of Z3 contexts for thread-safe verification.
	 */
	private static class Z3ContextPool {
		private final BlockingQueue<Context> pool;
		private final List<Context> allContexts;

		Z3ContextPool(int size) {
			this.pool = new LinkedBlockingQueue<>(size);
			this.allContexts = new ArrayList<>(size);
			
			for (int i = 0; i < size; i++) {
				Context ctx = new Context();
				pool.offer(ctx);
				allContexts.add(ctx);
			}
		}

		Context acquire() {
			try {
				Context ctx = pool.poll(30, TimeUnit.SECONDS);
				if (ctx == null) {
					ctx = new Context();
					allContexts.add(ctx);
				}
				return ctx;
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return new Context();
			}
		}

		void release(Context ctx) {
			if (ctx != null) {
				pool.offer(ctx);
			}
		}

		void shutdown() {
			for (Context ctx : allContexts) {
				try {
					ctx.close();
				}
				catch (Exception e) {
					// Ignore cleanup errors
				}
			}
			allContexts.clear();
			pool.clear();
		}
	}
}
