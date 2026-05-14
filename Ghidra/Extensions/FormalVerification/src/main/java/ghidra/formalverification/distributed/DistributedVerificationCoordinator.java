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
package ghidra.formalverification.distributed;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import ghidra.formalverification.core.*;
import ghidra.formalverification.engine.*;
import ghidra.formalverification.property.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Coordinator for distributed verification across multiple worker nodes.
 * Implements work distribution, load balancing, and result aggregation
 * for large-scale verification tasks.
 * 
 * Features:
 * - Dynamic work distribution with load balancing
 * - Fault tolerance with automatic retry
 * - Progress tracking and monitoring
 * - Configurable worker pool management
 */
public class DistributedVerificationCoordinator {

	private static final int DEFAULT_BATCH_SIZE = 10;
	private static final int DEFAULT_MAX_RETRIES = 3;
	private static final long DEFAULT_WORKER_TIMEOUT_MS = 30000;

	private final Program program;
	private final List<VerificationWorker> workers;
	private final ExecutorService coordinatorExecutor;
	private final int batchSize;
	private final int maxRetries;
	private final long workerTimeoutMs;
	
	private final AtomicInteger completedTasks;
	private final AtomicInteger failedTasks;
	private final AtomicLong totalVerificationTimeMs;

	/**
	 * Creates a new distributed verification coordinator.
	 *
	 * @param program the program to verify
	 * @param workerCount number of worker threads
	 */
	public DistributedVerificationCoordinator(Program program, int workerCount) {
		this(program, workerCount, DEFAULT_BATCH_SIZE, DEFAULT_MAX_RETRIES, DEFAULT_WORKER_TIMEOUT_MS);
	}

	/**
	 * Creates a new distributed verification coordinator with custom settings.
	 *
	 * @param program the program to verify
	 * @param workerCount number of worker threads
	 * @param batchSize number of functions per work unit
	 * @param maxRetries maximum retry attempts for failed tasks
	 * @param workerTimeoutMs timeout for worker tasks in milliseconds
	 */
	public DistributedVerificationCoordinator(Program program, int workerCount,
			int batchSize, int maxRetries, long workerTimeoutMs) {
		this.program = program;
		this.batchSize = batchSize;
		this.maxRetries = maxRetries;
		this.workerTimeoutMs = workerTimeoutMs;
		
		this.workers = new ArrayList<>();
		for (int i = 0; i < workerCount; i++) {
			workers.add(new VerificationWorker(program, i, workerTimeoutMs));
		}
		
		this.coordinatorExecutor = Executors.newSingleThreadExecutor();
		this.completedTasks = new AtomicInteger(0);
		this.failedTasks = new AtomicInteger(0);
		this.totalVerificationTimeMs = new AtomicLong(0);
	}

	/**
	 * Performs distributed verification of functions.
	 *
	 * @param functions the functions to verify
	 * @param property the security property to check
	 * @param monitor the task monitor
	 * @return future containing the batch verification result
	 */
	public CompletableFuture<BatchVerificationResult> verifyDistributed(
			Set<Function> functions, SecurityProperty property, TaskMonitor monitor) {
		
		return CompletableFuture.supplyAsync(() -> {
			long startTime = System.currentTimeMillis();
			
			List<Function> functionList = new ArrayList<>(functions);
			List<WorkUnit> workUnits = createWorkUnits(functionList, property);
			
			monitor.initialize(workUnits.size());
			monitor.setMessage("Distributing verification tasks...");
			
			BlockingQueue<WorkUnit> workQueue = new LinkedBlockingQueue<>(workUnits);
			List<CompletableFuture<WorkResult>> futures = new ArrayList<>();
			
			for (VerificationWorker worker : workers) {
				CompletableFuture<WorkResult> future = worker.processWorkQueue(workQueue, monitor);
				futures.add(future);
			}
			
			List<VerificationResult> allResults = new ArrayList<>();
			
			for (CompletableFuture<WorkResult> future : futures) {
				try {
					WorkResult result = future.get(workerTimeoutMs * workUnits.size(), TimeUnit.MILLISECONDS);
					allResults.addAll(result.results);
					completedTasks.addAndGet(result.completedUnits);
					failedTasks.addAndGet(result.failedUnits);
					totalVerificationTimeMs.addAndGet(result.totalTimeMs);
				}
				catch (Exception e) {
					Msg.error(this, "Worker failed: " + e.getMessage(), e);
				}
			}
			
			long totalTime = System.currentTimeMillis() - startTime;
			
			return buildBatchResult(property, functions.size(), allResults, totalTime);
			
		}, coordinatorExecutor);
	}

	/**
	 * Creates work units from the function list.
	 *
	 * @param functions the functions to verify
	 * @param property the property to check
	 * @return list of work units
	 */
	private List<WorkUnit> createWorkUnits(List<Function> functions, SecurityProperty property) {
		List<WorkUnit> units = new ArrayList<>();
		
		for (int i = 0; i < functions.size(); i += batchSize) {
			int end = Math.min(i + batchSize, functions.size());
			List<Function> batch = functions.subList(i, end);
			units.add(new WorkUnit(batch, property, maxRetries));
		}
		
		return units;
	}

	/**
	 * Builds the final batch verification result.
	 *
	 * @param property the property that was verified
	 * @param totalFunctions total number of functions
	 * @param results all verification results
	 * @param totalTimeMs total verification time
	 * @return the batch result
	 */
	private BatchVerificationResult buildBatchResult(SecurityProperty property,
			int totalFunctions, List<VerificationResult> results, long totalTimeMs) {
		
		int applicableFunctions = (int) results.stream()
			.map(r -> r.getCondition().getFunction())
			.distinct()
			.count();
		
		return BatchVerificationResult.builder()
			.property(property)
			.totalFunctions(totalFunctions)
			.applicableFunctions(applicableFunctions)
			.totalTimeMs(totalTimeMs)
			.results(results)
			.build();
	}

	/**
	 * Gets the number of completed tasks.
	 *
	 * @return completed task count
	 */
	public int getCompletedTasks() {
		return completedTasks.get();
	}

	/**
	 * Gets the number of failed tasks.
	 *
	 * @return failed task count
	 */
	public int getFailedTasks() {
		return failedTasks.get();
	}

	/**
	 * Gets the total verification time.
	 *
	 * @return total time in milliseconds
	 */
	public long getTotalVerificationTimeMs() {
		return totalVerificationTimeMs.get();
	}

	/**
	 * Gets the worker statistics.
	 *
	 * @return map of worker ID to statistics
	 */
	public Map<Integer, WorkerStatistics> getWorkerStatistics() {
		Map<Integer, WorkerStatistics> stats = new HashMap<>();
		for (VerificationWorker worker : workers) {
			stats.put(worker.getId(), worker.getStatistics());
		}
		return stats;
	}

	/**
	 * Shuts down the coordinator and all workers.
	 */
	public void shutdown() {
		for (VerificationWorker worker : workers) {
			worker.shutdown();
		}
		
		coordinatorExecutor.shutdown();
		try {
			if (!coordinatorExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
				coordinatorExecutor.shutdownNow();
			}
		}
		catch (InterruptedException e) {
			coordinatorExecutor.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Represents a unit of work for distributed verification.
	 */
	public static class WorkUnit {
		final List<Function> functions;
		final SecurityProperty property;
		int retriesRemaining;

		WorkUnit(List<Function> functions, SecurityProperty property, int maxRetries) {
			this.functions = new ArrayList<>(functions);
			this.property = property;
			this.retriesRemaining = maxRetries;
		}
	}

	/**
	 * Result from processing work units.
	 */
	public static class WorkResult {
		final List<VerificationResult> results;
		final int completedUnits;
		final int failedUnits;
		final long totalTimeMs;

		WorkResult(List<VerificationResult> results, int completedUnits,
				int failedUnits, long totalTimeMs) {
			this.results = results;
			this.completedUnits = completedUnits;
			this.failedUnits = failedUnits;
			this.totalTimeMs = totalTimeMs;
		}
	}

	/**
	 * Worker that processes verification tasks.
	 */
	public static class VerificationWorker {
		private final Program program;
		private final int id;
		private final long timeoutMs;
		private final ExecutorService executor;
		private final ScalableVerificationEngine engine;
		private final WorkerStatistics statistics;

		VerificationWorker(Program program, int id, long timeoutMs) {
			this.program = program;
			this.id = id;
			this.timeoutMs = timeoutMs;
			this.executor = Executors.newSingleThreadExecutor();
			this.engine = new ScalableVerificationEngine(program, 1, (int) timeoutMs);
			this.statistics = new WorkerStatistics();
		}

		int getId() {
			return id;
		}

		WorkerStatistics getStatistics() {
			return statistics;
		}

		CompletableFuture<WorkResult> processWorkQueue(BlockingQueue<WorkUnit> workQueue,
				TaskMonitor monitor) {
			return CompletableFuture.supplyAsync(() -> {
				List<VerificationResult> allResults = new ArrayList<>();
				int completed = 0;
				int failed = 0;
				long totalTime = 0;

				while (!monitor.isCancelled()) {
					WorkUnit unit = workQueue.poll();
					if (unit == null) {
						break;
					}

					long startTime = System.currentTimeMillis();
					
					try {
						for (Function function : unit.functions) {
							if (monitor.isCancelled()) {
								break;
							}
							
							if (!unit.property.isApplicable(function)) {
								continue;
							}
							
							List<VerificationCondition> conditions = 
								unit.property.generateConditions(function);
							
							for (VerificationCondition condition : conditions) {
								VerificationResult result = engine.verifyCondition(condition);
								allResults.add(result);
							}
						}
						
						completed++;
						statistics.recordSuccess();
						
					}
					catch (Exception e) {
						if (unit.retriesRemaining > 0) {
							unit.retriesRemaining--;
							workQueue.offer(unit);
							statistics.recordRetry();
						}
						else {
							failed++;
							statistics.recordFailure();
						}
					}
					
					long elapsed = System.currentTimeMillis() - startTime;
					totalTime += elapsed;
					statistics.recordTime(elapsed);
					
					monitor.incrementProgress(1);
				}

				return new WorkResult(allResults, completed, failed, totalTime);
				
			}, executor);
		}

		void shutdown() {
			engine.shutdown();
			executor.shutdown();
			try {
				if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
					executor.shutdownNow();
				}
			}
			catch (InterruptedException e) {
				executor.shutdownNow();
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * Statistics for a verification worker.
	 */
	public static class WorkerStatistics {
		private int successCount;
		private int failureCount;
		private int retryCount;
		private long totalTimeMs;
		private long minTimeMs = Long.MAX_VALUE;
		private long maxTimeMs = 0;

		public synchronized void recordSuccess() {
			successCount++;
		}

		public synchronized void recordFailure() {
			failureCount++;
		}

		public synchronized void recordRetry() {
			retryCount++;
		}

		public synchronized void recordTime(long timeMs) {
			totalTimeMs += timeMs;
			minTimeMs = Math.min(minTimeMs, timeMs);
			maxTimeMs = Math.max(maxTimeMs, timeMs);
		}

		public synchronized int getSuccessCount() {
			return successCount;
		}

		public synchronized int getFailureCount() {
			return failureCount;
		}

		public synchronized int getRetryCount() {
			return retryCount;
		}

		public synchronized long getTotalTimeMs() {
			return totalTimeMs;
		}

		public synchronized long getAverageTimeMs() {
			int total = successCount + failureCount;
			return total > 0 ? totalTimeMs / total : 0;
		}

		public synchronized String getSummary() {
			return String.format(
				"Worker Statistics: success=%d, failures=%d, retries=%d, " +
				"total_time=%dms, avg_time=%dms",
				successCount, failureCount, retryCount, totalTimeMs, getAverageTimeMs()
			);
		}
	}
}
