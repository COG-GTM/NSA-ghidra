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

import ghidra.formalverification.core.VerificationResult;
import ghidra.formalverification.property.SecurityProperty;
import ghidra.program.model.listing.Function;

/**
 * Represents the aggregated results of verifying multiple functions.
 * Provides summary statistics and access to individual verification results.
 */
public class BatchVerificationResult {

	private final SecurityProperty property;
	private final int totalFunctions;
	private final int applicableFunctions;
	private final long totalTimeMs;
	private final List<VerificationResult> results;
	private final Map<Function, List<VerificationResult>> resultsByFunction;

	private BatchVerificationResult(Builder builder) {
		this.property = builder.property;
		this.totalFunctions = builder.totalFunctions;
		this.applicableFunctions = builder.applicableFunctions;
		this.totalTimeMs = builder.totalTimeMs;
		this.results = Collections.unmodifiableList(new ArrayList<>(builder.results));
		this.resultsByFunction = Collections.unmodifiableMap(new HashMap<>(builder.resultsByFunction));
	}

	/**
	 * Gets the security property that was verified.
	 *
	 * @return the security property
	 */
	public SecurityProperty getProperty() {
		return property;
	}

	/**
	 * Gets the total number of functions that were considered.
	 *
	 * @return total function count
	 */
	public int getTotalFunctions() {
		return totalFunctions;
	}

	/**
	 * Gets the number of functions that the property was applicable to.
	 *
	 * @return applicable function count
	 */
	public int getApplicableFunctions() {
		return applicableFunctions;
	}

	/**
	 * Gets the total verification time in milliseconds.
	 *
	 * @return total time
	 */
	public long getTotalTimeMs() {
		return totalTimeMs;
	}

	/**
	 * Gets all verification results.
	 *
	 * @return list of all results
	 */
	public List<VerificationResult> getResults() {
		return results;
	}

	/**
	 * Gets results grouped by function.
	 *
	 * @return map of function to its results
	 */
	public Map<Function, List<VerificationResult>> getResultsByFunction() {
		return resultsByFunction;
	}

	/**
	 * Gets the count of proven conditions.
	 *
	 * @return proven count
	 */
	public int getProvenCount() {
		return (int) results.stream()
			.filter(r -> r.getStatus() == VerificationResult.Status.PROVEN)
			.count();
	}

	/**
	 * Gets the count of disproven conditions (violations found).
	 *
	 * @return violation count
	 */
	public int getViolationCount() {
		return (int) results.stream()
			.filter(r -> r.getStatus() == VerificationResult.Status.DISPROVEN)
			.count();
	}

	/**
	 * Gets the count of unknown results.
	 *
	 * @return unknown count
	 */
	public int getUnknownCount() {
		return (int) results.stream()
			.filter(r -> r.getStatus() == VerificationResult.Status.UNKNOWN ||
				r.getStatus() == VerificationResult.Status.TIMEOUT)
			.count();
	}

	/**
	 * Gets the count of errors.
	 *
	 * @return error count
	 */
	public int getErrorCount() {
		return (int) results.stream()
			.filter(r -> r.getStatus() == VerificationResult.Status.ERROR)
			.count();
	}

	/**
	 * Gets all results that found violations.
	 *
	 * @return list of violation results
	 */
	public List<VerificationResult> getViolations() {
		List<VerificationResult> violations = new ArrayList<>();
		for (VerificationResult result : results) {
			if (result.getStatus() == VerificationResult.Status.DISPROVEN) {
				violations.add(result);
			}
		}
		return violations;
	}

	/**
	 * Gets functions that have at least one violation.
	 *
	 * @return set of functions with violations
	 */
	public Set<Function> getFunctionsWithViolations() {
		Set<Function> functions = new HashSet<>();
		for (VerificationResult result : results) {
			if (result.getStatus() == VerificationResult.Status.DISPROVEN) {
				Function func = result.getFunction();
				if (func != null) {
					functions.add(func);
				}
			}
		}
		return functions;
	}

	/**
	 * Checks if all conditions were proven.
	 *
	 * @return true if all proven
	 */
	public boolean isFullyVerified() {
		return !results.isEmpty() && getProvenCount() == results.size();
	}

	/**
	 * Checks if any violations were found.
	 *
	 * @return true if violations exist
	 */
	public boolean hasViolations() {
		return getViolationCount() > 0;
	}

	/**
	 * Gets a summary string of the results.
	 *
	 * @return summary string
	 */
	public String getSummary() {
		return String.format(
			"Batch Verification: %d/%d functions analyzed, %d conditions checked\n" +
			"  Proven: %d, Violations: %d, Unknown: %d, Errors: %d\n" +
			"  Total time: %dms (%.2f conditions/sec)",
			applicableFunctions, totalFunctions, results.size(),
			getProvenCount(), getViolationCount(), getUnknownCount(), getErrorCount(),
			totalTimeMs, results.size() * 1000.0 / Math.max(1, totalTimeMs)
		);
	}

	@Override
	public String toString() {
		return getSummary();
	}

	/**
	 * Creates a new builder.
	 *
	 * @return new builder instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Builder for BatchVerificationResult.
	 */
	public static class Builder {
		private SecurityProperty property;
		private int totalFunctions;
		private int applicableFunctions;
		private long totalTimeMs;
		private List<VerificationResult> results = new ArrayList<>();
		private Map<Function, List<VerificationResult>> resultsByFunction = new HashMap<>();

		public Builder property(SecurityProperty property) {
			this.property = property;
			return this;
		}

		public Builder totalFunctions(int count) {
			this.totalFunctions = count;
			return this;
		}

		public Builder applicableFunctions(int count) {
			this.applicableFunctions = count;
			return this;
		}

		public Builder totalTimeMs(long timeMs) {
			this.totalTimeMs = timeMs;
			return this;
		}

		public Builder addResult(VerificationResult result) {
			this.results.add(result);
			Function func = result.getFunction();
			if (func != null) {
				resultsByFunction.computeIfAbsent(func, k -> new ArrayList<>()).add(result);
			}
			return this;
		}

		public Builder addResults(List<VerificationResult> results) {
			for (VerificationResult result : results) {
				addResult(result);
			}
			return this;
		}

		public Builder results(List<VerificationResult> results) {
			return addResults(results);
		}

		public BatchVerificationResult build() {
			return new BatchVerificationResult(this);
		}
	}
}
