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
import ghidra.program.model.listing.Function;

/**
 * Represents the result of a formal verification attempt.
 * Contains information about whether the property was proven, disproven,
 * or if the verification was inconclusive, along with any counterexamples
 * or additional diagnostic information.
 */
public class VerificationResult {

	/**
	 * The possible outcomes of a verification attempt.
	 */
	public enum Status {
		/** The property was mathematically proven to hold */
		PROVEN("Proven", "The security property has been mathematically proven to hold"),
		
		/** The property was disproven with a counterexample */
		DISPROVEN("Disproven", "A counterexample was found that violates the property"),
		
		/** The verification could not determine the result */
		UNKNOWN("Unknown", "The verification could not determine if the property holds"),
		
		/** The verification timed out */
		TIMEOUT("Timeout", "The verification exceeded the time limit"),
		
		/** An error occurred during verification */
		ERROR("Error", "An error occurred during verification");

		private final String displayName;
		private final String description;

		Status(String displayName, String description) {
			this.displayName = displayName;
			this.description = description;
		}

		public String getDisplayName() {
			return displayName;
		}

		public String getDescription() {
			return description;
		}
	}

	private final VerificationCondition condition;
	private final Status status;
	private final long verificationTimeMs;
	private final String counterexample;
	private final String errorMessage;
	private final Map<String, String> modelValues;
	private final List<Address> violationLocations;

	private VerificationResult(Builder builder) {
		this.condition = builder.condition;
		this.status = builder.status;
		this.verificationTimeMs = builder.verificationTimeMs;
		this.counterexample = builder.counterexample;
		this.errorMessage = builder.errorMessage;
		this.modelValues = Collections.unmodifiableMap(new HashMap<>(builder.modelValues));
		this.violationLocations = Collections.unmodifiableList(new ArrayList<>(builder.violationLocations));
	}

	/**
	 * Gets the verification condition that was checked.
	 *
	 * @return the verification condition
	 */
	public VerificationCondition getCondition() {
		return condition;
	}

	/**
	 * Gets the verification status.
	 *
	 * @return the status
	 */
	public Status getStatus() {
		return status;
	}

	/**
	 * Gets the time taken for verification in milliseconds.
	 *
	 * @return the verification time
	 */
	public long getVerificationTimeMs() {
		return verificationTimeMs;
	}

	/**
	 * Gets the counterexample if the property was disproven.
	 *
	 * @return the counterexample, or null if not applicable
	 */
	public String getCounterexample() {
		return counterexample;
	}

	/**
	 * Gets the error message if an error occurred.
	 *
	 * @return the error message, or null if no error
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * Gets the model values from Z3 if a counterexample was found.
	 *
	 * @return map of variable names to their values in the counterexample
	 */
	public Map<String, String> getModelValues() {
		return modelValues;
	}

	/**
	 * Gets the locations where violations were detected.
	 *
	 * @return list of violation addresses
	 */
	public List<Address> getViolationLocations() {
		return violationLocations;
	}

	/**
	 * Checks if the property was proven to hold.
	 *
	 * @return true if proven
	 */
	public boolean isProven() {
		return status == Status.PROVEN;
	}

	/**
	 * Checks if a violation was found.
	 *
	 * @return true if disproven
	 */
	public boolean isViolation() {
		return status == Status.DISPROVEN;
	}

	/**
	 * Gets the function that was verified.
	 *
	 * @return the function
	 */
	public Function getFunction() {
		return condition != null ? condition.getFunction() : null;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("VerificationResult[");
		sb.append("status=").append(status.getDisplayName());
		if (condition != null) {
			sb.append(", condition=").append(condition.getName());
		}
		sb.append(", time=").append(verificationTimeMs).append("ms");
		if (counterexample != null) {
			sb.append(", counterexample=").append(counterexample);
		}
		if (errorMessage != null) {
			sb.append(", error=").append(errorMessage);
		}
		sb.append("]");
		return sb.toString();
	}

	/**
	 * Creates a new builder for VerificationResult.
	 *
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Builder class for VerificationResult.
	 */
	public static class Builder {
		private VerificationCondition condition;
		private Status status = Status.UNKNOWN;
		private long verificationTimeMs;
		private String counterexample;
		private String errorMessage;
		private Map<String, String> modelValues = new HashMap<>();
		private List<Address> violationLocations = new ArrayList<>();

		public Builder condition(VerificationCondition condition) {
			this.condition = condition;
			return this;
		}

		public Builder status(Status status) {
			this.status = status;
			return this;
		}

		public Builder verificationTimeMs(long timeMs) {
			this.verificationTimeMs = timeMs;
			return this;
		}

		public Builder counterexample(String counterexample) {
			this.counterexample = counterexample;
			return this;
		}

		public Builder errorMessage(String errorMessage) {
			this.errorMessage = errorMessage;
			return this;
		}

		public Builder addModelValue(String variable, String value) {
			this.modelValues.put(variable, value);
			return this;
		}

		public Builder addViolationLocation(Address location) {
			this.violationLocations.add(location);
			return this;
		}

		public VerificationResult build() {
			return new VerificationResult(this);
		}
	}
}
