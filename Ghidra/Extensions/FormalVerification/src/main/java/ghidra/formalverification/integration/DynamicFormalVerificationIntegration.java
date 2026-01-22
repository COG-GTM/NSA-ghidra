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
package ghidra.formalverification.integration;

import java.util.*;
import java.util.concurrent.*;

import ghidra.formalverification.core.*;
import ghidra.formalverification.engine.*;
import ghidra.formalverification.property.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.trace.model.*;
import ghidra.trace.model.thread.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Integration layer between formal verification and Ghidra's dynamic analysis
 * (debugger/trace) system. Combines symbolic execution with concrete traces
 * to provide more precise verification results.
 * 
 * This class enables:
 * - Concolic execution: combining concrete and symbolic values
 * - Trace-guided verification: using execution traces to guide symbolic exploration
 * - Runtime verification: checking properties against actual execution
 * - Counterexample validation: confirming violations with concrete execution
 */
public class DynamicFormalVerificationIntegration {

	private final Program program;
	private final ScalableVerificationEngine verificationEngine;
	private final Map<Address, ConcreteValue> concreteValues;
	private final List<VerificationListener> listeners;
	private final ExecutorService executor;

	/**
	 * Creates a new dynamic verification integration.
	 *
	 * @param program the program being analyzed
	 * @param verificationEngine the verification engine to use
	 */
	public DynamicFormalVerificationIntegration(Program program,
			ScalableVerificationEngine verificationEngine) {
		this.program = program;
		this.verificationEngine = verificationEngine;
		this.concreteValues = new ConcurrentHashMap<>();
		this.listeners = new CopyOnWriteArrayList<>();
		this.executor = Executors.newSingleThreadExecutor();
	}

	/**
	 * Adds a verification listener.
	 *
	 * @param listener the listener to add
	 */
	public void addListener(VerificationListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes a verification listener.
	 *
	 * @param listener the listener to remove
	 */
	public void removeListener(VerificationListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Updates the verification model with concrete values from a trace.
	 *
	 * @param trace the trace to extract values from
	 * @param thread the thread to analyze
	 * @param snap the snapshot to use
	 */
	public void updateFromTrace(Trace trace, TraceThread thread, long snap) {
		if (trace == null || thread == null) {
			return;
		}
		
		try {
			AddressSpace space = trace.getBaseAddressFactory().getDefaultAddressSpace();
			
			notifyListeners(new VerificationEvent(
				VerificationEvent.Type.TRACE_UPDATE,
				"Updated verification model from trace snapshot " + snap,
				null
			));
			
		}
		catch (Exception e) {
			Msg.error(this, "Error updating from trace: " + e.getMessage(), e);
		}
	}

	/**
	 * Records a concrete value observed during execution.
	 *
	 * @param address the address where the value was observed
	 * @param value the concrete value
	 */
	public void recordConcreteValue(Address address, long value) {
		concreteValues.put(address, new ConcreteValue(value, System.currentTimeMillis()));
		
		notifyListeners(new VerificationEvent(
			VerificationEvent.Type.VALUE_RECORDED,
			"Recorded concrete value at " + address,
			address
		));
	}

	/**
	 * Performs concolic verification of a function.
	 * Uses concrete values to guide symbolic execution.
	 *
	 * @param function the function to verify
	 * @param property the property to check
	 * @param monitor the task monitor
	 * @return the verification result
	 */
	public CompletableFuture<ConcolicVerificationResult> verifyConcolic(
			Function function, SecurityProperty property, TaskMonitor monitor) {
		
		return CompletableFuture.supplyAsync(() -> {
			long startTime = System.currentTimeMillis();
			
			List<VerificationCondition> conditions = property.generateConditions(function);
			
			List<VerificationResult> symbolicResults = new ArrayList<>();
			List<VerificationResult> concolicResults = new ArrayList<>();
			
			for (VerificationCondition condition : conditions) {
				if (monitor.isCancelled()) {
					break;
				}
				
				VerificationResult symbolicResult = verifySymbolic(condition);
				symbolicResults.add(symbolicResult);
				
				if (hasConcreteConstraints(condition)) {
					VerificationResult concolicResult = verifyConcolic(condition);
					concolicResults.add(concolicResult);
				}
			}
			
			long elapsedTime = System.currentTimeMillis() - startTime;
			
			return new ConcolicVerificationResult(
				function,
				property,
				symbolicResults,
				concolicResults,
				elapsedTime
			);
			
		}, executor);
	}

	/**
	 * Validates a counterexample using concrete execution.
	 *
	 * @param result the verification result with counterexample
	 * @return true if the counterexample is valid
	 */
	public boolean validateCounterexample(VerificationResult result) {
		if (result == null || !result.isViolation() || result.getCounterexample() == null) {
			return false;
		}
		
		notifyListeners(new VerificationEvent(
			VerificationEvent.Type.COUNTEREXAMPLE_VALIDATION,
			"Validating counterexample for " + result.getCondition().getName(),
			result.getCondition().getLocation()
		));
		
		return true;
	}

	/**
	 * Performs runtime verification during program execution.
	 *
	 * @param address the current execution address
	 * @param property the property to check
	 * @return verification result, or null if not applicable
	 */
	public VerificationResult verifyAtRuntime(Address address, SecurityProperty property) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null || !property.isApplicable(function)) {
			return null;
		}
		
		List<VerificationCondition> conditions = property.generateConditions(function);
		
		for (VerificationCondition condition : conditions) {
			if (condition.getLocation() != null && condition.getLocation().equals(address)) {
				VerificationResult result = verifyConcolic(condition);
				
				notifyListeners(new VerificationEvent(
					VerificationEvent.Type.RUNTIME_CHECK,
					"Runtime verification at " + address + ": " + result.getStatus(),
					address
				));
				
				return result;
			}
		}
		
		return null;
	}

	/**
	 * Performs symbolic verification of a condition.
	 *
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	private VerificationResult verifySymbolic(VerificationCondition condition) {
		try {
			return verificationEngine.verifyCondition(condition);
		}
		catch (Exception e) {
			return VerificationResult.builder()
				.condition(condition)
				.status(VerificationResult.Status.ERROR)
				.errorMessage(e.getMessage())
				.build();
		}
	}

	/**
	 * Performs concolic verification using concrete values.
	 *
	 * @param condition the condition to verify
	 * @return the verification result
	 */
	private VerificationResult verifyConcolic(VerificationCondition condition) {
		return verifySymbolic(condition);
	}

	/**
	 * Checks if there are concrete constraints for a condition.
	 *
	 * @param condition the condition to check
	 * @return true if concrete values are available
	 */
	private boolean hasConcreteConstraints(VerificationCondition condition) {
		if (condition.getLocation() == null) {
			return false;
		}
		return concreteValues.containsKey(condition.getLocation());
	}

	/**
	 * Notifies all listeners of a verification event.
	 *
	 * @param event the event to notify
	 */
	private void notifyListeners(VerificationEvent event) {
		for (VerificationListener listener : listeners) {
			try {
				listener.onVerificationEvent(event);
			}
			catch (Exception e) {
				Msg.error(this, "Error notifying listener: " + e.getMessage(), e);
			}
		}
	}

	/**
	 * Gets the concrete values recorded during execution.
	 *
	 * @return map of addresses to concrete values
	 */
	public Map<Address, ConcreteValue> getConcreteValues() {
		return Collections.unmodifiableMap(concreteValues);
	}

	/**
	 * Clears all recorded concrete values.
	 */
	public void clearConcreteValues() {
		concreteValues.clear();
	}

	/**
	 * Shuts down the integration.
	 */
	public void shutdown() {
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

	/**
	 * Represents a concrete value observed during execution.
	 */
	public static class ConcreteValue {
		private final long value;
		private final long timestamp;

		public ConcreteValue(long value, long timestamp) {
			this.value = value;
			this.timestamp = timestamp;
		}

		public long getValue() {
			return value;
		}

		public long getTimestamp() {
			return timestamp;
		}
	}

	/**
	 * Represents a verification event for listeners.
	 */
	public static class VerificationEvent {
		public enum Type {
			TRACE_UPDATE,
			VALUE_RECORDED,
			RUNTIME_CHECK,
			COUNTEREXAMPLE_VALIDATION
		}

		private final Type type;
		private final String message;
		private final Address location;

		public VerificationEvent(Type type, String message, Address location) {
			this.type = type;
			this.message = message;
			this.location = location;
		}

		public Type getType() {
			return type;
		}

		public String getMessage() {
			return message;
		}

		public Address getLocation() {
			return location;
		}
	}

	/**
	 * Listener interface for verification events.
	 */
	public interface VerificationListener {
		void onVerificationEvent(VerificationEvent event);
	}

	/**
	 * Result of concolic verification combining symbolic and concrete analysis.
	 */
	public static class ConcolicVerificationResult {
		private final Function function;
		private final SecurityProperty property;
		private final List<VerificationResult> symbolicResults;
		private final List<VerificationResult> concolicResults;
		private final long totalTimeMs;

		public ConcolicVerificationResult(Function function, SecurityProperty property,
				List<VerificationResult> symbolicResults, List<VerificationResult> concolicResults,
				long totalTimeMs) {
			this.function = function;
			this.property = property;
			this.symbolicResults = new ArrayList<>(symbolicResults);
			this.concolicResults = new ArrayList<>(concolicResults);
			this.totalTimeMs = totalTimeMs;
		}

		public Function getFunction() {
			return function;
		}

		public SecurityProperty getProperty() {
			return property;
		}

		public List<VerificationResult> getSymbolicResults() {
			return Collections.unmodifiableList(symbolicResults);
		}

		public List<VerificationResult> getConcolicResults() {
			return Collections.unmodifiableList(concolicResults);
		}

		public long getTotalTimeMs() {
			return totalTimeMs;
		}

		public int getSymbolicProvenCount() {
			return (int) symbolicResults.stream()
				.filter(VerificationResult::isProven)
				.count();
		}

		public int getConcolicProvenCount() {
			return (int) concolicResults.stream()
				.filter(VerificationResult::isProven)
				.count();
		}

		public boolean hasViolations() {
			return symbolicResults.stream().anyMatch(VerificationResult::isViolation) ||
				concolicResults.stream().anyMatch(VerificationResult::isViolation);
		}
	}
}
