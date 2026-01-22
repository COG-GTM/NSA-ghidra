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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Manages incremental verification by tracking function dependencies and caching results.
 * When a function changes, only the affected functions need to be re-verified.
 * 
 * This manager maintains:
 * - A cache of verification results keyed by function address
 * - A dependency graph tracking which functions call which
 * - Logic to determine which functions need re-verification after changes
 */
public class IncrementalVerificationManager {

	private final Program program;
	private final Map<Address, CachedVerificationResult> resultCache;
	private final Map<Address, Set<Address>> callGraph;
	private final Map<Address, Set<Address>> reverseCallGraph;
	private final Map<Address, Long> functionVersions;

	/**
	 * Creates a new incremental verification manager.
	 *
	 * @param program the program to manage
	 */
	public IncrementalVerificationManager(Program program) {
		this.program = program;
		this.resultCache = new HashMap<>();
		this.callGraph = new HashMap<>();
		this.reverseCallGraph = new HashMap<>();
		this.functionVersions = new HashMap<>();
		
		buildCallGraph();
	}

	/**
	 * Builds the call graph for the program.
	 */
	private void buildCallGraph() {
		FunctionManager funcManager = program.getFunctionManager();
		FunctionIterator functions = funcManager.getFunctions(true);
		
		while (functions.hasNext()) {
			Function function = functions.next();
			Address funcAddr = function.getEntryPoint();
			
			callGraph.putIfAbsent(funcAddr, new HashSet<>());
			reverseCallGraph.putIfAbsent(funcAddr, new HashSet<>());
			
			Set<Function> calledFunctions = function.getCalledFunctions(null);
			for (Function callee : calledFunctions) {
				Address calleeAddr = callee.getEntryPoint();
				callGraph.get(funcAddr).add(calleeAddr);
				reverseCallGraph.computeIfAbsent(calleeAddr, k -> new HashSet<>()).add(funcAddr);
			}
			
			functionVersions.put(funcAddr, computeFunctionHash(function));
		}
	}

	/**
	 * Computes a hash representing the current state of a function.
	 *
	 * @param function the function to hash
	 * @return hash value
	 */
	private long computeFunctionHash(Function function) {
		long hash = 17;
		
		hash = 31 * hash + function.getBody().getNumAddresses();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		int instructionCount = 0;
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			hash = 31 * hash + instr.getMnemonicString().hashCode();
			instructionCount++;
			if (instructionCount > 100) {
				break;
			}
		}
		
		hash = 31 * hash + function.getParameterCount();
		
		return hash;
	}

	/**
	 * Performs incremental verification for a changed function.
	 * Only re-verifies the changed function and its dependents.
	 *
	 * @param changedFunction the function that changed
	 * @param property the security property to verify
	 * @param engine the verification engine to use
	 * @return list of verification results for affected functions
	 */
	public List<VerificationResult> verifyIncremental(Function changedFunction,
			SecurityProperty property, ScalableVerificationEngine engine) {
		
		Set<Function> affectedFunctions = getAffectedFunctions(changedFunction);
		
		invalidateCache(affectedFunctions);
		
		Set<Function> functionsToVerify = new HashSet<>();
		for (Function func : affectedFunctions) {
			if (!hasCachedResult(func, property)) {
				functionsToVerify.add(func);
			}
		}
		
		if (functionsToVerify.isEmpty()) {
			return getCachedResults(affectedFunctions, property);
		}
		
		BatchVerificationResult batchResult = engine.verify(functionsToVerify, property);
		
		for (VerificationResult result : batchResult.getResults()) {
			cacheResult(result, property);
		}
		
		updateFunctionVersion(changedFunction);
		
		return getCachedResults(affectedFunctions, property);
	}

	/**
	 * Gets all functions affected by a change to the given function.
	 * This includes the function itself and all functions that call it (transitively).
	 *
	 * @param changedFunction the changed function
	 * @return set of affected functions
	 */
	public Set<Function> getAffectedFunctions(Function changedFunction) {
		Set<Function> affected = new HashSet<>();
		Set<Address> visited = new HashSet<>();
		Queue<Address> queue = new LinkedList<>();
		
		Address startAddr = changedFunction.getEntryPoint();
		queue.add(startAddr);
		visited.add(startAddr);
		
		FunctionManager funcManager = program.getFunctionManager();
		
		while (!queue.isEmpty()) {
			Address addr = queue.poll();
			Function func = funcManager.getFunctionAt(addr);
			if (func != null) {
				affected.add(func);
			}
			
			Set<Address> callers = reverseCallGraph.get(addr);
			if (callers != null) {
				for (Address caller : callers) {
					if (!visited.contains(caller)) {
						visited.add(caller);
						queue.add(caller);
					}
				}
			}
		}
		
		return affected;
	}

	/**
	 * Checks if a cached result exists for a function and property.
	 *
	 * @param function the function
	 * @param property the property
	 * @return true if cached
	 */
	public boolean hasCachedResult(Function function, SecurityProperty property) {
		Address addr = function.getEntryPoint();
		CachedVerificationResult cached = resultCache.get(addr);
		
		if (cached == null) {
			return false;
		}
		
		if (!cached.propertyName.equals(property.getName())) {
			return false;
		}
		
		Long currentVersion = functionVersions.get(addr);
		if (currentVersion == null || !currentVersion.equals(cached.functionVersion)) {
			return false;
		}
		
		return true;
	}

	/**
	 * Gets the cached result for a function.
	 *
	 * @param function the function
	 * @param property the property
	 * @return the cached result, or null if not cached
	 */
	public VerificationResult getCachedResult(Function function, SecurityProperty property) {
		if (!hasCachedResult(function, property)) {
			return null;
		}
		return resultCache.get(function.getEntryPoint()).result;
	}

	/**
	 * Gets cached results for multiple functions.
	 *
	 * @param functions the functions
	 * @param property the property
	 * @return list of cached results
	 */
	private List<VerificationResult> getCachedResults(Set<Function> functions,
			SecurityProperty property) {
		List<VerificationResult> results = new ArrayList<>();
		for (Function func : functions) {
			VerificationResult result = getCachedResult(func, property);
			if (result != null) {
				results.add(result);
			}
		}
		return results;
	}

	/**
	 * Caches a verification result.
	 *
	 * @param result the result to cache
	 * @param property the property that was verified
	 */
	public void cacheResult(VerificationResult result, SecurityProperty property) {
		Function func = result.getFunction();
		if (func == null) {
			return;
		}
		
		Address addr = func.getEntryPoint();
		Long version = functionVersions.get(addr);
		if (version == null) {
			version = computeFunctionHash(func);
			functionVersions.put(addr, version);
		}
		
		resultCache.put(addr, new CachedVerificationResult(result, property.getName(), version));
	}

	/**
	 * Invalidates cached results for the given functions.
	 *
	 * @param functions the functions to invalidate
	 */
	public void invalidateCache(Set<Function> functions) {
		for (Function func : functions) {
			resultCache.remove(func.getEntryPoint());
		}
	}

	/**
	 * Invalidates all cached results.
	 */
	public void invalidateAllCache() {
		resultCache.clear();
	}

	/**
	 * Invalidates all cached results (alias for invalidateAllCache).
	 */
	public void invalidateAll() {
		invalidateAllCache();
	}

	/**
	 * Updates the version hash for a function.
	 *
	 * @param function the function to update
	 */
	private void updateFunctionVersion(Function function) {
		functionVersions.put(function.getEntryPoint(), computeFunctionHash(function));
	}

	/**
	 * Gets the functions that the given function calls.
	 *
	 * @param function the function
	 * @return set of called function addresses
	 */
	public Set<Address> getCallees(Function function) {
		Set<Address> callees = callGraph.get(function.getEntryPoint());
		return callees != null ? Collections.unmodifiableSet(callees) : Collections.emptySet();
	}

	/**
	 * Gets the functions that call the given function.
	 *
	 * @param function the function
	 * @return set of caller function addresses
	 */
	public Set<Address> getCallers(Function function) {
		Set<Address> callers = reverseCallGraph.get(function.getEntryPoint());
		return callers != null ? Collections.unmodifiableSet(callers) : Collections.emptySet();
	}

	/**
	 * Gets the number of cached results.
	 *
	 * @return cache size
	 */
	public int getCacheSize() {
		return resultCache.size();
	}

	/**
	 * Gets cache statistics.
	 *
	 * @return statistics string
	 */
	public String getCacheStatistics() {
		int proven = 0;
		int violations = 0;
		int other = 0;
		
		for (CachedVerificationResult cached : resultCache.values()) {
			switch (cached.result.getStatus()) {
				case PROVEN:
					proven++;
					break;
				case DISPROVEN:
					violations++;
					break;
				default:
					other++;
					break;
			}
		}
		
		return String.format(
			"Cache: %d entries (proven=%d, violations=%d, other=%d)",
			resultCache.size(), proven, violations, other
		);
	}

	/**
	 * Internal class to store cached verification results with metadata.
	 */
	private static class CachedVerificationResult {
		final VerificationResult result;
		final String propertyName;
		final long functionVersion;

		CachedVerificationResult(VerificationResult result, String propertyName, long functionVersion) {
			this.result = result;
			this.propertyName = propertyName;
			this.functionVersion = functionVersion;
		}
	}
}
