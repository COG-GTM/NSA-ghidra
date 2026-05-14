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
package ghidra.formalverification.cache;

import java.util.*;
import java.util.concurrent.*;

import ghidra.formalverification.core.*;
import ghidra.formalverification.engine.BatchVerificationResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

/**
 * High-performance cache for verification results with dependency tracking.
 * Implements intelligent invalidation based on function modifications and
 * call graph dependencies.
 * 
 * Features:
 * - LRU eviction policy with configurable size limits
 * - Dependency tracking for automatic invalidation
 * - Thread-safe concurrent access
 * - Statistics tracking for cache performance monitoring
 */
public class VerificationCache {

	private static final int DEFAULT_MAX_ENTRIES = 10000;
	private static final long DEFAULT_EXPIRATION_MS = 3600000;

	private final Program program;
	private final int maxEntries;
	private final long expirationMs;
	
	private final Map<CacheKey, CachedResult> cache;
	private final DependencyTracker dependencyTracker;
	private final CacheStatistics statistics;

	/**
	 * Creates a new verification cache with default settings.
	 *
	 * @param program the program being verified
	 */
	public VerificationCache(Program program) {
		this(program, DEFAULT_MAX_ENTRIES, DEFAULT_EXPIRATION_MS);
	}

	/**
	 * Creates a new verification cache with custom settings.
	 *
	 * @param program the program being verified
	 * @param maxEntries maximum number of cached entries
	 * @param expirationMs cache entry expiration time in milliseconds
	 */
	public VerificationCache(Program program, int maxEntries, long expirationMs) {
		this.program = program;
		this.maxEntries = maxEntries;
		this.expirationMs = expirationMs;
		
		this.cache = new ConcurrentHashMap<>();
		this.dependencyTracker = new DependencyTracker(program);
		this.statistics = new CacheStatistics();
	}

	/**
	 * Gets a cached verification result if available and valid.
	 *
	 * @param function the function
	 * @param propertyType the property type
	 * @return the cached result, or null if not cached or invalid
	 */
	public BatchVerificationResult getCachedResult(Function function, PropertyType propertyType) {
		CacheKey key = new CacheKey(function.getEntryPoint(), propertyType);
		CachedResult cached = cache.get(key);
		
		if (cached == null) {
			statistics.recordMiss();
			return null;
		}
		
		if (isExpired(cached)) {
			cache.remove(key);
			statistics.recordExpiration();
			return null;
		}
		
		long currentVersion = computeFunctionVersion(function);
		if (cached.functionVersion != currentVersion) {
			cache.remove(key);
			statistics.recordInvalidation();
			return null;
		}
		
		statistics.recordHit();
		cached.lastAccessTime = System.currentTimeMillis();
		return cached.result;
	}

	/**
	 * Caches a verification result.
	 *
	 * @param function the function
	 * @param propertyType the property type
	 * @param result the verification result
	 */
	public void cacheResult(Function function, PropertyType propertyType,
			BatchVerificationResult result) {
		if (cache.size() >= maxEntries) {
			evictOldestEntries();
		}
		
		CacheKey key = new CacheKey(function.getEntryPoint(), propertyType);
		long version = computeFunctionVersion(function);
		
		CachedResult cached = new CachedResult(result, version);
		cache.put(key, cached);
		
		dependencyTracker.trackDependencies(function);
		
		statistics.recordStore();
	}

	/**
	 * Invalidates cache entries for a function and its dependents.
	 *
	 * @param function the modified function
	 */
	public void invalidate(Function function) {
		Set<Address> affected = dependencyTracker.getAffectedFunctions(function.getEntryPoint());
		
		for (PropertyType propertyType : PropertyType.values()) {
			CacheKey key = new CacheKey(function.getEntryPoint(), propertyType);
			if (cache.remove(key) != null) {
				statistics.recordInvalidation();
			}
		}
		
		for (Address addr : affected) {
			for (PropertyType propertyType : PropertyType.values()) {
				CacheKey key = new CacheKey(addr, propertyType);
				if (cache.remove(key) != null) {
					statistics.recordInvalidation();
				}
			}
		}
	}

	/**
	 * Invalidates all cache entries.
	 */
	public void invalidateAll() {
		int count = cache.size();
		cache.clear();
		statistics.recordBulkInvalidation(count);
	}

	/**
	 * Gets the cache statistics.
	 *
	 * @return the statistics
	 */
	public CacheStatistics getStatistics() {
		return statistics;
	}

	/**
	 * Gets the current cache size.
	 *
	 * @return number of cached entries
	 */
	public int size() {
		return cache.size();
	}

	/**
	 * Checks if a cached result is expired.
	 *
	 * @param cached the cached result
	 * @return true if expired
	 */
	private boolean isExpired(CachedResult cached) {
		return System.currentTimeMillis() - cached.creationTime > expirationMs;
	}

	/**
	 * Computes a version hash for a function based on its content.
	 *
	 * @param function the function
	 * @return version hash
	 */
	private long computeFunctionVersion(Function function) {
		long hash = 17;
		
		hash = 31 * hash + function.getBody().getNumAddresses();
		
		InstructionIterator instructions = program.getListing()
			.getInstructions(function.getBody(), true);
		
		int count = 0;
		while (instructions.hasNext() && count < 100) {
			Instruction instr = instructions.next();
			hash = 31 * hash + instr.getMnemonicString().hashCode();
			hash = 31 * hash + instr.getNumOperands();
			count++;
		}
		
		hash = 31 * hash + function.getParameterCount();
		
		return hash;
	}

	/**
	 * Evicts the oldest entries to make room for new ones.
	 */
	private void evictOldestEntries() {
		int toEvict = maxEntries / 10;
		
		List<Map.Entry<CacheKey, CachedResult>> entries = new ArrayList<>(cache.entrySet());
		entries.sort(Comparator.comparingLong(e -> e.getValue().lastAccessTime));
		
		for (int i = 0; i < toEvict && i < entries.size(); i++) {
			cache.remove(entries.get(i).getKey());
			statistics.recordEviction();
		}
	}

	/**
	 * Cache key combining function address and property type.
	 */
	private static class CacheKey {
		final Address functionAddress;
		final PropertyType propertyType;

		CacheKey(Address functionAddress, PropertyType propertyType) {
			this.functionAddress = functionAddress;
			this.propertyType = propertyType;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			CacheKey cacheKey = (CacheKey) o;
			return Objects.equals(functionAddress, cacheKey.functionAddress) &&
				propertyType == cacheKey.propertyType;
		}

		@Override
		public int hashCode() {
			return Objects.hash(functionAddress, propertyType);
		}
	}

	/**
	 * Cached verification result with metadata.
	 */
	private static class CachedResult {
		final BatchVerificationResult result;
		final long functionVersion;
		final long creationTime;
		long lastAccessTime;

		CachedResult(BatchVerificationResult result, long functionVersion) {
			this.result = result;
			this.functionVersion = functionVersion;
			this.creationTime = System.currentTimeMillis();
			this.lastAccessTime = this.creationTime;
		}
	}

	/**
	 * Tracks function dependencies for cache invalidation.
	 */
	public static class DependencyTracker {
		private final Program program;
		private final Map<Address, Set<Address>> callGraph;
		private final Map<Address, Set<Address>> reverseCallGraph;

		public DependencyTracker(Program program) {
			this.program = program;
			this.callGraph = new ConcurrentHashMap<>();
			this.reverseCallGraph = new ConcurrentHashMap<>();
		}

		/**
		 * Tracks dependencies for a function.
		 *
		 * @param function the function
		 */
		public void trackDependencies(Function function) {
			Address funcAddr = function.getEntryPoint();
			Set<Address> callees = new HashSet<>();
			
			InstructionIterator instructions = program.getListing()
				.getInstructions(function.getBody(), true);
			
			while (instructions.hasNext()) {
				Instruction instr = instructions.next();
				PcodeOp[] pcodeOps = instr.getPcode();
				
				for (PcodeOp op : pcodeOps) {
					if (op.getOpcode() == PcodeOp.CALL) {
						Varnode target = op.getInput(0);
						if (target.isAddress()) {
							Address calleeAddr = target.getAddress();
							callees.add(calleeAddr);
							
							reverseCallGraph.computeIfAbsent(calleeAddr, k -> ConcurrentHashMap.newKeySet())
								.add(funcAddr);
						}
					}
				}
			}
			
			callGraph.put(funcAddr, callees);
		}

		/**
		 * Gets all functions affected by a change to the given function.
		 *
		 * @param functionAddress the changed function's address
		 * @return set of affected function addresses
		 */
		public Set<Address> getAffectedFunctions(Address functionAddress) {
			Set<Address> affected = new HashSet<>();
			Queue<Address> worklist = new LinkedList<>();
			worklist.add(functionAddress);
			
			while (!worklist.isEmpty()) {
				Address current = worklist.poll();
				if (affected.add(current)) {
					Set<Address> callers = reverseCallGraph.get(current);
					if (callers != null) {
						worklist.addAll(callers);
					}
				}
			}
			
			affected.remove(functionAddress);
			return affected;
		}

		/**
		 * Clears all tracked dependencies.
		 */
		public void clear() {
			callGraph.clear();
			reverseCallGraph.clear();
		}
	}

	/**
	 * Statistics for cache performance monitoring.
	 */
	public static class CacheStatistics {
		private long hits;
		private long misses;
		private long stores;
		private long invalidations;
		private long expirations;
		private long evictions;

		public synchronized void recordHit() {
			hits++;
		}

		public synchronized void recordMiss() {
			misses++;
		}

		public synchronized void recordStore() {
			stores++;
		}

		public synchronized void recordInvalidation() {
			invalidations++;
		}

		public synchronized void recordBulkInvalidation(int count) {
			invalidations += count;
		}

		public synchronized void recordExpiration() {
			expirations++;
		}

		public synchronized void recordEviction() {
			evictions++;
		}

		public synchronized long getHits() {
			return hits;
		}

		public synchronized long getMisses() {
			return misses;
		}

		public synchronized long getStores() {
			return stores;
		}

		public synchronized long getInvalidations() {
			return invalidations;
		}

		public synchronized long getExpirations() {
			return expirations;
		}

		public synchronized long getEvictions() {
			return evictions;
		}

		public synchronized double getHitRate() {
			long total = hits + misses;
			return total > 0 ? (double) hits / total : 0.0;
		}

		public synchronized String getSummary() {
			return String.format(
				"Cache Statistics: hits=%d, misses=%d, hit_rate=%.2f%%, " +
				"stores=%d, invalidations=%d, expirations=%d, evictions=%d",
				hits, misses, getHitRate() * 100, stores, invalidations, expirations, evictions
			);
		}

		public synchronized void reset() {
			hits = 0;
			misses = 0;
			stores = 0;
			invalidations = 0;
			expirations = 0;
			evictions = 0;
		}
	}
}
