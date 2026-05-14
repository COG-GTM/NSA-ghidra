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
package ghidra.formalverification.analyzer;

import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.formalverification.core.*;
import ghidra.formalverification.engine.*;
import ghidra.formalverification.property.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra analyzer that performs formal verification of security properties.
 * Integrates with Ghidra's auto-analysis pipeline to automatically verify
 * functions as they are discovered or modified.
 * 
 * This analyzer uses the Z3 theorem prover to mathematically prove or disprove
 * security properties such as memory safety, control flow integrity, and
 * arithmetic safety.
 */
public class FormalVerificationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Formal Verification";
	private static final String DESCRIPTION = 
		"Mathematical proof of security properties using Z3 theorem prover. " +
		"Verifies memory safety, control flow integrity, and arithmetic safety.";

	private static final String OPTION_VERIFY_MEMORY_SAFETY = "Verify Memory Safety";
	private static final String OPTION_VERIFY_CFI = "Verify Control Flow Integrity";
	private static final String OPTION_VERIFY_ARITHMETIC = "Verify Arithmetic Safety";
	private static final String OPTION_TIMEOUT_MS = "Verification Timeout (ms)";
	private static final String OPTION_MAX_THREADS = "Max Verification Threads";
	private static final String OPTION_STORE_RESULTS = "Store Results in Program";

	private boolean verifyMemorySafety = true;
	private boolean verifyCFI = true;
	private boolean verifyArithmetic = true;
	private int timeoutMs = 5000;
	private int maxThreads = Runtime.getRuntime().availableProcessors();
	private boolean storeResults = true;

	private ScalableVerificationEngine engine;
	private IncrementalVerificationManager incrementalManager;

	/**
	 * Creates a new formal verification analyzer.
	 */
	public FormalVerificationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program != null && program.getLanguage() != null;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_VERIFY_MEMORY_SAFETY, verifyMemorySafety, null,
			"Enable verification of memory safety properties (buffer overflows, null pointers)");
		
		options.registerOption(OPTION_VERIFY_CFI, verifyCFI, null,
			"Enable verification of control flow integrity (indirect calls, returns)");
		
		options.registerOption(OPTION_VERIFY_ARITHMETIC, verifyArithmetic, null,
			"Enable verification of arithmetic safety (overflow, division by zero)");
		
		options.registerOption(OPTION_TIMEOUT_MS, timeoutMs, null,
			"Maximum time in milliseconds for verifying each condition");
		
		options.registerOption(OPTION_MAX_THREADS, maxThreads, null,
			"Maximum number of parallel verification threads");
		
		options.registerOption(OPTION_STORE_RESULTS, storeResults, null,
			"Store verification results as bookmarks in the program");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		verifyMemorySafety = options.getBoolean(OPTION_VERIFY_MEMORY_SAFETY, verifyMemorySafety);
		verifyCFI = options.getBoolean(OPTION_VERIFY_CFI, verifyCFI);
		verifyArithmetic = options.getBoolean(OPTION_VERIFY_ARITHMETIC, verifyArithmetic);
		timeoutMs = options.getInt(OPTION_TIMEOUT_MS, timeoutMs);
		maxThreads = options.getInt(OPTION_MAX_THREADS, maxThreads);
		storeResults = options.getBoolean(OPTION_STORE_RESULTS, storeResults);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		if (engine == null) {
			engine = new ScalableVerificationEngine(program, maxThreads, timeoutMs);
		}
		
		if (incrementalManager == null) {
			incrementalManager = new IncrementalVerificationManager(program);
		}

		FunctionManager funcManager = program.getFunctionManager();
		FunctionIterator functions = funcManager.getFunctions(set, true);
		
		Set<Function> functionsToVerify = new HashSet<>();
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function func = functions.next();
			if (!func.isThunk() && !func.isExternal()) {
				functionsToVerify.add(func);
			}
		}

		if (functionsToVerify.isEmpty()) {
			return true;
		}

		monitor.setMessage("Formal Verification: Analyzing " + functionsToVerify.size() + " functions");
		monitor.initialize(functionsToVerify.size());

		int totalProven = 0;
		int totalViolations = 0;
		int totalUnknown = 0;

		if (verifyMemorySafety) {
			monitor.setMessage("Verifying memory safety...");
			BufferOverflowProperty memProperty = new BufferOverflowProperty(program);
			BatchVerificationResult result = engine.verify(functionsToVerify, memProperty);
			
			totalProven += result.getProvenCount();
			totalViolations += result.getViolationCount();
			totalUnknown += result.getUnknownCount();
			
			if (storeResults) {
				storeVerificationResults(program, result, log);
			}
			
			log.appendMsg(NAME, String.format("Memory Safety: %d proven, %d violations, %d unknown",
				result.getProvenCount(), result.getViolationCount(), result.getUnknownCount()));
		}

		if (verifyCFI) {
			monitor.setMessage("Verifying control flow integrity...");
			ControlFlowIntegrityProperty cfiProperty = new ControlFlowIntegrityProperty(program);
			BatchVerificationResult result = engine.verify(functionsToVerify, cfiProperty);
			
			totalProven += result.getProvenCount();
			totalViolations += result.getViolationCount();
			totalUnknown += result.getUnknownCount();
			
			if (storeResults) {
				storeVerificationResults(program, result, log);
			}
			
			log.appendMsg(NAME, String.format("CFI: %d proven, %d violations, %d unknown",
				result.getProvenCount(), result.getViolationCount(), result.getUnknownCount()));
		}

		if (verifyArithmetic) {
			monitor.setMessage("Verifying arithmetic safety...");
			ArithmeticSafetyProperty arithProperty = new ArithmeticSafetyProperty(program);
			BatchVerificationResult result = engine.verify(functionsToVerify, arithProperty);
			
			totalProven += result.getProvenCount();
			totalViolations += result.getViolationCount();
			totalUnknown += result.getUnknownCount();
			
			if (storeResults) {
				storeVerificationResults(program, result, log);
			}
			
			log.appendMsg(NAME, String.format("Arithmetic: %d proven, %d violations, %d unknown",
				result.getProvenCount(), result.getViolationCount(), result.getUnknownCount()));
		}

		log.appendMsg(NAME, String.format("Total: %d proven, %d violations, %d unknown",
			totalProven, totalViolations, totalUnknown));

		return true;
	}

	/**
	 * Stores verification results as bookmarks in the program.
	 *
	 * @param program the program
	 * @param result the batch verification result
	 * @param log the message log
	 */
	private void storeVerificationResults(Program program, BatchVerificationResult result,
			MessageLog log) {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		
		for (VerificationResult vr : result.getResults()) {
			if (vr.getCondition() == null || vr.getCondition().getLocation() == null) {
				continue;
			}
			
			Address addr = vr.getCondition().getLocation();
			String category = vr.getCondition().getPropertyType().getDisplayName();
			
			switch (vr.getStatus()) {
				case PROVEN:
					bookmarkManager.setBookmark(addr, BookmarkType.INFO, category,
						"Verified: " + vr.getCondition().getDescription());
					break;
					
				case DISPROVEN:
					bookmarkManager.setBookmark(addr, BookmarkType.WARNING, category,
						"Violation: " + vr.getCondition().getDescription() +
						(vr.getCounterexample() != null ? " [" + vr.getCounterexample() + "]" : ""));
					break;
					
				case UNKNOWN:
				case TIMEOUT:
					bookmarkManager.setBookmark(addr, BookmarkType.NOTE, category,
						"Inconclusive: " + vr.getCondition().getDescription());
					break;
					
				case ERROR:
					bookmarkManager.setBookmark(addr, BookmarkType.ERROR, category,
						"Error: " + vr.getCondition().getDescription() +
						(vr.getErrorMessage() != null ? " [" + vr.getErrorMessage() + "]" : ""));
					break;
			}
		}
	}

	@Override
	public void analysisEnded(Program program) {
		if (engine != null) {
			engine.shutdown();
			engine = null;
		}
		incrementalManager = null;
	}

	/**
	 * Gets the verification engine.
	 *
	 * @return the engine, or null if not initialized
	 */
	public ScalableVerificationEngine getEngine() {
		return engine;
	}

	/**
	 * Gets the incremental verification manager.
	 *
	 * @return the manager, or null if not initialized
	 */
	public IncrementalVerificationManager getIncrementalManager() {
		return incrementalManager;
	}
}
