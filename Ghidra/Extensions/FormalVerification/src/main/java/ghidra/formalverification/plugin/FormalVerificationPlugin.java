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
package ghidra.formalverification.plugin;

import java.util.*;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.formalverification.analyzer.FormalVerificationAnalyzer;
import ghidra.formalverification.core.*;
import ghidra.formalverification.engine.*;
import ghidra.formalverification.integration.DynamicFormalVerificationIntegration;
import ghidra.formalverification.property.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * Ghidra plugin for formal verification of security properties.
 * 
 * This plugin provides:
 * - Automated verification of memory safety, control flow integrity, and arithmetic safety
 * - Integration with Ghidra's analysis pipeline
 * - Interactive verification of selected functions
 * - Visualization of verification results
 * 
 * The plugin uses the Z3 theorem prover to mathematically prove or disprove
 * security properties, providing stronger guarantees than traditional static analysis.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = "FormalVerification",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Formal Verification Plugin",
	description = "Generate and verify security properties using formal methods. " +
		"Uses Z3 theorem prover to mathematically prove memory safety, " +
		"control flow integrity, and arithmetic safety properties."
)
//@formatter:on
public class FormalVerificationPlugin extends ProgramPlugin {

	private static final String MENU_GROUP = "FormalVerification";
	
	private ScalableVerificationEngine verificationEngine;
	private IncrementalVerificationManager incrementalManager;
	private DynamicFormalVerificationIntegration dynamicIntegration;
	private VerificationConditionGenerator conditionGenerator;

	/**
	 * Creates a new formal verification plugin.
	 *
	 * @param tool the plugin tool
	 */
	public FormalVerificationPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	/**
	 * Creates the plugin actions.
	 */
	private void createActions() {
		DockingAction verifyFunctionAction = new DockingAction("Verify Function", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifyCurrentFunction();
			}
		};
		verifyFunctionAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Verify Current Function" },
				MENU_GROUP));
		verifyFunctionAction.setKeyBindingData(new KeyBindingData("ctrl shift V"));
		verifyFunctionAction.setDescription("Verify security properties of the current function");
		verifyFunctionAction.setHelpLocation(new HelpLocation("FormalVerification", "VerifyFunction"));
		tool.addAction(verifyFunctionAction);

		DockingAction verifyAllAction = new DockingAction("Verify All Functions", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifyAllFunctions();
			}
		};
		verifyAllAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Verify All Functions" },
				MENU_GROUP));
		verifyAllAction.setDescription("Verify security properties of all functions");
		verifyAllAction.setHelpLocation(new HelpLocation("FormalVerification", "VerifyAll"));
		tool.addAction(verifyAllAction);

		DockingAction verifyMemorySafetyAction = new DockingAction("Verify Memory Safety", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifyProperty(PropertyType.MEMORY_SAFETY);
			}
		};
		verifyMemorySafetyAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Memory Safety" },
				MENU_GROUP));
		verifyMemorySafetyAction.setDescription("Verify memory safety properties");
		verifyMemorySafetyAction.setHelpLocation(new HelpLocation("FormalVerification", "MemorySafety"));
		tool.addAction(verifyMemorySafetyAction);

		DockingAction verifyCFIAction = new DockingAction("Verify Control Flow Integrity", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifyProperty(PropertyType.CONTROL_FLOW_INTEGRITY);
			}
		};
		verifyCFIAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Control Flow Integrity" },
				MENU_GROUP));
		verifyCFIAction.setDescription("Verify control flow integrity properties");
		verifyCFIAction.setHelpLocation(new HelpLocation("FormalVerification", "CFI"));
		tool.addAction(verifyCFIAction);

		DockingAction verifyArithmeticAction = new DockingAction("Verify Arithmetic Safety", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifyProperty(PropertyType.ARITHMETIC_SAFETY);
			}
		};
		verifyArithmeticAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Arithmetic Safety" },
				MENU_GROUP));
		verifyArithmeticAction.setDescription("Verify arithmetic safety properties");
		verifyArithmeticAction.setHelpLocation(new HelpLocation("FormalVerification", "Arithmetic"));
		tool.addAction(verifyArithmeticAction);

		DockingAction clearCacheAction = new DockingAction("Clear Verification Cache", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clearCache();
			}
		};
		clearCacheAction.setMenuBarData(
			new MenuData(new String[] { "Analysis", "Formal Verification", "Clear Cache" },
				MENU_GROUP));
		clearCacheAction.setDescription("Clear the verification result cache");
		clearCacheAction.setHelpLocation(new HelpLocation("FormalVerification", "ClearCache"));
		tool.addAction(clearCacheAction);
	}

	@Override
	protected void programActivated(Program program) {
		initializeComponents(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		shutdownComponents();
	}

	/**
	 * Initializes the verification components.
	 *
	 * @param program the program to verify
	 */
	private void initializeComponents(Program program) {
		if (program == null) {
			return;
		}
		
		int threadCount = Runtime.getRuntime().availableProcessors();
		int timeoutMs = 5000;
		
		verificationEngine = new ScalableVerificationEngine(program, threadCount, timeoutMs);
		incrementalManager = new IncrementalVerificationManager(program);
		dynamicIntegration = new DynamicFormalVerificationIntegration(program, verificationEngine);
		conditionGenerator = new VerificationConditionGenerator(program);
		
		Msg.info(this, "Formal Verification Plugin initialized for " + program.getName());
	}

	/**
	 * Shuts down the verification components.
	 */
	private void shutdownComponents() {
		if (verificationEngine != null) {
			verificationEngine.shutdown();
			verificationEngine = null;
		}
		if (dynamicIntegration != null) {
			dynamicIntegration.shutdown();
			dynamicIntegration = null;
		}
		incrementalManager = null;
		conditionGenerator = null;
	}

	/**
	 * Verifies the current function at the cursor location.
	 */
	private void verifyCurrentFunction() {
		Program program = currentProgram;
		if (program == null) {
			Msg.showError(this, null, "Error", "No program is open");
			return;
		}
		
		ProgramLocation location = currentLocation;
		if (location == null) {
			Msg.showError(this, null, "Error", "No location selected");
			return;
		}
		
		Function function = program.getFunctionManager().getFunctionContaining(location.getAddress());
		if (function == null) {
			Msg.showError(this, null, "Error", "No function at current location");
			return;
		}
		
		TaskLauncher.launchModal("Verifying " + function.getName(), monitor -> {
			verifyFunction(function, monitor);
		});
	}

	/**
	 * Verifies all functions in the program.
	 */
	private void verifyAllFunctions() {
		Program program = currentProgram;
		if (program == null) {
			Msg.showError(this, null, "Error", "No program is open");
			return;
		}
		
		TaskLauncher.launchModal("Verifying All Functions", monitor -> {
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			Set<Function> functionSet = new HashSet<>();
			
			while (functions.hasNext()) {
				Function func = functions.next();
				if (!func.isThunk() && !func.isExternal()) {
					functionSet.add(func);
				}
			}
			
			monitor.initialize(functionSet.size());
			
			List<SecurityProperty> properties = Arrays.asList(
				new BufferOverflowProperty(program),
				new ControlFlowIntegrityProperty(program),
				new ArithmeticSafetyProperty(program)
			);
			
			int totalProven = 0;
			int totalViolations = 0;
			int totalUnknown = 0;
			
			for (SecurityProperty property : properties) {
				if (monitor.isCancelled()) {
					break;
				}
				
				monitor.setMessage("Verifying " + property.getName() + "...");
				BatchVerificationResult result = verificationEngine.verify(functionSet, property);
				
				totalProven += result.getProvenCount();
				totalViolations += result.getViolationCount();
				totalUnknown += result.getUnknownCount();
			}
			
			Msg.showInfo(this, null, "Verification Complete",
				String.format("Results: %d proven, %d violations, %d unknown",
					totalProven, totalViolations, totalUnknown));
		});
	}

	/**
	 * Verifies a specific property type for all functions.
	 *
	 * @param propertyType the property type to verify
	 */
	private void verifyProperty(PropertyType propertyType) {
		Program program = currentProgram;
		if (program == null) {
			Msg.showError(this, null, "Error", "No program is open");
			return;
		}
		
		TaskLauncher.launchModal("Verifying " + propertyType.getDisplayName(), monitor -> {
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			Set<Function> functionSet = new HashSet<>();
			
			while (functions.hasNext()) {
				Function func = functions.next();
				if (!func.isThunk() && !func.isExternal()) {
					functionSet.add(func);
				}
			}
			
			SecurityProperty property;
			switch (propertyType) {
				case MEMORY_SAFETY:
					property = new BufferOverflowProperty(program);
					break;
				case CONTROL_FLOW_INTEGRITY:
					property = new ControlFlowIntegrityProperty(program);
					break;
				case ARITHMETIC_SAFETY:
					property = new ArithmeticSafetyProperty(program);
					break;
				default:
					Msg.showError(this, null, "Error", "Unsupported property type");
					return;
			}
			
			BatchVerificationResult result = verificationEngine.verify(functionSet, property);
			
			Msg.showInfo(this, null, "Verification Complete",
				String.format("%s: %d proven, %d violations, %d unknown",
					propertyType.getDisplayName(),
					result.getProvenCount(),
					result.getViolationCount(),
					result.getUnknownCount()));
		});
	}

	/**
	 * Verifies a single function.
	 *
	 * @param function the function to verify
	 * @param monitor the task monitor
	 */
	private void verifyFunction(Function function, TaskMonitor monitor) {
		Program program = function.getProgram();
		
		List<SecurityProperty> properties = Arrays.asList(
			new BufferOverflowProperty(program),
			new ControlFlowIntegrityProperty(program),
			new ArithmeticSafetyProperty(program)
		);
		
		int totalProven = 0;
		int totalViolations = 0;
		int totalUnknown = 0;
		
		for (SecurityProperty property : properties) {
			if (monitor.isCancelled()) {
				break;
			}
			
			if (!property.isApplicable(function)) {
				continue;
			}
			
			monitor.setMessage("Verifying " + property.getName() + "...");
			
			Set<Function> singleFunction = Collections.singleton(function);
			BatchVerificationResult result = verificationEngine.verify(singleFunction, property);
			
			totalProven += result.getProvenCount();
			totalViolations += result.getViolationCount();
			totalUnknown += result.getUnknownCount();
		}
		
		Msg.showInfo(this, null, "Verification Complete",
			String.format("Function %s: %d proven, %d violations, %d unknown",
				function.getName(), totalProven, totalViolations, totalUnknown));
	}

	/**
	 * Clears the verification cache.
	 */
	private void clearCache() {
		if (incrementalManager != null) {
			incrementalManager.invalidateAll();
			Msg.showInfo(this, null, "Cache Cleared", "Verification cache has been cleared");
		}
	}

	/**
	 * Gets the verification engine.
	 *
	 * @return the engine, or null if not initialized
	 */
	public ScalableVerificationEngine getVerificationEngine() {
		return verificationEngine;
	}

	/**
	 * Gets the incremental verification manager.
	 *
	 * @return the manager, or null if not initialized
	 */
	public IncrementalVerificationManager getIncrementalManager() {
		return incrementalManager;
	}

	/**
	 * Gets the dynamic verification integration.
	 *
	 * @return the integration, or null if not initialized
	 */
	public DynamicFormalVerificationIntegration getDynamicIntegration() {
		return dynamicIntegration;
	}

	/**
	 * Gets the condition generator.
	 *
	 * @return the generator, or null if not initialized
	 */
	public VerificationConditionGenerator getConditionGenerator() {
		return conditionGenerator;
	}
}
