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
package externaldependencyanalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExternalDependencyScanner {

	private ExternalDependencyScanner() {
	}

	public static List<DependencyFinding> scan(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<DependencyFinding> findings = new ArrayList<>();
		scanStrings(program, monitor, findings);
		scanImports(program, monitor, findings);
		Collections.sort(findings);
		return findings;
	}

	private static void scanStrings(Program program, TaskMonitor monitor,
			List<DependencyFinding> findings) throws CancelledException {
		for (Data data : DefinedStringIterator.forProgram(program)) {
			monitor.checkCancelled();
			String value = StringDataInstance.getStringDataInstance(data).getStringValue();
			if (value == null && data.getValue() != null) {
				value = data.getValue().toString();
			}
			DependencyCategory category = DependencyRules.classifyString(value);
			if (category == null) {
				continue;
			}
			String redacted = DependencyRules.redact(value);
			ReferenceIterator references =
				program.getReferenceManager().getReferencesTo(data.getAddress());
			boolean foundReference = false;
			while (references.hasNext()) {
				monitor.checkCancelled();
				foundReference = true;
				addFinding(findings, category, "string", redacted, null, data.getAddress(),
					references.next().getFromAddress(), program);
			}
			if (!foundReference) {
				addFinding(findings, category, "string", redacted, null, data.getAddress(),
					data.getAddress(), program);
			}
		}
	}

	private static void scanImports(Program program, TaskMonitor monitor,
			List<DependencyFinding> findings) throws CancelledException {
		String[] libraries = program.getExternalManager().getExternalLibraryNames();
		List<String> sortedLibraries = new ArrayList<>(List.of(libraries));
		Collections.sort(sortedLibraries);
		for (String library : sortedLibraries) {
			monitor.checkCancelled();
			ExternalLocationIterator locations =
				program.getExternalManager().getExternalLocations(library);
			while (locations.hasNext()) {
				monitor.checkCancelled();
				ExternalLocation location = locations.next();
				DependencyCategory category = DependencyRules.classifyImport(location.getLabel());
				if (category == null) {
					continue;
				}
				Address indicatorAddress = location.getExternalSpaceAddress();
				ReferenceIterator references =
					program.getReferenceManager().getReferencesTo(indicatorAddress);
				while (references.hasNext()) {
					monitor.checkCancelled();
					addFinding(findings, category, "import", location.getLabel(), library,
						indicatorAddress, references.next().getFromAddress(), program);
				}
			}
		}
	}

	private static void addFinding(List<DependencyFinding> findings, DependencyCategory category,
			String kind, String value, String library, Address indicatorAddress, Address fromAddress,
			Program program) {
		Function function = program.getFunctionManager().getFunctionContaining(fromAddress);
		boolean viaThunk = false;
		if (function != null && function.isThunk()) {
			Function thunked = function.getThunkedFunction(true);
			if (thunked != null) {
				function = thunked;
				viaThunk = true;
			}
		}
		findings.add(new DependencyFinding(category, kind, value, library, indicatorAddress,
			fromAddress, function == null ? null : function.getName(), viaThunk));
	}
}
