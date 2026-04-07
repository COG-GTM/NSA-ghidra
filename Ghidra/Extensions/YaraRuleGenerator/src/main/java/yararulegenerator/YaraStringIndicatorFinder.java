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
package yararulegenerator;

import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.util.ProgramSelection;

import java.util.*;
import java.util.regex.*;

/**
 * Scans selected regions (and referenced data) for high-value string indicators
 * useful in YARA rules. Classifies strings using regex patterns into categories
 * such as C2 URLs, mutex names, registry paths, file paths, and suspicious APIs.
 */
public class YaraStringIndicatorFinder {

	private Program program;

	// Regex patterns for high-value indicators
	private static final Pattern URL_PATTERN =
		Pattern.compile("https?://[\\w./-]+", Pattern.CASE_INSENSITIVE);
	private static final Pattern IP_PATTERN =
		Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
	private static final Pattern REGISTRY_PATTERN =
		Pattern.compile(
			"(HKEY_|SOFTWARE\\\\|CurrentVersion\\\\Run|\\\\Microsoft\\\\Windows)",
			Pattern.CASE_INSENSITIVE);
	private static final Pattern MUTEX_PATTERN =
		Pattern.compile("(Global\\\\|Local\\\\)[\\w-]+");
	private static final Pattern FILE_PATH_PATTERN =
		Pattern.compile(
			"[A-Z]:\\\\[\\w\\\\. -]+\\.(exe|dll|bat|ps1|vbs|cmd)",
			Pattern.CASE_INSENSITIVE);
	private static final String[] SUSPICIOUS_APIS = {
		"VirtualAlloc",
		"WriteProcessMemory",
		"CreateRemoteThread",
		"NtUnmapViewOfSection",
		"RtlDecompressBuffer"
	};

	public YaraStringIndicatorFinder(Program program) {
		this.program = program;
	}

	/**
	 * Find high-value string indicators within the selected region and
	 * from data referenced by the selected instructions.
	 *
	 * @param selection the program selection to scan
	 * @return map of YARA variable names to string literals
	 */
	public Map<String, String> findIndicators(ProgramSelection selection) {
		Map<String, String> indicators = new LinkedHashMap<>();
		Set<String> seen = new HashSet<>();
		int counter = 0;

		// 1. Get strings defined within the selection
		AddressSet addrSet = new AddressSet(selection);
		DefinedStringIterator stringIt =
			DefinedStringIterator.forProgram(program, addrSet);
		while (stringIt.hasNext()) {
			Data data = stringIt.next();
			String value = getStringValue(data);
			if (value != null && !value.isEmpty()) {
				counter = classifyAndAdd(indicators, seen, value, counter);
			}
		}

		// 2. Follow references FROM the selection to find referenced strings
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		for (AddressRange range : selection) {
			AddressSet rangeSet = new AddressSet(range);
			InstructionIterator instrIt = listing.getInstructions(rangeSet, true);
			while (instrIt.hasNext()) {
				Instruction instr = instrIt.next();
				for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
					if (ref.getReferenceType().isData()) {
						Data refData =
							listing.getDefinedDataAt(ref.getToAddress());
						if (refData != null && refData.hasStringValue()) {
							String val = getStringValue(refData);
							if (val != null && !val.isEmpty()) {
								counter = classifyAndAdd(indicators, seen,
									val, counter);
							}
						}
					}
				}
			}
		}

		return indicators;
	}

	/**
	 * Extract the raw string value from a Data element using StringDataInstance,
	 * avoiding the display-formatted representation which includes C-style
	 * escape sequences and surrounding quotes.
	 */
	private static String getStringValue(Data data) {
		StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
		if (sdi == null) {
			return null;
		}
		String value = sdi.getStringValue();
		if (value != null) {
			value = value.trim();
		}
		return value;
	}

	private int classifyAndAdd(Map<String, String> indicators, Set<String> seen,
			String value, int counter) {

		if (value.length() < 4 || seen.contains(value)) {
			return counter;
		}
		seen.add(value);

		String prefix = null;
		if (URL_PATTERN.matcher(value).find()) {
			prefix = "c2_url";
		}
		else if (IP_PATTERN.matcher(value).find()) {
			prefix = "c2_ip";
		}
		else if (REGISTRY_PATTERN.matcher(value).find()) {
			prefix = "reg_path";
		}
		else if (MUTEX_PATTERN.matcher(value).find()) {
			prefix = "mutex";
		}
		else if (FILE_PATH_PATTERN.matcher(value).find()) {
			prefix = "file_path";
		}
		else {
			for (String api : SUSPICIOUS_APIS) {
				if (value.contains(api)) {
					prefix = "sus_api";
					break;
				}
			}
		}

		if (prefix != null) {
			indicators.put("$" + prefix + "_" + counter, value);
			counter++;
		}
		else if (value.length() >= 8) {
			// Include longer strings as generic indicators
			indicators.put("$str_" + counter, value);
			counter++;
		}
		return counter;
	}
}
