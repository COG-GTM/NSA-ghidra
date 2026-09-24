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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Identifies the inputs of a scan: the scan-affecting options, the content of the API table that
 * was actually used, and the program state the scan depends on (memory layout, defined
 * functions, instructions and data). A stored result is only reused when the fingerprint of the
 * requested scan equals the one recorded with the result.
 */
public final class ScanFingerprint {

	private static final String VERSION = "1";

	private ScanFingerprint() {
	}

	public static String compute(Program program, ScanOptions options) {
		ApiTable table = ApiTable.loadOrDefault(options.apiTablePath(), new ArrayList<>());
		return compute(program, options, table);
	}

	static String compute(Program program, ScanOptions options, ApiTable table) {
		Listing listing = program.getListing();
		List<String> parts = new ArrayList<>();
		parts.add("v" + VERSION);
		parts.add("options=" + options.endpoints() + "," + options.connectionStrings() + "," +
			options.protocolHints() + "," + options.apiCallSites() + "," + options.findings() + "," +
			options.portHeuristics() + "," + options.minStringLength());
		parts.add("apiTable=" + table.getContentHash());
		String sha = program.getExecutableSHA256();
		parts.add("executable=" + (sha == null ? "" : sha));
		parts.add("language=" + program.getLanguageID() + "/" + program.getCompilerSpec()
				.getCompilerSpecID());
		parts.add("functions=" + program.getFunctionManager().getFunctionCount());
		parts.add("instructions=" + listing.getNumInstructions());
		parts.add("data=" + listing.getNumDefinedData());
		StringBuilder blocks = new StringBuilder();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			blocks.append(b.getStart()).append('-').append(b.getEnd()).append(':')
					.append(b.isInitialized() ? 'i' : 'u').append(b.isWrite() ? 'w' : 'r')
					.append(';');
		}
		parts.add("memory=" + blocks);
		return ApiTable.sha256(String.join("|", parts).getBytes(StandardCharsets.UTF_8));
	}
}
