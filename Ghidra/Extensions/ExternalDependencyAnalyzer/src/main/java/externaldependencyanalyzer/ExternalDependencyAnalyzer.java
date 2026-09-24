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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers external data-source dependencies (endpoints, connection strings, protocol hints
 * and network/auth call sites) from ELF and PE programs and records them as bookmarks,
 * comments and a program property summary.
 */
public class ExternalDependencyAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "External Dependency Analyzer";
	private static final String DESCRIPTION =
		"Recovers hostnames, addresses, URLs, connection strings, ports and network/auth API " +
			"call sites from the binary and links each constant to the functions and calls that " +
			"use it. Credentials found in constants are redacted in all output.";

	static final String OPT_ENDPOINTS = "Recover endpoints";
	static final String OPT_CONNECTION_STRINGS = "Recover connection strings";
	static final String OPT_PROTOCOL_HINTS = "Recover protocol hints";
	static final String OPT_API_CALL_SITES = "Recover API call sites";
	static final String OPT_FINDINGS = "Report findings";
	static final String OPT_PORT_HEURISTICS = "Recover ports by sockaddr heuristic";
	static final String OPT_MIN_STRING_LENGTH = "Minimum string length";
	static final String OPT_API_TABLE_PATH = "Custom API table path";
	static final String OPT_WRITE_COMMENTS = "Write comments";
	static final String OPT_WRITE_BOOKMARKS = "Write bookmarks";

	private ScanOptions scanOptions = ScanOptions.defaults();

	public ExternalDependencyAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return format != null && (format.contains("ELF") || format.contains("PE") ||
			format.contains("Mach-O") || format.contains("Raw"));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		ScanOptions d = ScanOptions.defaults();
		options.registerOption(OPT_ENDPOINTS, d.endpoints(), null,
			"Hostnames, IP literals, host:port pairs, ports and UNC/NFS paths");
		options.registerOption(OPT_CONNECTION_STRINGS, d.connectionStrings(), null,
			"URLs and database, broker and directory connection strings");
		options.registerOption(OPT_PROTOCOL_HINTS, d.protocolHints(), null,
			"HTTP paths, auth header constants, OGC/gRPC/Kafka keywords, LDAP DNs and Kerberos realms");
		options.registerOption(OPT_API_CALL_SITES, d.apiCallSites(), null,
			"Call sites of network and authentication APIs listed in the API table");
		options.registerOption(OPT_FINDINGS, d.findings(), null,
			"Credentials, plaintext protocols, disabled TLS verification, embedded addresses and duplicate hosts");
		options.registerOption(OPT_PORT_HEURISTICS, d.portHeuristics(), null,
			"Report byte-swapped port immediates stored in functions that call socket APIs");
		options.registerOption(OPT_MIN_STRING_LENGTH, d.minStringLength(), null,
			"Strings shorter than this are not classified");
		options.registerOption(OPT_API_TABLE_PATH, d.apiTablePath(), null,
			"Path to a JSON API table that replaces the bundled data/external_dependency_apis.json");
		options.registerOption(OPT_WRITE_COMMENTS, d.writeComments(), null,
			"Write EOL and plate comments at defining addresses and call sites");
		options.registerOption(OPT_WRITE_BOOKMARKS, d.writeBookmarks(), null,
			"Write bookmarks in the External Dependency category");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		ScanOptions d = ScanOptions.defaults();
		int minLen = options.getInt(OPT_MIN_STRING_LENGTH, d.minStringLength());
		if (minLen < 2) {
			minLen = 2;
		}
		if (minLen > 256) {
			minLen = 256;
		}
		String path = options.getString(OPT_API_TABLE_PATH, d.apiTablePath());
		if (path != null && path.length() > 4096) {
			path = "";
		}
		scanOptions = new ScanOptions(options.getBoolean(OPT_ENDPOINTS, d.endpoints()),
			options.getBoolean(OPT_CONNECTION_STRINGS, d.connectionStrings()),
			options.getBoolean(OPT_PROTOCOL_HINTS, d.protocolHints()),
			options.getBoolean(OPT_API_CALL_SITES, d.apiCallSites()),
			options.getBoolean(OPT_FINDINGS, d.findings()),
			options.getBoolean(OPT_PORT_HEURISTICS, d.portHeuristics()), minLen,
			path == null ? "" : path, options.getBoolean(OPT_WRITE_COMMENTS, d.writeComments()),
			options.getBoolean(OPT_WRITE_BOOKMARKS, d.writeBookmarks()));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		DependencyModel.ScanResult result;
		try {
			result = new DependencyScanner(program, scanOptions, monitor).scan();
			ProgramAnnotator.annotate(program, result, scanOptions, monitor);
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (RuntimeException e) {
			Msg.error(this, "External dependency analysis failed", e);
			log.appendMsg(NAME, "Analysis did not complete; see the application log");
			return false;
		}
		for (String w : result.warnings()) {
			log.appendMsg(NAME, w);
		}
		log.appendMsg(NAME, result.endpoints().size() + " endpoints, " +
			result.apiCallSites().size() + " API call sites, " + result.findings().size() +
			" findings");
		return true;
	}

	ScanOptions getScanOptions() {
		return scanOptions;
	}
}
