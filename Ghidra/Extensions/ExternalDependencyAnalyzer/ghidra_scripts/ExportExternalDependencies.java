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
//Recovers the external data-source dependencies of the current program (hostnames, addresses,
//URLs, connection strings, ports, network and authentication call sites, and related findings)
//and writes <program>-dependencies.json and <program>-dependencies.md to an output directory.
//
//Script arguments:
//  <outputDir>                 directory that receives the two files (created if missing)
//  --reuse                     use the result stored by External Dependency Analyzer when present
//  --api-table=<path>          analyst-supplied API table replacing the bundled one
//  --min-string-length=<n>     ignore strings shorter than n characters (default 6)
//  --no-comments               do not write EOL/plate comments into the program
//  --no-bookmarks              do not write bookmarks into the program
//
//Headless example:
//  analyzeHeadless <project dir> <project> -import <binary> \
//      -postScript ExportExternalDependencies.java /tmp/out
//
//Credentials found in constants are redacted in every output path.
//@category Analysis
//@menupath Tools.External Dependencies.Export dependency map

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import externaldependencyanalyzer.*;
import externaldependencyanalyzer.DependencyModel.ScanResult;
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;

public class ExportExternalDependencies extends GhidraScript {

	private static final int MAX_NAME_LENGTH = 128;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No program is open");
			return;
		}
		String[] args = getScriptArgs();
		Path outDir = null;
		boolean reuse = false;
		ScanOptions options = ScanOptions.defaults();
		for (String arg : args) {
			if (arg.equals("--reuse")) {
				reuse = true;
			}
			else if (arg.equals("--no-comments")) {
				options = options.withWriteComments(false);
			}
			else if (arg.equals("--no-bookmarks")) {
				options = options.withWriteBookmarks(false);
			}
			else if (arg.startsWith("--api-table=")) {
				options = options.withApiTablePath(arg.substring("--api-table=".length()));
			}
			else if (arg.startsWith("--min-string-length=")) {
				options = options.withMinStringLength(
					parseLength(arg.substring("--min-string-length=".length())));
			}
			else if (arg.startsWith("--")) {
				printerr("Unknown option: " + arg);
				return;
			}
			else if (outDir == null) {
				outDir = Paths.get(arg);
			}
			else {
				printerr("Unexpected argument");
				return;
			}
		}
		if (outDir == null) {
			if (isRunningHeadless()) {
				printerr("Usage: ExportExternalDependencies.java <outputDir> [--reuse] " +
					"[--api-table=<path>] [--min-string-length=<n>] [--no-comments] [--no-bookmarks]");
				return;
			}
			java.io.File chosen = askDirectory("Output directory for dependency map", "Select");
			outDir = chosen.toPath();
		}

		ScanResult result = null;
		if (reuse) {
			String stored = ProgramAnnotator.storedResultJson(currentProgram);
			if (stored != null) {
				try {
					result = DependencyReportReader.fromJson(stored);
					println("Reusing result stored by " + ExternalDependencyAnalyzer.NAME);
				}
				catch (IOException e) {
					Msg.warn(this, "Stored result could not be parsed; rescanning", e);
				}
			}
		}
		if (result == null) {
			result = new DependencyScanner(currentProgram, options, monitor).scan();
			ProgramAnnotator.annotate(currentProgram, result, options, monitor);
		}

		Files.createDirectories(outDir);
		String base = safeName(currentProgram.getName());
		Path json = outDir.resolve(base + "-dependencies.json");
		Path md = outDir.resolve(base + "-dependencies.md");
		Files.writeString(json, DependencyReportWriter.toJson(result), StandardCharsets.UTF_8);
		Files.writeString(md, DependencyReportWriter.toMarkdown(result), StandardCharsets.UTF_8);

		println("Endpoints: " + result.endpoints().size() + ", API call sites: " +
			result.apiCallSites().size() + ", findings: " + result.findings().size());
		for (String w : result.warnings()) {
			println("Warning: " + w);
		}
		println("Wrote " + json);
		println("Wrote " + md);
	}

	private static int parseLength(String s) {
		try {
			int n = Integer.parseInt(s.trim());
			return Math.max(2, Math.min(256, n));
		}
		catch (NumberFormatException e) {
			return ScanOptions.DEFAULT_MIN_STRING_LENGTH;
		}
	}

	static String safeName(String name) {
		StringBuilder sb = new StringBuilder();
		for (char c : name.toCharArray()) {
			if (Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-') {
				sb.append(c);
			}
			else {
				sb.append('_');
			}
			if (sb.length() >= MAX_NAME_LENGTH) {
				break;
			}
		}
		String s = sb.toString();
		while (s.startsWith(".")) {
			s = s.substring(1);
		}
		return s.isEmpty() ? "program" : s;
	}
}
