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

import ghidra.program.model.listing.Program;

public class ExternalDependencyExporter {

	private ExternalDependencyExporter() {
	}

	public static String toJson(Program program, List<DependencyFinding> findings) {
		List<DependencyFinding> sorted = new ArrayList<>(findings);
		Collections.sort(sorted);
		StringBuilder out = new StringBuilder();
		out.append("{\n");
		out.append("  \"schema\": \"external-dependency-report/1\",\n");
		out.append("  \"program\": ").append(jsonString(program.getName())).append(",\n");
		out.append("  \"findings\": [");
		if (!sorted.isEmpty()) {
			out.append('\n');
		}
		for (int i = 0; i < sorted.size(); i++) {
			DependencyFinding finding = sorted.get(i);
			out.append("    {\n");
			out.append("      \"from_address\": ").append(jsonString(finding.getFromAddress().toString()))
				.append(",\n");
			out.append("      \"category\": ").append(jsonString(finding.getCategory().getId()))
				.append(",\n");
			out.append("      \"severity\": ").append(jsonString(finding.getCategory().getSeverity()))
				.append(",\n");
			out.append("      \"kind\": ").append(jsonString(finding.getKind())).append(",\n");
			out.append("      \"value\": ").append(jsonString(finding.getMatchedValue())).append(",\n");
			out.append("      \"library\": ").append(jsonNullable(finding.getLibrary())).append(",\n");
			out.append("      \"indicator_address\": ")
				.append(jsonString(finding.getIndicatorAddress().toString())).append(",\n");
			out.append("      \"function\": ").append(jsonNullable(finding.getFunctionName()))
				.append(",\n");
			out.append("      \"via_thunk\": ").append(finding.isViaThunk()).append('\n');
			out.append("    }");
			if (i + 1 < sorted.size()) {
				out.append(',');
			}
			out.append('\n');
		}
		out.append("  ]\n");
		out.append("}\n");
		return out.toString();
	}

	public static String toMarkdown(Program program, List<DependencyFinding> findings) {
		List<DependencyFinding> sorted = new ArrayList<>(findings);
		Collections.sort(sorted);
		StringBuilder out = new StringBuilder();
		out.append("# External Dependency Report\n\n");
		out.append("Program: ").append(program.getName()).append("\n\n");
		out.append("| From | Category | Severity | Kind | Value | Library | Indicator | Function | Via thunk |\n");
		out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
		for (DependencyFinding finding : sorted) {
			out.append("| ").append(finding.getFromAddress()).append(" | ");
			out.append(finding.getCategory().getId()).append(" | ");
			out.append(finding.getCategory().getSeverity()).append(" | ");
			out.append(finding.getKind()).append(" | ");
			out.append(markdown(finding.getMatchedValue())).append(" | ");
			out.append(finding.getLibrary() == null ? "-" : markdown(finding.getLibrary())).append(" | ");
			out.append(markdown(finding.getIndicatorAddress().toString())).append(" | ");
			out.append(finding.getFunctionName() == null ? "-" : markdown(finding.getFunctionName()))
				.append(" | ");
			out.append(finding.isViaThunk()).append(" |\n");
		}
		return out.toString();
	}

	private static String markdown(String value) {
		return value.replace("|", "\\|");
	}

	private static String jsonNullable(String value) {
		return value == null ? "null" : jsonString(value);
	}

	private static String jsonString(String value) {
		StringBuilder out = new StringBuilder("\"");
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			switch (c) {
				case '"' -> out.append("\\\"");
				case '\\' -> out.append("\\\\");
				case '\b' -> out.append("\\b");
				case '\f' -> out.append("\\f");
				case '\n' -> out.append("\\n");
				case '\r' -> out.append("\\r");
				case '\t' -> out.append("\\t");
				default -> {
					if (c < 0x20) {
						out.append(String.format("\\u%04x", (int) c));
					}
					else {
						out.append(c);
					}
				}
			}
		}
		return out.append('"').toString();
	}
}
