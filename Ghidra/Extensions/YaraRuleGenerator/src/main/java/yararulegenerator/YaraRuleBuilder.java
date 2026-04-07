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

import java.util.*;

/**
 * Assembles the final YARA rule text from byte patterns, string indicators,
 * and metadata.
 */
public class YaraRuleBuilder {

	private String ruleName;
	private String md5;
	private String sha256;
	private String author;
	private String date;
	private String description;
	private List<String> bytePatterns = new ArrayList<>();
	private Map<String, String> stringIndicators = new LinkedHashMap<>();

	public void setRuleName(String name) {
		this.ruleName = name;
	}

	public void setMetadata(String md5, String sha256, String author, String date,
			String desc) {
		this.md5 = md5;
		this.sha256 = sha256;
		this.author = author;
		this.date = date;
		this.description = desc;
	}

	public void addBytePatterns(List<String> patterns) {
		this.bytePatterns.addAll(patterns);
	}

	public void addStringIndicators(Map<String, String> indicators) {
		this.stringIndicators.putAll(indicators);
	}

	/**
	 * Build the complete YARA rule text.
	 *
	 * @return the formatted YARA rule as a string
	 */
	public String build() {
		StringBuilder sb = new StringBuilder();
		sb.append("rule ").append(ruleName).append(" {\n");

		// Metadata
		sb.append("    meta:\n");
		if (md5 != null) {
			sb.append("        md5 = \"").append(md5).append("\"\n");
		}
		if (sha256 != null) {
			sb.append("        sha256 = \"").append(sha256).append("\"\n");
		}
		if (author != null) {
			sb.append("        author = \"").append(author).append("\"\n");
		}
		if (date != null) {
			sb.append("        date = \"").append(date).append("\"\n");
		}
		if (description != null) {
			sb.append("        description = \"").append(description)
				.append("\"\n");
		}

		// Strings section (only emit if there are patterns or indicators)
		if (!bytePatterns.isEmpty() || !stringIndicators.isEmpty()) {
			sb.append("\n    strings:\n");
			for (int i = 0; i < bytePatterns.size(); i++) {
				sb.append("        $code_").append(i).append(" = { ")
					.append(bytePatterns.get(i)).append(" }\n");
			}
			for (Map.Entry<String, String> entry : stringIndicators.entrySet()) {
				String escaped =
					entry.getValue().replace("\\", "\\\\").replace("\"", "\\\"");
				sb.append("        ").append(entry.getKey()).append(" = \"")
					.append(escaped).append("\"\n");
			}
		}

		// Condition block
		sb.append("\n    condition:\n");
		List<String> conditions = new ArrayList<>();
		if (!bytePatterns.isEmpty()) {
			if (bytePatterns.size() == 1) {
				conditions.add("$code_0");
			}
			else {
				conditions.add("all of ($code_*)");
			}
		}
		if (!stringIndicators.isEmpty()) {
			int threshold = Math.max(1, stringIndicators.size() / 2);
			List<String> stringVarNames =
				new ArrayList<>(stringIndicators.keySet());
			conditions.add(
				threshold + " of (" + String.join(", ", stringVarNames) + ")");
		}
		if (conditions.isEmpty()) {
			sb.append("        true\n");
		}
		else {
			sb.append("        ")
				.append(String.join(" and\n        ", conditions)).append("\n");
		}

		sb.append("}\n");
		return sb.toString();
	}
}
