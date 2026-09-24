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

/** Derives file-system safe report names from program names. */
public final class OutputNames {

	public static final int MAX_LENGTH = 128;
	private static final int HASH_LENGTH = 8;

	private OutputNames() {
	}

	/**
	 * Restricts the name to {@code [A-Za-z0-9._-]} and at most {@link #MAX_LENGTH} characters. A
	 * name that had to be altered gets a suffix derived from the original, so two distinct
	 * program names never map to the same output file.
	 */
	public static String safeName(String name) {
		StringBuilder sb = new StringBuilder();
		boolean altered = false;
		for (char c : name.toCharArray()) {
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '.' || c == '_' || c == '-') {
				sb.append(c);
			}
			else {
				sb.append('_');
				altered = true;
			}
		}
		String s = sb.toString();
		while (s.startsWith(".")) {
			s = s.substring(1);
			altered = true;
		}
		if (s.isEmpty()) {
			s = "program";
			altered = true;
		}
		if (!altered && s.length() <= MAX_LENGTH) {
			return s;
		}
		String suffix =
			"-" + ApiTable.sha256(name.getBytes(StandardCharsets.UTF_8)).substring(0, HASH_LENGTH);
		int limit = MAX_LENGTH - suffix.length();
		if (s.length() > limit) {
			s = s.substring(0, limit);
		}
		return s + suffix;
	}
}
