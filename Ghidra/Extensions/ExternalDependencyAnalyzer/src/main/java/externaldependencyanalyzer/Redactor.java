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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removes credential material from recovered strings before it reaches any output path
 * (bookmarks, comments, JSON, Markdown, logs).
 */
public final class Redactor {

	public static final String MASK = "***";

	private static final Pattern USERINFO =
		Pattern.compile("(?<=://)([^/@:\\s]+):([^@/\\s]+)(?=@)");

	private static final Pattern KEY_VALUE = Pattern.compile(
		"(?i)\\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|client[_-]?secret|sasl\\.password)\\s*[=:]\\s*(?:'[^']*'|\"[^\"]*\"|\\{[^}]*\\}|[^;&\\s,'\"]+)");

	private static final Pattern BEARER =
		Pattern.compile("(?i)\\b(Bearer|Basic|Token|ApiKey)\\s+([A-Za-z0-9._~+/=-]{8,})");

	private static final Pattern HEADER_VALUE = Pattern.compile(
		"(?i)\\b(X-Api-Key|X-Auth-Token|Api-Key|Authorization|Proxy-Authorization|Ocp-Apim-Subscription-Key|X-Amz-Security-Token|X-Access-Token|X-Client-Secret|X-Auth-Key)\\s*:\\s*([^\\r\\n'\"]+)");

	public record Result(String text, boolean redacted) {
	}

	private Redactor() {
	}

	/** Redacts credential material in {@code s}. Never throws; a null input yields an empty result. */
	public static Result redact(String s) {
		if (s == null) {
			return new Result("", false);
		}
		boolean changed = false;
		String out = s;

		Matcher m = USERINFO.matcher(out);
		if (m.find()) {
			out = m.replaceAll("$1:" + MASK);
			changed = true;
		}

		m = KEY_VALUE.matcher(out);
		if (m.find()) {
			out = m.replaceAll("$1=" + MASK);
			changed = true;
		}

		m = HEADER_VALUE.matcher(out);
		if (m.find()) {
			out = m.replaceAll("$1: " + MASK);
			changed = true;
		}

		m = BEARER.matcher(out);
		if (m.find()) {
			out = m.replaceAll("$1 " + MASK);
			changed = true;
		}
		return new Result(out, changed);
	}

	/** True when the string appears to carry a credential, without revealing it. */
	public static boolean containsCredential(String s) {
		return redact(s).redacted();
	}
}
