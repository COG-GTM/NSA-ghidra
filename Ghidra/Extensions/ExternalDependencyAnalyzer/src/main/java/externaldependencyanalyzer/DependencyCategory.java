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

public enum DependencyCategory {
	ENDPOINT("endpoint", "LOW"),
	JDBC("jdbc", "HIGH"),
	HTTP("http", "MEDIUM"),
	QUEUE("queue", "MEDIUM"),
	AUTH_TLS("auth_tls", "HIGH");

	private final String id;
	private final String severity;

	DependencyCategory(String id, String severity) {
		this.id = id;
		this.severity = severity;
	}

	public String getId() {
		return id;
	}

	public String getSeverity() {
		return severity;
	}
}
