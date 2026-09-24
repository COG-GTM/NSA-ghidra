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

import java.util.Set;
import java.util.regex.Pattern;

final class DependencyRules {

	static final String REDACTION_MARKER = "***REDACTED***";

	private static final Pattern JDBC = Pattern.compile("^jdbc:", Pattern.CASE_INSENSITIVE);
	private static final Pattern AUTH_TLS = Pattern.compile(
		"(?i)^(authorization\\s*:|x-api-key\\s*:|bearer\\s|basic\\s)|(?i)(^|[?&])(api_?key|access_token|token)=");
	private static final Pattern QUEUE_SCHEME =
		Pattern.compile("^(amqps?|mqtt|kafka)://", Pattern.CASE_INSENSITIVE);
	private static final Pattern QUEUE_PORT =
		Pattern.compile(":5672$|:9092$|:1883$|:61616$", Pattern.CASE_INSENSITIVE);
	private static final Pattern HTTP = Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);
	private static final Pattern HOSTNAME = Pattern.compile(
		"^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+(?:\\:\\d{1,5})?(?:/\\S*)?$");
	private static final Pattern IPV4 =
		Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d{1,5})?$");
	private static final Pattern BARE_PORT = Pattern.compile("^:\\d{2,5}$");

	private static final Set<String> AUTH_TLS_IMPORTS = Set.of(
		"SSL_connect", "SSL_CTX_new", "SSL_read", "SSL_write", "SSL_set_fd",
		"TLS_client_method", "X509_verify_cert", "gnutls_handshake", "gnutls_init",
		"InitializeSecurityContextA", "InitializeSecurityContextW",
		"AcquireCredentialsHandleA", "AcquireCredentialsHandleW");
	private static final Set<String> HTTP_IMPORTS = Set.of(
		"curl_easy_perform", "curl_easy_setopt", "InternetOpenUrlA", "InternetOpenUrlW",
		"HttpSendRequestA", "HttpSendRequestW", "WinHttpSendRequest", "WinHttpConnect");
	private static final Set<String> JDBC_IMPORTS = Set.of(
		"PQconnectdb", "PQconnectdbParams", "mysql_real_connect", "SQLConnect",
		"SQLDriverConnect", "sqlite3_open");
	private static final Set<String> QUEUE_IMPORTS = Set.of(
		"amqp_new_connection", "amqp_socket_open", "amqp_login", "MQCONN", "MQOPEN",
		"rd_kafka_new", "mosquitto_connect");
	private static final Set<String> ENDPOINT_IMPORTS = Set.of(
		"connect", "getaddrinfo", "gethostbyname", "socket", "WSAConnect", "WSAStartup",
		"sendto", "recvfrom");

	private DependencyRules() {
	}

	static DependencyCategory classifyString(String s) {
		if (s == null) {
			return null;
		}
		if (JDBC.matcher(s).find()) {
			return DependencyCategory.JDBC;
		}
		if (AUTH_TLS.matcher(s).find()) {
			return DependencyCategory.AUTH_TLS;
		}
		if (QUEUE_SCHEME.matcher(s).find()) {
			return DependencyCategory.QUEUE;
		}
		if (HTTP.matcher(s).find()) {
			return DependencyCategory.HTTP;
		}
		boolean endpointShaped = BARE_PORT.matcher(s).matches() || IPV4.matcher(s).matches() ||
			isHostname(s);
		if (endpointShaped &&
			(s.matches("(?i)^(?:mq|rabbitmq|kafka)\\..*") || QUEUE_PORT.matcher(s).find())) {
			return DependencyCategory.QUEUE;
		}
		if (endpointShaped) {
			return DependencyCategory.ENDPOINT;
		}
		return null;
	}

	private static boolean isHostname(String s) {
		if (!HOSTNAME.matcher(s).matches()) {
			return false;
		}
		String host = s;
		int slash = host.indexOf('/');
		if (slash >= 0) {
			host = host.substring(0, slash);
		}
		int colon = host.lastIndexOf(':');
		if (colon >= 0) {
			host = host.substring(0, colon);
		}
		return !host.isEmpty() && Character.isAlphabetic(host.charAt(host.length() - 1));
	}

	static DependencyCategory classifyImport(String symbolName) {
		if (symbolName == null) {
			return null;
		}
		if (AUTH_TLS_IMPORTS.contains(symbolName)) {
			return DependencyCategory.AUTH_TLS;
		}
		if (HTTP_IMPORTS.contains(symbolName)) {
			return DependencyCategory.HTTP;
		}
		if (JDBC_IMPORTS.contains(symbolName)) {
			return DependencyCategory.JDBC;
		}
		if (QUEUE_IMPORTS.contains(symbolName)) {
			return DependencyCategory.QUEUE;
		}
		if (ENDPOINT_IMPORTS.contains(symbolName)) {
			return DependencyCategory.ENDPOINT;
		}
		return null;
	}

	static String redact(String s) {
		if (s == null) {
			return null;
		}
		return s.replaceAll(
			"(?i)((?:^|[?&;,#\\s])[a-z0-9_-]*(?:password|passwd|pwd|secret|api_?key|access_token|token)=)[^&;]+",
			"$1" + REDACTION_MARKER)
			.replaceAll("(?i)((?:authorization\\s*:\\s*)?(?:bearer|basic)\\s+)\\S+",
				"$1" + REDACTION_MARKER)
			.replaceAll("(?i)((?:x-api-key|x-auth-token|api-key)\\s*:\\s*)\\S+",
				"$1" + REDACTION_MARKER)
			.replaceAll("(?i)(://[^/:@\\s]+:)[^@/\\s]+(@)", "$1" + REDACTION_MARKER + "$2");
	}
}
