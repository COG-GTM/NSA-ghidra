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

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Immutable result types produced by {@link DependencyScanner}. Every value is already
 * redacted; nothing in this model may hold a secret.
 */
public final class DependencyModel {

	private DependencyModel() {
	}

	/** Kinds of recovered endpoint constants. Names are stable and appear in the JSON output. */
	public enum EndpointKind {
		URL("url"),
		CONNECTION_STRING("connection_string"),
		HOSTNAME("hostname"),
		HOST_PORT("host_port"),
		IPV4("ipv4"),
		IPV6("ipv6"),
		PORT("port"),
		UNC_PATH("unc_path"),
		HTTP_PATH("http_path"),
		HEADER_CONSTANT("header_constant"),
		SERVICE_HINT("service_hint"),
		LDAP_DN("ldap_dn"),
		KERBEROS_REALM("kerberos_realm");

		private final String jsonName;

		EndpointKind(String jsonName) {
			this.jsonName = jsonName;
		}

		public String jsonName() {
			return jsonName;
		}

		/** Option category that controls this kind; several kinds share a category. */
		public String category() {
			switch (this) {
				case URL:
				case CONNECTION_STRING:
					return "connection strings";
				case HOSTNAME:
				case HOST_PORT:
				case IPV4:
				case IPV6:
				case PORT:
				case UNC_PATH:
					return "endpoints";
				default:
					return "protocol hints";
			}
		}
	}

	/** Finding rule identifiers. Names are stable and appear in the JSON output. */
	public enum Rule {
		HARDCODED_CREDENTIAL("hardcoded_credential"),
		TLS_VERIFICATION_DISABLED("tls_verification_disabled"),
		PLAINTEXT_PROTOCOL("plaintext_protocol"),
		PLAINTEXT_PORT("plaintext_port"),
		PRIVATE_ADDRESS_EMBEDDED("private_address_embedded"),
		PUBLIC_ADDRESS_EMBEDDED("public_address_embedded"),
		DUPLICATE_HOST_CONSTANTS("duplicate_host_constants"),
		RUNTIME_COMPOSED_ENDPOINT("runtime_composed_endpoint"),
		RUNTIME_SUPPLIED_ENDPOINT("runtime_supplied_endpoint");

		private final String jsonName;

		Rule(String jsonName) {
			this.jsonName = jsonName;
		}

		public String jsonName() {
			return jsonName;
		}
	}

	public enum Severity {
		INFO("info", 0), LOW("low", 1), MEDIUM("medium", 2), HIGH("high", 3);

		private final String jsonName;
		private final int rank;

		Severity(String jsonName, int rank) {
			this.jsonName = jsonName;
			this.rank = rank;
		}

		public String jsonName() {
			return jsonName;
		}

		public int rank() {
			return rank;
		}
	}

	public enum Confidence {
		HIGH("high"), MEDIUM("medium"), LOW("low");

		private final String jsonName;

		Confidence(String jsonName) {
			this.jsonName = jsonName;
		}

		public String jsonName() {
			return jsonName;
		}
	}

	/** Reference to a network or authentication API call site. */
	public record ApiCallSite(String api, String category, String address, String function,
			String protocolHint, boolean external, List<String> notes) {

		public static final Comparator<ApiCallSite> ORDER =
			Comparator.comparing(ApiCallSite::address).thenComparing(ApiCallSite::api);
	}

	/** Link from an endpoint to the nearest network/auth call site. */
	public record NetworkCallLink(String api, String address, String function,
			boolean heuristic) {
	}

	/** One recovered endpoint constant. {@code value} is always redacted. */
	public record Endpoint(EndpointKind kind, String value, String address,
			List<String> referencingFunctions, NetworkCallLink nearestNetworkCall,
			Confidence confidence, String protocolHint, List<String> notes) {

		public static final Comparator<Endpoint> ORDER =
			Comparator.comparing(Endpoint::address).thenComparing(e -> e.kind().jsonName())
					.thenComparing(Endpoint::value);
	}

	/** A security or sustainment-relevant observation. */
	public record Finding(Severity severity, String rule, String address, String function,
			String detail) {

		public static final Comparator<Finding> ORDER =
			Comparator.<Finding>comparingInt(f -> -f.severity().rank())
					.thenComparing(Finding::rule).thenComparing(Finding::address)
					.thenComparing(Finding::detail);
	}

	/** Program metadata included in every export. */
	public record ProgramInfo(String name, String sha256, String format, String arch,
			String imageBase) {
	}

	/** Complete, sorted scan result. */
	public record ScanResult(ProgramInfo program, List<Endpoint> endpoints,
			List<ApiCallSite> apiCallSites, List<Finding> findings, List<String> warnings) {

		public Map<String, Integer> countsByKind() {
			Map<String, Integer> counts = new TreeMap<>();
			for (Endpoint e : endpoints) {
				counts.merge(e.kind().jsonName(), 1, Integer::sum);
			}
			return counts;
		}

		public Map<String, Integer> countsBySeverity() {
			Map<String, Integer> counts = new TreeMap<>();
			for (Finding f : findings) {
				counts.merge(f.severity().jsonName(), 1, Integer::sum);
			}
			return counts;
		}

		public Map<String, Integer> countsByApiCategory() {
			Map<String, Integer> counts = new TreeMap<>();
			for (ApiCallSite c : apiCallSites) {
				counts.merge(c.category(), 1, Integer::sum);
			}
			return counts;
		}
	}
}
