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

import java.io.IOException;
import java.util.*;

import com.google.gson.*;

import externaldependencyanalyzer.DependencyModel.*;

/**
 * Parses the documented JSON schema back into a {@link ScanResult}. Used to reuse results
 * stored on the program and to validate exported files. Unknown or malformed content raises
 * {@link IOException} with a generic message.
 */
public final class DependencyReportReader {

	private static final List<String> ROOT_KEYS =
		List.of("schemaVersion", "program", "endpoints", "apiCallSites", "findings", "summary");
	private static final List<String> PROGRAM_KEYS =
		List.of("name", "sha256", "format", "arch", "imageBase");
	private static final List<String> ENDPOINT_KEYS = List.of("kind", "value", "address",
		"referencingFunctions", "nearestNetworkCall", "confidence", "protocolHint", "notes");
	private static final List<String> CALL_KEYS = List.of("api", "address", "function", "heuristic");
	private static final List<String> SITE_KEYS =
		List.of("api", "category", "address", "function", "protocolHint", "external", "notes");
	private static final List<String> FINDING_KEYS =
		List.of("severity", "rule", "address", "function", "detail");
	private static final List<String> SUMMARY_KEYS = List.of("endpointCount", "apiCallSiteCount",
		"findingCount", "endpointsByKind", "findingsBySeverity", "apiCallSitesByCategory",
		"warnings");

	private DependencyReportReader() {
	}

	public static ScanResult fromJson(String json) throws IOException {
		JsonObject root;
		try {
			JsonElement el = JsonParser.parseString(json);
			if (!el.isJsonObject()) {
				throw new IOException("report is not a JSON object");
			}
			root = el.getAsJsonObject();
			requireKeys(root, ROOT_KEYS, "root");
			if (root.get("schemaVersion").getAsInt() != DependencyReportWriter.SCHEMA_VERSION) {
				throw new IOException("unsupported schema version");
			}

			JsonObject p = obj(root, "program");
			requireKeys(p, PROGRAM_KEYS, "program");
			ProgramInfo info = new ProgramInfo(str(p, "name"), str(p, "sha256"),
				str(p, "format"), str(p, "arch"), str(p, "imageBase"));

			List<Endpoint> endpoints = new ArrayList<>();
			for (JsonElement e : arr(root, "endpoints")) {
				JsonObject o = asObject(e, "endpoint");
				requireKeys(o, ENDPOINT_KEYS, "endpoint");
				NetworkCallLink link = null;
				JsonElement n = o.get("nearestNetworkCall");
				if (!n.isJsonNull()) {
					JsonObject no = asObject(n, "nearestNetworkCall");
					requireKeys(no, CALL_KEYS, "nearestNetworkCall");
					link = new NetworkCallLink(str(no, "api"), str(no, "address"),
						str(no, "function"), no.get("heuristic").getAsBoolean());
				}
				endpoints.add(new Endpoint(kind(str(o, "kind")), str(o, "value"),
					str(o, "address"), strings(arr(o, "referencingFunctions")), link,
					confidence(str(o, "confidence")), str(o, "protocolHint"),
					strings(arr(o, "notes"))));
			}

			List<ApiCallSite> sites = new ArrayList<>();
			for (JsonElement e : arr(root, "apiCallSites")) {
				JsonObject o = asObject(e, "apiCallSite");
				requireKeys(o, SITE_KEYS, "apiCallSite");
				sites.add(new ApiCallSite(str(o, "api"), str(o, "category"), str(o, "address"),
					str(o, "function"), str(o, "protocolHint"), o.get("external").getAsBoolean(),
					strings(arr(o, "notes"))));
			}

			List<Finding> findings = new ArrayList<>();
			for (JsonElement e : arr(root, "findings")) {
				JsonObject o = asObject(e, "finding");
				requireKeys(o, FINDING_KEYS, "finding");
				findings.add(new Finding(severity(str(o, "severity")), rule(str(o, "rule")),
					str(o, "address"), str(o, "function"), str(o, "detail")));
			}

			JsonObject s = obj(root, "summary");
			requireKeys(s, SUMMARY_KEYS, "summary");
			if (!isCount(s.get("endpointCount"), endpoints.size()) ||
				!isCount(s.get("apiCallSiteCount"), sites.size()) ||
				!isCount(s.get("findingCount"), findings.size())) {
				throw new IOException("summary counts do not match content");
			}
			List<String> warnings = strings(arr(s, "warnings"));
			ScanResult result = new ScanResult(info, Collections.unmodifiableList(endpoints),
				Collections.unmodifiableList(sites), Collections.unmodifiableList(findings),
				Collections.unmodifiableList(warnings));
			requireCounts(obj(s, "endpointsByKind"), result.countsByKind(), "endpointsByKind");
			requireCounts(obj(s, "findingsBySeverity"), result.countsBySeverity(),
				"findingsBySeverity");
			requireCounts(obj(s, "apiCallSitesByCategory"), result.countsByApiCategory(),
				"apiCallSitesByCategory");
			return result;
		}
		catch (JsonParseException | IllegalStateException | UnsupportedOperationException |
				NumberFormatException e) {
			throw new IOException("report is malformed");
		}
	}

	private static void requireKeys(JsonObject o, List<String> keys, String where)
			throws IOException {
		for (String k : keys) {
			if (!o.has(k)) {
				throw new IOException("missing key \"" + k + "\" in " + where);
			}
		}
		for (String k : o.keySet()) {
			if (!keys.contains(k)) {
				throw new IOException("unexpected key \"" + k + "\" in " + where);
			}
		}
	}

	private static JsonObject obj(JsonObject o, String key) throws IOException {
		return asObject(o.get(key), key);
	}

	private static JsonObject asObject(JsonElement e, String where) throws IOException {
		if (e == null || !e.isJsonObject()) {
			throw new IOException(where + " is not an object");
		}
		return e.getAsJsonObject();
	}

	private static JsonArray arr(JsonObject o, String key) throws IOException {
		JsonElement e = o.get(key);
		if (e == null || !e.isJsonArray()) {
			throw new IOException(key + " is not an array");
		}
		return e.getAsJsonArray();
	}

	private static String str(JsonObject o, String key) throws IOException {
		JsonElement e = o.get(key);
		if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
			throw new IOException(key + " is not a string");
		}
		return e.getAsString();
	}

	private static List<String> strings(JsonArray a) throws IOException {
		List<String> out = new ArrayList<>();
		for (JsonElement e : a) {
			if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
				throw new IOException("array element is not a string");
			}
			out.add(e.getAsString());
		}
		return Collections.unmodifiableList(out);
	}

	private static EndpointKind kind(String s) throws IOException {
		for (EndpointKind k : EndpointKind.values()) {
			if (k.jsonName().equals(s)) {
				return k;
			}
		}
		throw new IOException("unknown endpoint kind");
	}

	private static Confidence confidence(String s) throws IOException {
		for (Confidence c : Confidence.values()) {
			if (c.jsonName().equals(s)) {
				return c;
			}
		}
		throw new IOException("unknown confidence");
	}

	private static String rule(String s) throws IOException {
		for (Rule r : Rule.values()) {
			if (r.jsonName().equals(s)) {
				return s;
			}
		}
		throw new IOException("unknown finding rule");
	}

	private static void requireCounts(JsonObject actual, Map<String, Integer> expected,
			String where) throws IOException {
		if (!actual.keySet().equals(expected.keySet())) {
			throw new IOException(where + " keys do not match content");
		}
		for (Map.Entry<String, Integer> e : expected.entrySet()) {
			if (!isCount(actual.get(e.getKey()), e.getValue())) {
				throw new IOException(where + " counts do not match content");
			}
		}
	}

	private static boolean isCount(JsonElement v, int expected) {
		return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber() &&
			v.getAsString().equals(Integer.toString(expected));
	}

	private static Severity severity(String s) throws IOException {
		for (Severity v : Severity.values()) {
			if (v.jsonName().equals(s)) {
				return v;
			}
		}
		throw new IOException("unknown severity");
	}
}
