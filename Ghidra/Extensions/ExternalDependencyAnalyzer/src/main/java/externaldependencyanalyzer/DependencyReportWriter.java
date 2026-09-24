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

import java.util.*;

import com.google.gson.*;

import externaldependencyanalyzer.DependencyModel.*;

/**
 * Serialises a {@link ScanResult} to the documented JSON schema and to Markdown. Key order and
 * list order are fixed so that two runs over the same program produce identical text.
 */
public final class DependencyReportWriter {

	public static final int SCHEMA_VERSION = 1;

	private static final Gson GSON =
		new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();

	private DependencyReportWriter() {
	}

	public static String toJson(ScanResult r) {
		return GSON.toJson(toJsonTree(r)) + "\n";
	}

	/** Returns a copy with every list in its canonical order. */
	public static ScanResult normalize(ScanResult r) {
		List<Endpoint> endpoints = new ArrayList<>(r.endpoints());
		List<ApiCallSite> sites = new ArrayList<>(r.apiCallSites());
		List<Finding> findings = new ArrayList<>(r.findings());
		endpoints.sort(Endpoint.ORDER);
		sites.sort(ApiCallSite.ORDER);
		findings.sort(Finding.ORDER);
		List<String> warnings = new ArrayList<>(r.warnings());
		Collections.sort(warnings);
		return new ScanResult(r.program(), List.copyOf(endpoints), List.copyOf(sites),
			List.copyOf(findings), List.copyOf(warnings));
	}

	public static JsonObject toJsonTree(ScanResult unsorted) {
		ScanResult r = normalize(unsorted);
		JsonObject root = new JsonObject();
		root.addProperty("schemaVersion", SCHEMA_VERSION);

		JsonObject program = new JsonObject();
		program.addProperty("name", r.program().name());
		program.addProperty("sha256", r.program().sha256());
		program.addProperty("format", r.program().format());
		program.addProperty("arch", r.program().arch());
		program.addProperty("imageBase", r.program().imageBase());
		root.add("program", program);

		JsonArray endpoints = new JsonArray();
		for (Endpoint e : r.endpoints()) {
			JsonObject o = new JsonObject();
			o.addProperty("kind", e.kind().jsonName());
			o.addProperty("value", e.value());
			o.addProperty("address", e.address());
			o.add("referencingFunctions", strings(e.referencingFunctions()));
			if (e.nearestNetworkCall() == null) {
				o.add("nearestNetworkCall", JsonNull.INSTANCE);
			}
			else {
				JsonObject n = new JsonObject();
				n.addProperty("api", e.nearestNetworkCall().api());
				n.addProperty("address", e.nearestNetworkCall().address());
				n.addProperty("function", e.nearestNetworkCall().function());
				n.addProperty("heuristic", e.nearestNetworkCall().heuristic());
				o.add("nearestNetworkCall", n);
			}
			o.addProperty("confidence", e.confidence().jsonName());
			o.addProperty("protocolHint", e.protocolHint());
			o.add("notes", strings(e.notes()));
			endpoints.add(o);
		}
		root.add("endpoints", endpoints);

		JsonArray sites = new JsonArray();
		for (ApiCallSite c : r.apiCallSites()) {
			JsonObject o = new JsonObject();
			o.addProperty("api", c.api());
			o.addProperty("category", c.category());
			o.addProperty("address", c.address());
			o.addProperty("function", c.function());
			o.addProperty("protocolHint", c.protocolHint());
			o.addProperty("external", c.external());
			o.add("notes", strings(c.notes()));
			sites.add(o);
		}
		root.add("apiCallSites", sites);

		JsonArray findings = new JsonArray();
		for (Finding f : r.findings()) {
			JsonObject o = new JsonObject();
			o.addProperty("severity", f.severity().jsonName());
			o.addProperty("rule", f.rule());
			o.addProperty("address", f.address());
			o.addProperty("function", f.function());
			o.addProperty("detail", f.detail());
			findings.add(o);
		}
		root.add("findings", findings);

		JsonObject summary = new JsonObject();
		summary.addProperty("endpointCount", r.endpoints().size());
		summary.addProperty("apiCallSiteCount", r.apiCallSites().size());
		summary.addProperty("findingCount", r.findings().size());
		summary.add("endpointsByKind", counts(r.countsByKind()));
		summary.add("findingsBySeverity", counts(r.countsBySeverity()));
		summary.add("apiCallSitesByCategory", counts(r.countsByApiCategory()));
		summary.add("warnings", strings(r.warnings()));
		root.add("summary", summary);
		return root;
	}

	private static JsonArray strings(List<String> values) {
		JsonArray a = new JsonArray();
		for (String s : values) {
			a.add(s);
		}
		return a;
	}

	private static JsonObject counts(Map<String, Integer> m) {
		JsonObject o = new JsonObject();
		for (Map.Entry<String, Integer> e : new TreeMap<>(m).entrySet()) {
			o.addProperty(e.getKey(), e.getValue());
		}
		return o;
	}

	public static String toMarkdown(ScanResult unsorted) {
		ScanResult r = normalize(unsorted);
		StringBuilder sb = new StringBuilder();
		sb.append("# External dependencies: ").append(md(r.program().name())).append("\n\n");
		sb.append("| Field | Value |\n|---|---|\n");
		sb.append("| SHA-256 | `").append(md(r.program().sha256())).append("` |\n");
		sb.append("| Format | ").append(md(r.program().format())).append(" |\n");
		sb.append("| Architecture | ").append(md(r.program().arch())).append(" |\n");
		sb.append("| Image base | ").append(md(r.program().imageBase())).append(" |\n\n");

		sb.append("## Summary\n\n");
		sb.append("| Metric | Count |\n|---|---|\n");
		sb.append("| Endpoints | ").append(r.endpoints().size()).append(" |\n");
		sb.append("| API call sites | ").append(r.apiCallSites().size()).append(" |\n");
		sb.append("| Findings | ").append(r.findings().size()).append(" |\n\n");
		appendCounts(sb, "Endpoints by kind", r.countsByKind());
		appendCounts(sb, "Findings by severity", r.countsBySeverity());
		appendCounts(sb, "API call sites by category", r.countsByApiCategory());
		if (!r.warnings().isEmpty()) {
			sb.append("### Warnings\n\n");
			for (String w : r.warnings()) {
				sb.append("- ").append(md(w)).append('\n');
			}
			sb.append('\n');
		}

		sb.append("## Findings\n\n");
		if (r.findings().isEmpty()) {
			sb.append("None.\n\n");
		}
		else {
			sb.append("| Severity | Rule | Address | Function | Detail |\n|---|---|---|---|---|\n");
			for (Finding f : r.findings()) {
				sb.append("| ").append(f.severity().jsonName()).append(" | `").append(f.rule())
						.append("` | `").append(f.address()).append("` | ").append(md(f.function()))
						.append(" | ").append(md(f.detail())).append(" |\n");
			}
			sb.append('\n');
		}

		sb.append("## Endpoints\n\n");
		if (r.endpoints().isEmpty()) {
			sb.append("None.\n\n");
		}
		else {
			sb.append(
				"| Kind | Value | Address | Referencing functions | Nearest network call | Confidence | Protocol | Notes |\n");
			sb.append("|---|---|---|---|---|---|---|---|\n");
			for (Endpoint e : r.endpoints()) {
				String call = e.nearestNetworkCall() == null ? "-"
						: "`" + e.nearestNetworkCall().api() + "` @ `" +
							e.nearestNetworkCall().address() + "`" +
							(e.nearestNetworkCall().heuristic() ? " (heuristic)" : "");
				sb.append("| ").append(e.kind().jsonName()).append(" | `").append(md(e.value()))
						.append("` | `").append(e.address()).append("` | ")
						.append(md(String.join(", ", e.referencingFunctions()))).append(" | ")
						.append(call).append(" | ").append(e.confidence().jsonName()).append(" | ")
						.append(md(e.protocolHint())).append(" | ")
						.append(md(String.join("; ", e.notes()))).append(" |\n");
			}
			sb.append('\n');
		}

		sb.append("## API call sites\n\n");
		if (r.apiCallSites().isEmpty()) {
			sb.append("None.\n\n");
		}
		else {
			sb.append("| API | Category | Address | Function | Protocol | Linkage | Notes |\n");
			sb.append("|---|---|---|---|---|---|---|\n");
			for (ApiCallSite c : r.apiCallSites()) {
				sb.append("| `").append(md(c.api())).append("` | ").append(c.category())
						.append(" | `").append(c.address()).append("` | ").append(md(c.function()))
						.append(" | ").append(md(c.protocolHint())).append(" | ")
						.append(c.external() ? "imported" : "internal").append(" | ")
						.append(md(String.join("; ", c.notes()))).append(" |\n");
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	private static void appendCounts(StringBuilder sb, String title, Map<String, Integer> m) {
		if (m.isEmpty()) {
			return;
		}
		sb.append("### ").append(title).append("\n\n| Key | Count |\n|---|---|\n");
		for (Map.Entry<String, Integer> e : new TreeMap<>(m).entrySet()) {
			sb.append("| ").append(md(e.getKey())).append(" | ").append(e.getValue()).append(" |\n");
		}
		sb.append('\n');
	}

	private static String md(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("|", "\\|").replace("\n", " ").replace("\r", "");
	}
}
