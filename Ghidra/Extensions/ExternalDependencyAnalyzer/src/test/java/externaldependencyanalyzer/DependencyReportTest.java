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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;

import externaldependencyanalyzer.DependencyModel.*;
import generic.test.AbstractGenericTest;

public class DependencyReportTest extends AbstractGenericTest {

	private static ScanResult sample() {
		ProgramInfo program = new ProgramInfo("svc", "ab".repeat(32), "ELF", "x86:LE:64:default",
			"0x400000");
		List<Endpoint> endpoints = new ArrayList<>(List.of(
			new Endpoint(EndpointKind.HOSTNAME, "tiles.example.test", "00402010", List.of("main"),
				new NetworkCallLink("getaddrinfo", "00401020", "main", false), Confidence.HIGH,
				"", List.of()),
			new Endpoint(EndpointKind.URL, "http://tiles.example.test/wms", "00402000",
				List.of("fetch", "main"), null, Confidence.MEDIUM, "http",
				List.of("OGC web service request")),
			new Endpoint(EndpointKind.CONNECTION_STRING, "postgresql://u:***@db.example.test/db",
				"00402040", List.of(), null, Confidence.LOW, "postgresql",
				List.of("credential redacted"))));
		List<ApiCallSite> sites = new ArrayList<>(List.of(
			new ApiCallSite("getaddrinfo", "resolver", "00401020", "main", "dns", true,
				List.of("imported")),
			new ApiCallSite("connect", "socket", "00401010", "main", "tcp", true,
				List.of("imported"))));
		List<Finding> findings = new ArrayList<>(List.of(
			new Finding(Severity.LOW, Rule.PLAINTEXT_PORT.jsonName(), "00401030", "main", "port 80"),
			new Finding(Severity.HIGH, Rule.HARDCODED_CREDENTIAL.jsonName(), "00402040", "",
				"credential embedded (redacted)"),
			new Finding(Severity.MEDIUM, Rule.PLAINTEXT_PROTOCOL.jsonName(), "00402000", "fetch",
				"http://")));
		return new ScanResult(program, endpoints, sites, findings, List.of("one warning"));
	}

	private static ScanResult shuffled(ScanResult r) {
		List<Endpoint> e = new ArrayList<>(r.endpoints());
		List<ApiCallSite> s = new ArrayList<>(r.apiCallSites());
		List<Finding> f = new ArrayList<>(r.findings());
		Collections.reverse(e);
		Collections.reverse(s);
		Collections.reverse(f);
		return new ScanResult(r.program(), e, s, f, r.warnings());
	}

	@Test
	public void testJsonIsDeterministicRegardlessOfInputOrder() {
		String a = DependencyReportWriter.toJson(sample());
		String b = DependencyReportWriter.toJson(shuffled(sample()));
		assertEquals(a, b);
		assertEquals(DependencyReportWriter.toMarkdown(sample()),
			DependencyReportWriter.toMarkdown(shuffled(sample())));
	}

	@Test
	public void testJsonOrderingRules() {
		ScanResult r = DependencyReportWriter.normalize(shuffled(sample()));
		assertEquals(List.of("00402000", "00402010", "00402040"),
			r.endpoints().stream().map(Endpoint::address).toList());
		assertEquals(List.of("00401010", "00401020"),
			r.apiCallSites().stream().map(ApiCallSite::address).toList());
		assertEquals(List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW),
			r.findings().stream().map(Finding::severity).toList());
	}

	@Test
	public void testRoundTripThroughReader() throws IOException {
		String json = DependencyReportWriter.toJson(sample());
		ScanResult parsed = DependencyReportReader.fromJson(json);
		assertEquals(json, DependencyReportWriter.toJson(parsed));
		assertEquals(sample().program(), parsed.program());
		assertEquals(3, parsed.endpoints().size());
		assertEquals(2, parsed.apiCallSites().size());
		assertEquals(3, parsed.findings().size());
		assertEquals(List.of("one warning"), parsed.warnings());
	}

	@Test
	public void testSummaryCountsMatchBody() {
		JsonObject root = DependencyReportWriter.toJsonTree(sample());
		JsonObject summary = root.getAsJsonObject("summary");
		assertEquals(3, summary.get("endpointCount").getAsInt());
		assertEquals(2, summary.get("apiCallSiteCount").getAsInt());
		assertEquals(3, summary.get("findingCount").getAsInt());
		assertEquals(1, summary.getAsJsonObject("endpointsByKind").get("hostname").getAsInt());
		assertEquals(1, summary.getAsJsonObject("findingsBySeverity").get("high").getAsInt());
		assertEquals(1, summary.getAsJsonObject("apiCallSitesByCategory").get("socket").getAsInt());
		assertEquals(DependencyReportWriter.SCHEMA_VERSION, root.get("schemaVersion").getAsInt());
	}

	@Test
	public void testReaderRejectsSchemaDrift() {
		String json = DependencyReportWriter.toJson(sample());
		String[] broken = {
			json.replace("\"schemaVersion\": 1", "\"schemaVersion\": 99"),
			json.replace("\"endpoints\"", "\"endpoint\""),
			json.replace("\"kind\": \"hostname\"", "\"kind\": \"host\""),
			json.replace("\"severity\": \"high\"", "\"severity\": \"critical\""),
			json.replace("\"confidence\": \"high\"", "\"confidence\": \"certain\""),
			json.replace("\"endpointCount\": 3", "\"endpointCount\": 2"),
			json.replace("\"imageBase\"", "\"base\""),
			json.replace("\"heuristic\": false", "\"heuristic\": false, \"extra\": 1"),
			"[]",
			"not json",
		};
		for (String s : broken) {
			assertNotEquals(json, s);
			try {
				DependencyReportReader.fromJson(s);
				fail("reader accepted drifted report");
			}
			catch (IOException expected) {
				// rejected as intended
			}
		}
	}

	@Test
	public void testRuleIdentifiersAreStableAndUnique() {
		List<String> ids = new ArrayList<>();
		for (Rule r : Rule.values()) {
			assertTrue(r.jsonName(), r.jsonName().matches("[a-z0-9_]+"));
			assertFalse(ids.contains(r.jsonName()));
			ids.add(r.jsonName());
		}
		List<String> kinds = new ArrayList<>();
		for (EndpointKind k : EndpointKind.values()) {
			assertTrue(k.jsonName(), k.jsonName().matches("[a-z0-9_]+"));
			assertFalse(kinds.contains(k.jsonName()));
			kinds.add(k.jsonName());
		}
	}

	@Test
	public void testMarkdownEscapesTableCells() {
		Endpoint e = new Endpoint(EndpointKind.HEADER_CONSTANT, "X-Api-Key: ***|`x`", "00402000",
			List.of(), null, Confidence.LOW, "", List.of("a|b"));
		ScanResult r = new ScanResult(sample().program(), List.of(e), List.of(), List.of(),
			List.of());
		String md = DependencyReportWriter.toMarkdown(r);
		assertTrue(md.contains("\\|"));
		assertFalse(md.contains("***|`x`"));
	}
}
