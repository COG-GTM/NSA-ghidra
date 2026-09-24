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
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;

import externaldependencyanalyzer.DependencyModel.*;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import generic.test.AbstractGenericTest;

/**
 * Keeps the README's documented taxonomies equal to the ones defined in code, in both
 * directions, so that neither can gain or lose a value without the other.
 */
public class ReadmeSyncTest extends AbstractGenericTest {

	private static final String MODULE = "ExternalDependencyAnalyzer";
	private static String readme;
	private static String schema;

	@Before
	public void loadReadme() throws IOException {
		if (readme != null) {
			return;
		}
		ResourceFile f = Application.getModuleFile(MODULE, "README.md");
		readme = new String(f.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		int start = readme.indexOf("## JSON schema");
		int end = readme.indexOf("\n## ", start + 1);
		assertTrue(start > 0 && end > start);
		schema = readme.substring(start, end);
	}

	private static Set<String> quotedAlternatives(String field) {
		Pattern p = Pattern.compile("\"" + field + "\":\\s*((?:\"[a-z0-9_]+\"\\s*\\|?\\s*)+)");
		Matcher m = p.matcher(schema);
		assertTrue("schema lists values for " + field, m.find());
		Set<String> out = new TreeSet<>();
		Matcher v = Pattern.compile("\"([a-z0-9_]+)\"").matcher(m.group(1));
		while (v.find()) {
			out.add(v.group(1));
		}
		return out;
	}

	private static Set<String> codeTicks(String section, String from, String to) {
		int s = readme.indexOf(from);
		int e = readme.indexOf(to, s + 1);
		assertTrue(section, s >= 0 && e > s);
		Set<String> out = new TreeSet<>();
		Matcher m = Pattern.compile("`([a-z0-9_]+)`").matcher(readme.substring(s, e));
		while (m.find()) {
			out.add(m.group(1));
		}
		return out;
	}

	@Test
	public void testEndpointKindsMatchSchema() {
		Set<String> code = new TreeSet<>();
		for (EndpointKind k : EndpointKind.values()) {
			code.add(k.jsonName());
		}
		assertEquals(code, quotedAlternatives("kind"));
		assertEquals(13, code.size());
	}

	@Test
	public void testEndpointKindsAreAllDescribedInRecoverySection() {
		Set<String> code = new TreeSet<>();
		for (EndpointKind k : EndpointKind.values()) {
			code.add(k.jsonName());
		}
		Set<String> documented =
			codeTicks("recovers", "## What it recovers", "API call sites:");
		documented.retainAll(code);
		assertEquals(code, documented);
	}

	@Test
	public void testRulesMatchSchemaAndFindingsSection() {
		Set<String> code = new TreeSet<>();
		for (Rule r : Rule.values()) {
			code.add(r.jsonName());
		}
		assertEquals(code, quotedAlternatives("rule"));
		Set<String> documented = codeTicks("findings", "Findings (rule identifiers", "Inside Ghidra");
		documented.retainAll(code);
		assertEquals(code, documented);
		assertEquals(9, code.size());
	}

	@Test
	public void testSeverityAndConfidenceMatchSchema() {
		Set<String> sev = new TreeSet<>();
		for (Severity s : Severity.values()) {
			sev.add(s.jsonName());
		}
		assertEquals(sev, quotedAlternatives("severity"));
		Set<String> conf = new TreeSet<>();
		for (Confidence c : Confidence.values()) {
			conf.add(c.jsonName());
		}
		assertEquals(conf, quotedAlternatives("confidence"));
	}

	@Test
	public void testAnalyzerOptionsAreDocumented() {
		List<String> options = List.of(ExternalDependencyAnalyzer.OPT_ENDPOINTS,
			ExternalDependencyAnalyzer.OPT_CONNECTION_STRINGS,
			ExternalDependencyAnalyzer.OPT_PROTOCOL_HINTS,
			ExternalDependencyAnalyzer.OPT_API_CALL_SITES, ExternalDependencyAnalyzer.OPT_FINDINGS,
			ExternalDependencyAnalyzer.OPT_PORT_HEURISTICS,
			ExternalDependencyAnalyzer.OPT_MIN_STRING_LENGTH,
			ExternalDependencyAnalyzer.OPT_API_TABLE_PATH,
			ExternalDependencyAnalyzer.OPT_WRITE_COMMENTS,
			ExternalDependencyAnalyzer.OPT_WRITE_BOOKMARKS);
		Set<String> documented = new TreeSet<>();
		Matcher m = Pattern.compile("(?m)^\\| ([A-Z][^|]*?) \\| (on|\\d+|empty) \\|").matcher(readme);
		while (m.find()) {
			documented.add(m.group(1));
		}
		assertEquals(new TreeSet<>(options), documented);
		assertTrue(readme.contains("| Minimum string length | " +
			ScanOptions.DEFAULT_MIN_STRING_LENGTH + " |"));
	}

	@Test
	public void testSchemaVersionMatches() {
		assertTrue(schema.contains("\"schemaVersion\": " + DependencyReportWriter.SCHEMA_VERSION));
	}
}
