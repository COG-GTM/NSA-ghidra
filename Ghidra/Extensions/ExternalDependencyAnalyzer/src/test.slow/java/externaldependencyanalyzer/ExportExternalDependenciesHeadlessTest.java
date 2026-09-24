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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import externaldependencyanalyzer.DependencyModel.*;
import generic.jar.ResourceFile;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessOptions;
import ghidra.framework.Application;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;

/**
 * End-to-end test: compiles the committed C fixture with the system compiler, imports and
 * analyzes it with the headless analyzer, runs {@code ExportExternalDependencies.java}, and
 * checks the exported JSON and Markdown. Nothing produced by the compiler is ever executed.
 */
public class ExportExternalDependenciesHeadlessTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String SCRIPT = "ExportExternalDependencies.java";
	private static final String BUILDER = "ExportExternalDependencies_build_fixture.py";

	private static File scriptsDir;
	private static File fixture;

	@Before
	public void buildFixture() throws Exception {
		if (fixture != null) {
			return;
		}
		ResourceFile script = Application.getModuleFile("ExternalDependencyAnalyzer",
			"ghidra_scripts/" + SCRIPT);
		scriptsDir = script.getParentFile().getFile(false);
		File builder = new File(scriptsDir, BUILDER);
		assertTrue(builder.getPath(), builder.isFile());

		Path out = Files.createTempDirectory("edfixture");
		ProcessBuilder pb = new ProcessBuilder("python3", builder.getPath(), out.toString(),
			"--list");
		pb.redirectErrorStream(true);
		Process p = pb.start();
		String log = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
		assertTrue("fixture build timed out", p.waitFor(120, TimeUnit.SECONDS));
		Msg.info(ExportExternalDependenciesHeadlessTest.class, "fixture build:\n" + log);
		assertEquals("fixture build failed:\n" + log, 0, p.exitValue());

		File built = null;
		for (String line : log.split("\\R")) {
			if (line.startsWith("elf-x86_64 ") && !line.contains("SKIPPED")) {
				built = new File(line.substring("elf-x86_64 ".length()).trim());
			}
		}
		assertNotNull("builder did not report an ELF fixture:\n" + log, built);
		assertTrue(built.isFile());
		fixture = built;
	}

	private static Path runHeadless(String... scriptArgs) throws IOException {
		return runHeadless(fixture, scriptArgs);
	}

	private static Path runHeadless(File binary, String... scriptArgs) throws IOException {
		Path project = Files.createTempDirectory("edproj");
		Path output = Files.createTempDirectory("edout");
		String[] args = new String[scriptArgs.length + 1];
		args[0] = output.toString();
		System.arraycopy(scriptArgs, 0, args, 1, scriptArgs.length);

		HeadlessAnalyzer headless = HeadlessAnalyzer.getInstance();
		headless.reset();
		HeadlessOptions options = headless.getOptions();
		options.setScriptDirectories(List.of(scriptsDir.getAbsolutePath()));
		options.setPostScriptsWithArgs(List.of(new generic.stl.Pair<>(SCRIPT, args)));
		options.setDeleteCreatedProjectOnClose(true);
		options.enableAnalysis(true);
		headless.processLocal(project.toString(), "fixture", "/", List.of(binary));
		return output;
	}

	@Test
	public void testOutputFileNamesAreAsciiOnly() throws Exception {
		Path dir = Files.createTempDirectory("edname");
		File odd = dir.resolve("fixt\u00fcre \u03b5\u03bb$name.bin").toFile();
		Files.copy(fixture.toPath(), odd.toPath());
		Path out = runHeadless(odd);
		List<String> names = new ArrayList<>();
		try (var stream = Files.list(out)) {
			stream.map(p -> p.getFileName().toString()).sorted().forEach(names::add);
		}
		assertEquals(List.of("fixt_re____name.bin-dependencies.json",
			"fixt_re____name.bin-dependencies.md"), names);
		String json = Files.readString(out.resolve(names.get(0)), StandardCharsets.UTF_8);
		assertEquals(odd.getName(), DependencyReportReader.fromJson(json).program().name());
	}

	private static String read(Path dir, String suffix) throws IOException {
		Path f = dir.resolve(fixture.getName() + suffix);
		assertTrue("missing " + f, Files.isRegularFile(f));
		return Files.readString(f, StandardCharsets.UTF_8);
	}

	@Test
	public void testPlantedItemsAreRecoveredWithCorrectKinds() throws Exception {
		Path out = runHeadless();
		String json = read(out, "-dependencies.json");
		String md = read(out, "-dependencies.md");
		ScanResult r = DependencyReportReader.fromJson(json);

		assertEquals(fixture.getName(), r.program().name());
		assertEquals(64, r.program().sha256().length());
		assertTrue(r.program().format(), r.program().format().contains("ELF"));
		assertTrue(r.program().arch(), r.program().arch().startsWith("x86:LE:64"));

		Endpoint host1 = endpoint(r, EndpointKind.HOSTNAME, "tiles.example-geo.internal");
		Endpoint host2 = endpoint(r, EndpointKind.HOSTNAME, "tiles-standby.example-geo.internal");
		Endpoint ip = endpoint(r, EndpointKind.IPV4, "10.20.30.40");
		Endpoint db = endpoint(r, EndpointKind.CONNECTION_STRING,
			"postgresql://svc_user:" + Redactor.MASK + "@db.example-geo.internal:5432/tiles");
		Endpoint port = endpoint(r, EndpointKind.PORT, "8080");
		Endpoint url = endpoint(r, EndpointKind.URL,
			"http://tiles.example-geo.internal/wms?SERVICE=WMS&REQUEST=GetCapabilities");
		Endpoint header = endpoint(r, EndpointKind.HEADER_CONSTANT, "Authorization: " + Redactor.MASK);

		for (String secret : new String[] { "Tr0ub4dor", "Bearer" }) {
			assertFalse("secret leaked into JSON", json.contains(secret));
			assertFalse("secret leaked into Markdown", md.contains(secret));
		}
		assertEquals("postgresql", db.protocolHint());
		assertTrue(db.notes().contains("credential redacted"));

		assertEquals(List.of("resolve_tile_hosts"), host1.referencingFunctions());
		assertEquals(List.of("resolve_tile_hosts"), host2.referencingFunctions());
		assertEquals("getaddrinfo", host1.nearestNetworkCall().api());
		assertEquals("resolve_tile_hosts", host1.nearestNetworkCall().function());
		assertFalse(host1.nearestNetworkCall().heuristic());

		assertEquals(List.of("open_database"), db.referencingFunctions());
		assertEquals("PQconnectdb", db.nearestNetworkCall().api());

		assertEquals(List.of("fetch_capabilities"), url.referencingFunctions());
		assertEquals("curl_easy_setopt", url.nearestNetworkCall().api());
		assertEquals("fetch_capabilities", header.nearestNetworkCall().function());

		assertEquals(List.of("open_broker_socket"), port.referencingFunctions());
		assertEquals("htons", port.nearestNetworkCall().api());
		assertEquals(List.of("open_broker_socket"), ip.referencingFunctions());

		ApiCallSite curlUrl = r.apiCallSites().stream()
				.filter(c -> c.api().equals("curl_easy_setopt") &&
					c.notes().contains("option CURLOPT_URL"))
				.findFirst().orElseThrow();
		assertEquals("fetch_capabilities", curlUrl.function());
		assertTrue(r.apiCallSites().stream().anyMatch(c -> c.api().equals("connect")));
		assertTrue(r.apiCallSites().stream().anyMatch(c -> c.api().equals("SSL_CTX_set_verify") &&
			c.notes().stream().anyMatch(n -> n.contains("SSL_VERIFY_NONE"))));

		assertTrue(hasFinding(r, Rule.HARDCODED_CREDENTIAL, "open_database"));
		assertTrue(hasFinding(r, Rule.TLS_VERIFICATION_DISABLED, "disable_tls_checks"));
		assertTrue(hasFinding(r, Rule.TLS_VERIFICATION_DISABLED, "fetch_capabilities"));
		assertTrue(hasFinding(r, Rule.PLAINTEXT_PROTOCOL, "fetch_capabilities"));
		assertTrue(hasFinding(r, Rule.PLAINTEXT_PORT, "open_broker_socket"));
		assertTrue(hasFinding(r, Rule.PRIVATE_ADDRESS_EMBEDDED, "open_broker_socket"));
		assertTrue(hasFinding(r, Rule.DUPLICATE_HOST_CONSTANTS, "resolve_tile_hosts"));

		assertTrue(md.startsWith("# External dependencies: " + fixture.getName()));
		assertTrue(md.contains("tiles-standby.example-geo.internal"));
	}

	@Test
	public void testExportIsDeterministicAcrossRunsAndReuse() throws Exception {
		Path first = runHeadless();
		Path second = runHeadless("--reuse");
		assertEquals(read(first, "-dependencies.json"), read(second, "-dependencies.json"));
		assertEquals(read(first, "-dependencies.md"), read(second, "-dependencies.md"));
	}

	private static Endpoint endpoint(ScanResult r, EndpointKind kind, String value) {
		return r.endpoints().stream().filter(e -> e.kind() == kind && e.value().equals(value))
				.findFirst()
				.orElseThrow(() -> new AssertionError(
					"missing " + kind + " " + value + " in " + r.endpoints()));
	}

	private static boolean hasFinding(ScanResult r, Rule rule, String function) {
		return r.findings().stream()
				.anyMatch(f -> f.rule().equals(rule.jsonName()) && f.function().equals(function));
	}
}
