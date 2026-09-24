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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class ExternalDependencyExporterTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String JSON_GOLDEN = """
		{
		  "schema": "external-dependency-report/1",
		  "program": "ExternalDependencyFixture",
		  "findings": [
		    {
		      "from_address": "00001004",
		      "category": "jdbc",
		      "severity": "HIGH",
		      "kind": "string",
		      "value": "jdbc:postgresql://db.internal.example.com:5432/appdb?user=svc&password=***REDACTED***",
		      "library": null,
		      "indicator_address": "00002300",
		      "function": "connect_db",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001008",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "string",
		      "value": "db.internal.example.com",
		      "library": null,
		      "indicator_address": "00002000",
		      "function": "connect_db",
		      "via_thunk": false
		    },
		    {
		      "from_address": "0000100c",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "string",
		      "value": ":5432",
		      "library": null,
		      "indicator_address": "00002180",
		      "function": "connect_db",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001010",
		      "category": "jdbc",
		      "severity": "HIGH",
		      "kind": "import",
		      "value": "PQconnectdb",
		      "library": "libpq.so.5",
		      "indicator_address": "EXTERNAL:00000003",
		      "function": "connect_db",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001044",
		      "category": "http",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": "https://api.example.com/v1/orders",
		      "library": null,
		      "indicator_address": "00002100",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001048",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "string",
		      "value": "Authorization: Bearer ***REDACTED***",
		      "library": null,
		      "indicator_address": "00002380",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "0000104c",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "string",
		      "value": "X-Api-Key: ***REDACTED***",
		      "library": null,
		      "indicator_address": "00002400",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001050",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "string",
		      "value": ":8443",
		      "library": null,
		      "indicator_address": "00002200",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001054",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "string",
		      "value": "192.0.2.10:8443",
		      "library": null,
		      "indicator_address": "00002480",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001058",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "import",
		      "value": "getaddrinfo",
		      "library": "libc.so.6",
		      "indicator_address": "EXTERNAL:00000004",
		      "function": "call_api",
		      "via_thunk": false
		    },
		    {
		      "from_address": "0000105c",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "import",
		      "value": "SSL_connect",
		      "library": "libssl.so.3",
		      "indicator_address": "EXTERNAL:00000001",
		      "function": "call_api",
		      "via_thunk": true
		    },
		    {
		      "from_address": "00001084",
		      "category": "queue",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": "mq.example.com",
		      "library": null,
		      "indicator_address": "00002080",
		      "function": "send_queue",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001088",
		      "category": "queue",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": ":5672",
		      "library": null,
		      "indicator_address": "00002280",
		      "function": "send_queue",
		      "via_thunk": false
		    },
		    {
		      "from_address": "0000108c",
		      "category": "queue",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": "amqps://mq.example.com:5672/vhost",
		      "library": null,
		      "indicator_address": "00002500",
		      "function": "send_queue",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001090",
		      "category": "http",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": "https://api.example.com/v1/orders",
		      "library": null,
		      "indicator_address": "00002100",
		      "function": "send_queue",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001094",
		      "category": "http",
		      "severity": "MEDIUM",
		      "kind": "string",
		      "value": "https://api.example.com/v1/orders",
		      "library": null,
		      "indicator_address": "00002100",
		      "function": "send_queue",
		      "via_thunk": false
		    },
		    {
		      "from_address": "000010c4",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "import",
		      "value": "SSL_connect",
		      "library": "libssl.so.3",
		      "indicator_address": "EXTERNAL:00000001",
		      "function": "tls_helper",
		      "via_thunk": false
		    },
		    {
		      "from_address": "000010c8",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "import",
		      "value": "SSL_connect",
		      "library": "libssl.so.3",
		      "indicator_address": "EXTERNAL:00000001",
		      "function": "tls_helper",
		      "via_thunk": false
		    },
		    {
		      "from_address": "00001104",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "string",
		      "value": "Authorization: Bearer ***REDACTED***",
		      "library": null,
		      "indicator_address": "00002380",
		      "function": "tls_helper",
		      "via_thunk": true
		    },
		    {
		      "from_address": "00001108",
		      "category": "auth_tls",
		      "severity": "HIGH",
		      "kind": "import",
		      "value": "SSL_CTX_new",
		      "library": "libssl.so.3",
		      "indicator_address": "EXTERNAL:00000002",
		      "function": "tls_helper",
		      "via_thunk": true
		    },
		    {
		      "from_address": "00002580",
		      "category": "endpoint",
		      "severity": "LOW",
		      "kind": "string",
		      "value": "unused.example.com",
		      "library": null,
		      "indicator_address": "00002580",
		      "function": null,
		      "via_thunk": false
		    }
		  ]
		}
		""";

	private static final String MARKDOWN_GOLDEN = """
		# External Dependency Report

		Program: ExternalDependencyFixture

		| From | Category | Severity | Kind | Value | Library | Indicator | Function | Via thunk |
		| --- | --- | --- | --- | --- | --- | --- | --- | --- |
		| 00001004 | jdbc | HIGH | string | jdbc:postgresql://db.internal.example.com:5432/appdb?user=svc&amp;password=***REDACTED*** | - | 00002300 | connect_db | false |
		| 00001008 | endpoint | LOW | string | db.internal.example.com | - | 00002000 | connect_db | false |
		| 0000100c | endpoint | LOW | string | :5432 | - | 00002180 | connect_db | false |
		| 00001010 | jdbc | HIGH | import | PQconnectdb | libpq.so.5 | EXTERNAL:00000003 | connect_db | false |
		| 00001044 | http | MEDIUM | string | https://api.example.com/v1/orders | - | 00002100 | call_api | false |
		| 00001048 | auth_tls | HIGH | string | Authorization: Bearer ***REDACTED*** | - | 00002380 | call_api | false |
		| 0000104c | auth_tls | HIGH | string | X-Api-Key: ***REDACTED*** | - | 00002400 | call_api | false |
		| 00001050 | endpoint | LOW | string | :8443 | - | 00002200 | call_api | false |
		| 00001054 | endpoint | LOW | string | 192.0.2.10:8443 | - | 00002480 | call_api | false |
		| 00001058 | endpoint | LOW | import | getaddrinfo | libc.so.6 | EXTERNAL:00000004 | call_api | false |
		| 0000105c | auth_tls | HIGH | import | SSL_connect | libssl.so.3 | EXTERNAL:00000001 | call_api | true |
		| 00001084 | queue | MEDIUM | string | mq.example.com | - | 00002080 | send_queue | false |
		| 00001088 | queue | MEDIUM | string | :5672 | - | 00002280 | send_queue | false |
		| 0000108c | queue | MEDIUM | string | amqps://mq.example.com:5672/vhost | - | 00002500 | send_queue | false |
		| 00001090 | http | MEDIUM | string | https://api.example.com/v1/orders | - | 00002100 | send_queue | false |
		| 00001094 | http | MEDIUM | string | https://api.example.com/v1/orders | - | 00002100 | send_queue | false |
		| 000010c4 | auth_tls | HIGH | import | SSL_connect | libssl.so.3 | EXTERNAL:00000001 | tls_helper | false |
		| 000010c8 | auth_tls | HIGH | import | SSL_connect | libssl.so.3 | EXTERNAL:00000001 | tls_helper | false |
		| 00001104 | auth_tls | HIGH | string | Authorization: Bearer ***REDACTED*** | - | 00002380 | tls_helper | true |
		| 00001108 | auth_tls | HIGH | import | SSL_CTX_new | libssl.so.3 | EXTERNAL:00000002 | tls_helper | true |
		| 00002580 | endpoint | LOW | string | unused.example.com | - | 00002580 | - | false |
		""";

	private ExternalDependencyFixture fixture;
	private Program program;

	@Before
	public void setUp() throws Exception {
		fixture = new ExternalDependencyFixture();
		program = fixture.getProgram();
	}

	@After
	public void tearDown() {
		fixture.dispose();
	}

	@Test
	public void testJsonGolden() throws Exception {
		List<DependencyFinding> findings = scan();
		String json = ExternalDependencyExporter.toJson(program, findings);
		assertEquals(JSON_GOLDEN, json);
	}

	@Test
	public void testMarkdownGolden() throws Exception {
		List<DependencyFinding> findings = scan();
		String markdown = ExternalDependencyExporter.toMarkdown(program, findings);
		assertEquals(MARKDOWN_GOLDEN, markdown);
	}

	@Test
	public void testMarkdownEscaping() {
		DependencyFinding finding = new DependencyFinding(DependencyCategory.HTTP, "string",
			"https://api.example.com/\norders<b>", null, fixture.getBuilder().addr("0x2100"),
			fixture.getBuilder().addr("0x1094"), null, false);
		String markdown = ExternalDependencyExporter.toMarkdown(program, List.of(finding));
		assertTrue(markdown.contains("https://api.example.com/\\norders&lt;b&gt;"));
		assertEquals(3, markdown.lines().filter(line -> line.startsWith("| ")).count());
	}

	@Test
	public void testSecretsRedacted() throws Exception {
		String json = ExternalDependencyExporter.toJson(program, scan());
		String markdown = ExternalDependencyExporter.toMarkdown(program, scan());
		for (String secret : new String[] { "REDACTME", "FAKE-TOKEN-0000", "FAKE-API-KEY-0000" }) {
			assertFalse(json.contains(secret));
			assertFalse(markdown.contains(secret));
		}
		assertTrue(json.contains("***REDACTED***"));
		assertTrue(markdown.contains("***REDACTED***"));
	}

	@Test
	public void testAttribution() throws Exception {
		List<DependencyFinding> findings = scan();
		DependencyFinding jdbc = find(findings,
			"jdbc:postgresql://db.internal.example.com:5432/appdb?user=svc&password=***REDACTED***",
			ExternalDependencyFixture.CONNECT_DB_ADDRESS);
		assertNotNull(jdbc);
		assertEquals("connect_db", jdbc.getFunctionName());
		assertEquals(3, findFrom(findings, "https://api.example.com/v1/orders").size());
		DependencyFinding thunkImport = find(findings, "SSL_connect",
			ExternalDependencyFixture.SSL_CONNECT_THUNK_CALL_ADDRESS);
		assertNotNull(thunkImport);
		assertEquals("call_api", thunkImport.getFunctionName());
		assertTrue(thunkImport.isViaThunk());
		DependencyFinding authThunk = find(findings, "Authorization: Bearer ***REDACTED***",
			ExternalDependencyFixture.TLS_THUNK_ADDRESS);
		assertNotNull(authThunk);
		assertEquals("tls_helper", authThunk.getFunctionName());
		assertTrue(authThunk.isViaThunk());
		assertEquals(3, findImports(findings, "SSL_connect").size());
		DependencyFinding renamedJdbc = find(findings, "PQconnectdb", "0x1010");
		assertNotNull(renamedJdbc);
		DependencyFinding ctx = find(findings, "SSL_CTX_new", "0x1108");
		assertNotNull(ctx);
		assertEquals("tls_helper", ctx.getFunctionName());
		assertTrue(ctx.isViaThunk());
		DependencyFinding unused = find(findings, ExternalDependencyFixture.UNUSED, "0x2580");
		assertNotNull(unused);
		assertEquals(null, unused.getFunctionName());
	}

	@Test
	public void testDeterminism() throws Exception {
		String json = ExternalDependencyExporter.toJson(program, scan());
		String markdown = ExternalDependencyExporter.toMarkdown(program, scan());
		assertEquals(json, ExternalDependencyExporter.toJson(program, scan()));
		assertEquals(markdown, ExternalDependencyExporter.toMarkdown(program, scan()));
		ExternalDependencyFixture second = new ExternalDependencyFixture();
		try {
			assertEquals(json, ExternalDependencyExporter.toJson(second.getProgram(),
				ExternalDependencyScanner.scan(second.getProgram(), TaskMonitor.DUMMY)));
			assertEquals(markdown, ExternalDependencyExporter.toMarkdown(second.getProgram(),
				ExternalDependencyScanner.scan(second.getProgram(), TaskMonitor.DUMMY)));
		}
		finally {
			second.dispose();
		}
	}

	@Test
	public void testRulesClassification() {
		assertEquals(DependencyCategory.ENDPOINT,
			DependencyRules.classifyString(ExternalDependencyFixture.DB_HOST));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString(ExternalDependencyFixture.MQ_HOST));
		assertEquals(DependencyCategory.HTTP,
			DependencyRules.classifyString(ExternalDependencyFixture.HTTP_URL));
		assertEquals(DependencyCategory.HTTP,
			DependencyRules.classifyString("http://example.com:5672"));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString("amqp://x:5672"));
		assertEquals(null, DependencyRules.classifyString("Log request failed:5672"));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString("mq.example.com:5672"));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString("localhost:5672"));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString("[::1]:5672"));
		assertEquals(null, DependencyRules.classifyString("[.]:5672"));
		assertEquals(DependencyCategory.ENDPOINT,
			DependencyRules.classifyString("localhost:8443"));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString(":5672"));
		assertEquals(DependencyCategory.ENDPOINT,
			DependencyRules.classifyString(ExternalDependencyFixture.PORT_5432));
		assertEquals(DependencyCategory.JDBC,
			DependencyRules.classifyString(ExternalDependencyFixture.JDBC));
		assertEquals(DependencyCategory.AUTH_TLS,
			DependencyRules.classifyString(ExternalDependencyFixture.AUTHORIZATION));
		assertEquals(DependencyCategory.AUTH_TLS,
			DependencyRules.classifyString(ExternalDependencyFixture.API_KEY));
		assertEquals(DependencyCategory.ENDPOINT,
			DependencyRules.classifyString(ExternalDependencyFixture.IPV4));
		assertEquals(DependencyCategory.QUEUE,
			DependencyRules.classifyString(ExternalDependencyFixture.AMQPS));
		assertEquals(null, DependencyRules.classifyString("hello world"));
		assertEquals("password=***REDACTED***",
			DependencyRules.redact("password=REDACTME"));
		assertEquals("jdbc:x://h/db?user=u&password=***REDACTED***&ssl=true",
			DependencyRules.redact("jdbc:x://h/db?user=u&password=two words&ssl=true"));
		assertEquals("jdbc:postgresql://h/db?sslpassword=***REDACTED***&user=u",
			DependencyRules.redact("jdbc:postgresql://h/db?sslpassword=abc&user=u"));
		assertEquals("https://api.example.com/cb#access_token=***REDACTED***",
			DependencyRules.redact("https://api.example.com/cb#access_token=abc"));
		assertTrue(DependencyRules.redact("https://api.example.com/cb#foo.access_token=abc")
			.endsWith("access_token=***REDACTED***"));
		assertEquals("https://user:***REDACTED***@api.example.com:8443/path",
			DependencyRules.redact("https://user:password=abc@api.example.com:8443/path"));
		assertEquals("?password_token=***REDACTED***&x=1",
			DependencyRules.redact("?password_token=PRIVATE&x=1"));
		assertEquals("Authorization: Bearer ***REDACTED***",
			DependencyRules.redact(ExternalDependencyFixture.AUTHORIZATION));
		assertEquals("X-Api-Key: ***REDACTED***",
			DependencyRules.redact(ExternalDependencyFixture.API_KEY));
		assertEquals("https://user:***REDACTED***@example.com",
			DependencyRules.redact("https://user:secret@example.com"));
	}

	private List<DependencyFinding> scan() throws Exception {
		return ExternalDependencyScanner.scan(program, TaskMonitor.DUMMY);
	}

	private static DependencyFinding find(List<DependencyFinding> findings, String value,
			String fromAddress) {
		return findings.stream()
			.filter(f -> f.getMatchedValue().equals(value) &&
				f.getFromAddress().toString().equals(normalize(fromAddress)))
			.findFirst().orElse(null);
	}

	private static String normalize(String address) {
		String value = address.replace("0x", "");
		return "00000000".substring(Math.min(value.length(), 8)) + value.toLowerCase();
	}

	private static List<DependencyFinding> findFrom(List<DependencyFinding> findings, String value) {
		return findings.stream().filter(f -> f.getMatchedValue().equals(value)).toList();
	}

	private static List<DependencyFinding> findImports(List<DependencyFinding> findings,
			String value) {
		return findings.stream().filter(f -> f.getKind().equals("import") &&
			f.getMatchedValue().equals(value)).toList();
	}
}
