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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import externaldependencyanalyzer.ApiTable.ApiEntry;
import generic.test.AbstractGenericTest;

public class ApiTableTest extends AbstractGenericTest {

	private static final Set<String> REQUIRED_APIS = Set.of("connect", "getaddrinfo",
		"gethostbyname", "WSAConnect", "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpConnect",
		"curl_easy_setopt", "SSL_CTX_new", "SSL_connect", "SSL_CTX_set_verify", "PQconnectdb",
		"mysql_real_connect", "sqlite3_open", "ldap_init", "amqp_login", "krb5_init_context");

	private static ApiTable bundled() throws IOException {
		Path p = findBundledTable();
		try (InputStream in = Files.newInputStream(p)) {
			return ApiTable.load(in, p.toString());
		}
	}

	private static Path findBundledTable() {
		Path here = Path.of("").toAbsolutePath();
		for (Path dir = here; dir != null; dir = dir.getParent()) {
			Path candidate = dir.resolve("data").resolve(ApiTable.DEFAULT_FILE_NAME);
			if (Files.isRegularFile(candidate)) {
				return candidate;
			}
			Path nested = dir.resolve("Ghidra/Extensions/ExternalDependencyAnalyzer/data")
					.resolve(ApiTable.DEFAULT_FILE_NAME);
			if (Files.isRegularFile(nested)) {
				return nested;
			}
		}
		throw new AssertionError("bundled API table not found from " + here);
	}

	private static ApiTable parse(String json) throws IOException {
		return ApiTable.load(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)),
			"test");
	}

	@Test
	public void testBundledTableCoversRequiredApis() throws IOException {
		ApiTable t = bundled();
		List<String> missing = new ArrayList<>();
		for (String api : REQUIRED_APIS) {
			if (t.lookup(api) == null) {
				missing.add(api);
			}
		}
		assertTrue("missing from bundled table: " + missing, missing.isEmpty());
	}

	@Test
	public void testBundledTableMetadataIsConsistent() throws IOException {
		ApiTable t = bundled();
		ApiEntry curl = t.lookup("curl_easy_setopt");
		assertTrue(curl.hasOptionArgument());
		assertTrue(curl.hasHostArgument());
		assertEquals("CURLOPT_URL", curl.optionValues().get(10002L));

		ApiEntry verify = t.lookup("SSL_CTX_set_verify");
		assertTrue(verify.hasVerifyModeArgument());
		assertEquals("tls", verify.category());

		ApiEntry htons = t.lookup("htons");
		assertTrue(htons.hasPortArgument());

		for (ApiEntry e : t.entries()) {
			assertTrue(e.name(), e.category().matches("[a-z0-9_-]{1,32}"));
		}
	}

	@Test
	public void testSymbolDecorationsAreNormalized() throws IOException {
		ApiTable t = bundled();
		assertNotNull(t.lookup("__imp_connect"));
		assertNotNull(t.lookup("_connect"));
		assertNotNull(t.lookup("connect@GLIBC_2.2.5"));
		assertNotNull(t.lookup("connect@@GLIBC_2.2.5"));
		assertNotNull(t.lookup("InternetOpenUrlA"));
		assertNull(t.lookup("not_a_network_api"));
		assertNull(t.lookup(null));
		assertNull(t.lookup(""));
	}

	@Test
	public void testCustomTableValidation() throws IOException {
		ApiTable ok = parse("{\"apis\":[{\"name\":\"vendor_connect\",\"category\":\"socket\"," +
			"\"protocolHint\":\"tcp\",\"hostArgument\":1}]}");
		assertEquals(1, ok.size());
		assertEquals(1, ok.lookup("vendor_connect").hostArgument());

		String[] rejected = {
			"not json",
			"[]",
			"{\"apis\":{}}",
			"{\"apis\":[1]}",
			"{\"apis\":[{\"name\":\"\"}]}",
			"{\"apis\":[{\"name\":\"bad name;rm -rf\"}]}",
			"{\"apis\":[{\"name\":\"ok\",\"category\":\"Not Valid!\"}]}",
			"{\"apis\":[{\"name\":\"ok\",\"hostArgument\":99}]}",
			"{\"apis\":[{\"name\":\"ok\",\"hostArgument\":-2}]}",
			"{\"apis\":[{\"name\":\"ok\",\"hostArgument\":\"one\"}]}",
			"{\"apis\":[{\"name\":\"ok\",\"optionValues\":{\"x\":\"CURLOPT_URL\"}}]}",
		};
		for (String json : rejected) {
			try {
				parse(json);
				fail("accepted invalid table: " + json);
			}
			catch (IOException expected) {
				// rejected as intended
			}
		}
	}

	@Test
	public void testLoadOrDefaultFallsBackWithGenericWarning() throws IOException {
		List<String> warnings = new ArrayList<>();
		Path bad = Files.createTempFile("edapi", ".json");
		try {
			Files.writeString(bad, "{\"apis\":[{\"name\":\"\"}]}");
			ApiTable t = ApiTable.loadOrDefault(bad.toString(), warnings);
			assertEquals(1, warnings.size());
			assertFalse(warnings.get(0).contains(bad.toString()));
			assertNotEquals(bad.toString(), t.getSource());
		}
		finally {
			Files.deleteIfExists(bad);
		}

		warnings.clear();
		ApiTable.loadOrDefault("/definitely/not/here.json", warnings);
		assertEquals(1, warnings.size());
	}
}
