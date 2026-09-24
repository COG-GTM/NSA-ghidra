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

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class RedactorTest extends AbstractGenericTest {

	@Test
	public void testUriUserinfoPasswordIsMasked() {
		Redactor.Result r = Redactor.redact("postgresql://svc_user:Tr0ub4dor@db.example.test:5432/tiles");
		assertTrue(r.redacted());
		assertEquals("postgresql://svc_user:" + Redactor.MASK + "@db.example.test:5432/tiles", r.text());
	}

	@Test
	public void testBareUriUserinfoIsMasked() {
		Redactor.Result r = Redactor.redact("https://ghp_0123456789abcdef@git.example.test/org/repo.git");
		assertTrue(r.redacted());
		assertEquals("https://" + Redactor.MASK + "@git.example.test/org/repo.git", r.text());

		r = Redactor.redact("amqp://guest:guest@broker.example.test:5672/vhost");
		assertEquals("amqp://guest:" + Redactor.MASK + "@broker.example.test:5672/vhost", r.text());
		assertEquals(1, r.text().split("\\*\\*\\*", -1).length - 1);

		assertFalse(Redactor.redact("svc/host@EXAMPLE.TEST").redacted());
	}

	@Test
	public void testUrlQueryCredentialsAreMasked() {
		String[][] cases = {
			{ "https://auth.example.test/oauth/token?client_id=web&client_secret=s3cret-Value",
				"s3cret-Value", "client_id=web" },
			{ "https://maps.example.test/tiles?zoom=3&key=AIzaFAKEKEY0123", "AIzaFAKEKEY0123",
				"zoom=3" },
			{ "https://acct.blob.example.test/c/b?sv=2020-08-04&sig=abc%2Fdef123", "abc%2Fdef123",
				"sv=2020-08-04" },
			{ "https://api.example.test/v1?access_token=ya29.tok&format=json", "ya29.tok",
				"format=json" },
			{ "Endpoint=sb://ns.example.test/;SharedAccessKeyName=root;SharedAccessKey=Zm9v=",
				"Zm9v=", "SharedAccessKeyName=root" },
			{ "https://api.example.test/items?pass=hunter22&page=2", "hunter22", "page=2" },
		};
		for (String[] c : cases) {
			Redactor.Result r = Redactor.redact(c[0]);
			assertTrue(c[0], r.redacted());
			assertFalse(r.text(), r.text().contains(c[1]));
			assertTrue(r.text(), r.text().contains(c[2]));
			assertTrue(r.text(), r.text().contains(Redactor.MASK));
		}
		assertEquals("https://auth.example.test/oauth/token?client_id=web&client_secret=" + Redactor.MASK,
			Redactor.redact(
				"https://auth.example.test/oauth/token?client_id=web&client_secret=s3cret-Value").text());
	}

	@Test
	public void testKeyValuePasswordIsMasked() {
		Redactor.Result r = Redactor.redact("host=db.example.test user=app password=hunter22 dbname=ops");
		assertTrue(r.redacted());
		assertFalse(r.text().contains("hunter22"));
		assertTrue(r.text().contains("host=db.example.test"));

		r = Redactor.redact("Server=sql01;Database=ops;Uid=app;Pwd=s3cret;");
		assertTrue(r.redacted());
		assertFalse(r.text().contains("s3cret"));
	}

	@Test
	public void testQuotedAndBracedKeyValuePasswordsAreMasked() {
		String[] inputs = {
			"host=db.example.test password='p;a&s,s w\"d' dbname=ops",
			"host=db.example.test password=\"p;a&s,s w'd\" dbname=ops",
			"Server=sql01;Pwd={p;a&s,s w'd};Database=ops",
			"user=app password = 'p;a&s,s w\"d'",
		};
		for (String s : inputs) {
			Redactor.Result r = Redactor.redact(s);
			assertTrue(s, r.redacted());
			assertFalse(s, r.text().contains("p;a&s"));
			assertFalse(s, r.text().contains("s w"));
			assertTrue(s, r.text().contains(Redactor.MASK));
		}
		assertEquals("host=db.example.test password=" + Redactor.MASK + " dbname=ops",
			Redactor.redact("host=db.example.test password='p;a&s,s w\"d' dbname=ops").text());
	}

	@Test
	public void testAuthorizationHeadersAreMasked() {
		Redactor.Result r = Redactor.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
		assertTrue(r.redacted());
		assertFalse(r.text().contains("eyJhbGci"));

		r = Redactor.redact("X-Api-Key: 0123456789abcdef");
		assertTrue(r.redacted());
		assertFalse(r.text().contains("0123456789abcdef"));

		r = Redactor.redact("Basic dXNlcjpwYXNz");
		assertTrue(r.redacted());
		assertFalse(r.text().contains("dXNlcjpwYXNz"));
	}

	@Test
	public void testNonCredentialTextIsUnchanged() {
		for (String s : new String[] { "http://tiles.example.test/wms", "tiles.example.test",
			"10.20.30.40", "user=app", "Content-Type: application/json", "" }) {
			Redactor.Result r = Redactor.redact(s);
			assertFalse(s, r.redacted());
			assertEquals(s, r.text());
		}
		assertFalse(Redactor.redact(null).redacted());
		assertEquals("", Redactor.redact(null).text());
	}

	@Test
	public void testContainsCredentialMirrorsRedaction() {
		assertTrue(Redactor.containsCredential("mysql://root:pw@localhost/db"));
		assertFalse(Redactor.containsCredential("mysql://localhost/db"));
	}
}
