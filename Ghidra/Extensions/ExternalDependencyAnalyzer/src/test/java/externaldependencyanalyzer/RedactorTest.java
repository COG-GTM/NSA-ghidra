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
