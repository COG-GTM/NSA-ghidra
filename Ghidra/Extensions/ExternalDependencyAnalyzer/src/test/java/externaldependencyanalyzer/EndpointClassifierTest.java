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

import java.util.List;

import org.junit.Test;

import externaldependencyanalyzer.DependencyModel.EndpointKind;
import externaldependencyanalyzer.EndpointClassifier.Candidate;
import generic.test.AbstractGenericTest;

public class EndpointClassifierTest extends AbstractGenericTest {

	private static final int MIN = ScanOptions.DEFAULT_MIN_STRING_LENGTH;

	private static Candidate one(String s) {
		List<Candidate> list = EndpointClassifier.classify(s, MIN);
		assertEquals("expected exactly one candidate for: " + s, 1, list.size());
		return list.get(0);
	}

	private static void none(String s) {
		assertTrue("expected no candidate for: " + s,
			EndpointClassifier.classify(s, MIN).isEmpty());
	}

	@Test
	public void testUrlWithPlaintextScheme() {
		Candidate c = one("http://tiles.example-geo.internal/wms?SERVICE=WMS&REQUEST=GetCapabilities");
		assertEquals(EndpointKind.URL, c.kind());
		assertEquals("http", c.scheme());
		assertEquals("tiles.example-geo.internal", c.host());
		assertEquals("ogc/wms", c.protocolHint());
		assertTrue(EndpointClassifier.isPlaintextScheme(c.scheme()));
	}

	@Test
	public void testPostgresConnectionStringIsRedacted() {
		Candidate c = one("postgresql://svc_user:Tr0ub4dor@db.example-geo.internal:5432/tiles");
		assertEquals(EndpointKind.CONNECTION_STRING, c.kind());
		assertEquals("postgresql", c.protocolHint());
		assertEquals("db.example-geo.internal", c.host());
		assertEquals(5432, c.port());
		assertFalse(c.value().contains("Tr0ub4dor"));
		assertTrue(c.value().contains(Redactor.MASK));
		assertTrue(c.notes().contains("credential redacted"));
	}

	@Test
	public void testJdbcOdbcAndOracleThin() {
		Candidate jdbc = one("jdbc:mysql://mysql.example.test:3306/inventory");
		assertEquals(EndpointKind.CONNECTION_STRING, jdbc.kind());
		assertEquals("jdbc/mysql", jdbc.protocolHint());
		assertEquals("mysql.example.test", jdbc.host());

		Candidate odbc = one("Driver={SQL Server};Server=sql01.example.test;Database=ops;Uid=app;Pwd=secret;");
		assertEquals(EndpointKind.CONNECTION_STRING, odbc.kind());
		assertEquals("sql01.example.test", odbc.host());
		assertFalse(odbc.value().contains("secret"));

		Candidate oracle = one("jdbc:oracle:thin:@ora.example.test:1521:ORCL");
		assertEquals(EndpointKind.CONNECTION_STRING, oracle.kind());
		assertEquals("oracle", oracle.protocolHint());
		assertEquals(1521, oracle.port());
	}

	@Test
	public void testHostnamesAndLiterals() {
		Candidate host = one("tiles.example-geo.internal");
		assertEquals(EndpointKind.HOSTNAME, host.kind());

		Candidate hp = one("broker.example.test:5672");
		assertEquals(EndpointKind.HOST_PORT, hp.kind());
		assertEquals(5672, hp.port());
		assertEquals("amqp", hp.protocolHint());

		Candidate v4 = one("10.20.30.40");
		assertEquals(EndpointKind.IPV4, v4.kind());
		assertTrue(EndpointClassifier.isPrivateIpv4(v4.host()));
		assertFalse(EndpointClassifier.isPrivateIpv4("8.8.8.8"));

		Candidate v6 = one("2001:db8::10");
		assertEquals(EndpointKind.IPV6, v6.kind());
		assertEquals("2001:db8::10", v6.host());

		Candidate v6port = one("[2001:db8::10]:443");
		assertEquals(EndpointKind.HOST_PORT, v6port.kind());
		assertEquals("[2001:db8::10]", v6port.host());
		assertEquals(443, v6port.port());
		assertEquals("https", v6port.protocolHint());
	}

	@Test
	public void testBrokerBootstrapAndFileShares() {
		Candidate kafka = one("kafka1.example.test:9092,kafka2.example.test:9092");
		assertEquals(EndpointKind.CONNECTION_STRING, kafka.kind());
		assertEquals("kafka", kafka.protocolHint());
		assertEquals("kafka1.example.test", kafka.host());
		assertEquals(9092, kafka.port());

		Candidate unc = one("\\\\fileserver01\\tiles\\cache");
		assertEquals(EndpointKind.UNC_PATH, unc.kind());
		assertEquals("fileserver01", unc.host());

		Candidate nfs = one("nfs01.example.test:/export/tiles");
		assertEquals(EndpointKind.UNC_PATH, nfs.kind());
		assertEquals("nfs", nfs.protocolHint());
	}

	@Test
	public void testDirectoryAndAuthConstants() {
		Candidate dn = one("cn=svc,ou=services,dc=example,dc=test");
		assertEquals(EndpointKind.LDAP_DN, dn.kind());

		Candidate realm = one("HTTP/geo.example.test@EXAMPLE.TEST");
		assertEquals(EndpointKind.KERBEROS_REALM, realm.kind());

		Candidate hdr = one("Authorization: Bearer");
		assertEquals(EndpointKind.HEADER_CONSTANT, hdr.kind());
		assertEquals("Authorization: " + Redactor.MASK, hdr.value());

		Candidate key = one("X-Api-Key: 0123456789abcdef");
		assertEquals(EndpointKind.HEADER_CONSTANT, key.kind());
		assertFalse(key.value().contains("0123456789abcdef"));
	}

	@Test
	public void testPathsAndServiceHints() {
		Candidate grpc = one("/geo.tiles.v1.TileService/GetTile");
		assertEquals(EndpointKind.HTTP_PATH, grpc.kind());
		assertEquals("grpc", grpc.protocolHint());

		Candidate api = one("/api/v2/layers");
		assertEquals(EndpointKind.HTTP_PATH, api.kind());

		Candidate ogc = one("SERVICE=WFS&REQUEST=GetCapabilities");
		assertEquals(EndpointKind.SERVICE_HINT, ogc.kind());
	}

	@Test
	public void testFalsePositiveControl() {
		none("/lib64/ld-linux-x86-64.so.2");
		none("GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0");
		none("libc.so.6");
		none("GLIBC_2.34");
		none(".note.gnu.property");
		none("__libc_start_main");
		none("/usr/share/zoneinfo");
		none("1.2.3.4.5");
		none("version 2.0.1");
		none("hello world");
		none("short");
		none("bad\u0001control.example.test");
		none("x".repeat(EndpointClassifier.MAX_STRING_LENGTH + 1));
	}

	@Test
	public void testMinimumLengthIsHonoured() {
		assertTrue(EndpointClassifier.classify("a.io", 6).isEmpty());
		assertFalse(EndpointClassifier.classify("a.io", 2).isEmpty());
	}
}
