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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import externaldependencyanalyzer.DependencyModel.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Drives the analyzer over a small synthetic x86-64 program built with {@link ProgramBuilder}.
 * The program contains a caller that loads two string constants and calls locally defined
 * stubs named after network APIs, which is the shape a statically linked binary presents.
 */
public class ExternalDependencyAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String CONN = "postgresql://svc_user:Tr0ub4dor@db.example.test:5432/ops";
	private static final String URL = "http://tiles.example.test/wms?REQUEST=GetCapabilities";

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("synthetic", ProgramBuilder._X64, "gcc", this);
		builder.createMemory(".text", "0x401000", 0x200);
		builder.createMemory(".rodata", "0x402000", 0x200);

		builder.createString("0x402000", CONN, StandardCharsets.US_ASCII, true,
			TerminatedStringDataType.dataType);
		builder.createString("0x402080", URL, StandardCharsets.US_ASCII, true,
			TerminatedStringDataType.dataType);

		// PQconnectdb stub at 0x401100, curl_easy_setopt stub at 0x401110: both "ret".
		builder.setBytes("0x401100", "c3");
		builder.setBytes("0x401110", "c3");
		builder.disassemble("0x401100", 1);
		builder.disassemble("0x401110", 1);
		builder.createFunction("0x401100");
		builder.createFunction("0x401110");
		builder.createLabel("0x401100", "PQconnectdb");
		builder.createLabel("0x401110", "curl_easy_setopt");

		// main at 0x401000:
		//   lea rdi,[rip+X] -> 0x402000       48 8d 3d disp32   (7 bytes, ends 0x401007)
		//   call 0x401100                      e8 rel32          (5 bytes, ends 0x40100c)
		//   mov esi,0x2712 (CURLOPT_URL)       be 12 27 00 00    (5 bytes, ends 0x401011)
		//   lea rdx,[rip+Y] -> 0x402080        48 8d 15 disp32   (7 bytes, ends 0x401018)
		//   call 0x401110                      e8 rel32          (5 bytes, ends 0x40101d)
		//   ret                                c3
		String code = "48 8d 3d " + le32(0x402000 - 0x401007) + "e8 " + le32(0x401100 - 0x40100c) +
			"be 12 27 00 00 " + "48 8d 15 " + le32(0x402080 - 0x401018) + "e8 " +
			le32(0x401110 - 0x40101d) + "c3";
		builder.setBytes("0x401000", code, true);
		builder.createFunction("0x401000");
		builder.createLabel("0x401000", "main");
		program = builder.getProgram();
		int tx = program.startTransaction("format");
		try {
			program.setExecutableFormat("Executable and Linking Format (ELF)");
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private static String le32(int v) {
		return String.format("%02x %02x %02x %02x ", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff,
			(v >> 24) & 0xff);
	}

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	private ScanResult runAnalyzer(ScanOptions options) throws Exception {
		ExternalDependencyAnalyzer analyzer = new ExternalDependencyAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		int tx = program.startTransaction("analyze");
		try {
			ScanResult result = new DependencyScanner(program, options, TaskMonitor.DUMMY).scan();
			ProgramAnnotator.annotate(program, result, options, TaskMonitor.DUMMY);
			return result;
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void testAnalyzerEntryPointRunsWithoutError() throws Exception {
		ExternalDependencyAnalyzer analyzer = new ExternalDependencyAnalyzer();
		MessageLog log = new MessageLog();
		int tx = program.startTransaction("analyze");
		try {
			AddressSet set = new AddressSet(program.getMemory());
			assertTrue(analyzer.added(program, set, TaskMonitor.DUMMY, log));
		}
		finally {
			program.endTransaction(tx, true);
		}
		String messages = log.toString();
		assertTrue(messages, messages.contains("2 endpoints"));
		assertFalse(messages, messages.contains("did not complete"));
		String stored = ProgramAnnotator.storedResultJson(program);
		assertNotNull(stored);
		ScanResult parsed = DependencyReportReader.fromJson(stored);
		assertEquals(2, parsed.endpoints().size());
	}

	@Test
	public void testEndpointsLinkedToCallSitesAndRedacted() throws Exception {
		ScanResult r = runAnalyzer(ScanOptions.defaults());

		Endpoint conn = find(r, EndpointKind.CONNECTION_STRING);
		assertEquals("00402000", conn.address());
		assertFalse(conn.value().contains("Tr0ub4dor"));
		assertTrue(conn.value().contains(Redactor.MASK));
		assertEquals(List.of("main"), conn.referencingFunctions());
		assertNotNull(conn.nearestNetworkCall());
		assertEquals("PQconnectdb", conn.nearestNetworkCall().api());
		assertEquals("00401007", conn.nearestNetworkCall().address());
		assertEquals("main", conn.nearestNetworkCall().function());
		assertEquals("postgresql", conn.protocolHint());

		Endpoint url = find(r, EndpointKind.URL);
		assertEquals("00402080", url.address());
		assertEquals(List.of("main"), url.referencingFunctions());
		assertNotNull(url.nearestNetworkCall());
		assertEquals("curl_easy_setopt", url.nearestNetworkCall().api());
		assertEquals("00401018", url.nearestNetworkCall().address());

		List<String> apis = r.apiCallSites().stream().map(ApiCallSite::api).toList();
		assertEquals(List.of("PQconnectdb", "curl_easy_setopt"), apis);
		ApiCallSite curl = r.apiCallSites().get(1);
		assertTrue(curl.notes().toString(), curl.notes().contains("option CURLOPT_URL"));

		List<String> rules = r.findings().stream().map(Finding::rule).toList();
		assertTrue(rules.toString(), rules.contains(Rule.HARDCODED_CREDENTIAL.jsonName()));
		assertTrue(rules.toString(), rules.contains(Rule.PLAINTEXT_PROTOCOL.jsonName()));
		for (Finding f : r.findings()) {
			assertFalse(f.detail(), f.detail().contains("Tr0ub4dor"));
		}
	}

	@Test
	public void testProgramAnnotationsAreWrittenAndRedacted() throws Exception {
		runAnalyzer(ScanOptions.defaults());

		BookmarkManager bm = program.getBookmarkManager();
		List<Bookmark> marks = new ArrayList<>();
		bm.getBookmarksIterator().forEachRemaining(marks::add);
		assertFalse(marks.isEmpty());
		for (Bookmark b : marks) {
			assertEquals(ProgramAnnotator.BOOKMARK_CATEGORY, b.getCategory());
			assertFalse(b.getComment(), b.getComment().contains("Tr0ub4dor"));
		}
		assertTrue(marks.stream().anyMatch(b -> b.getAddress().getOffset() == 0x402000));

		Address conn = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000);
		String eol = program.getListing().getComment(CodeUnit.EOL_COMMENT, conn);
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith(ProgramAnnotator.COMMENT_PREFIX));
		assertFalse(eol, eol.contains("Tr0ub4dor"));

		String stored = ProgramAnnotator.storedResultJson(program);
		assertNotNull(stored);
		assertFalse(stored.contains("Tr0ub4dor"));
		assertEquals(stored, DependencyReportWriter.toJson(DependencyReportReader.fromJson(stored)));
	}

	@Test
	public void testCommentOptionCanBeDisabled() throws Exception {
		runAnalyzer(ScanOptions.defaults().withWriteComments(false));
		Address conn = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000);
		assertNull(program.getListing().getComment(CodeUnit.EOL_COMMENT, conn));
		assertTrue(program.getBookmarkManager().getBookmarkCount() > 0);
	}

	@Test
	public void testTwoScansProduceIdenticalJson() throws Exception {
		String first = DependencyReportWriter.toJson(runAnalyzer(ScanOptions.defaults()));
		String second = DependencyReportWriter.toJson(runAnalyzer(ScanOptions.defaults()));
		assertEquals(first, second);
	}

	private static Endpoint find(ScanResult r, EndpointKind kind) {
		return r.endpoints().stream().filter(e -> e.kind() == kind).findFirst().orElseThrow(
			() -> new AssertionError("no endpoint of kind " + kind + " in " + r.endpoints()));
	}
}
