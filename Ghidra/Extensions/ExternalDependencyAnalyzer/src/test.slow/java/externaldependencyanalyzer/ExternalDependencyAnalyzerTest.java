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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
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
		String eol = program.getListing().getComment(CommentType.EOL, conn);
		assertNotNull(eol);
		assertTrue(eol, eol.startsWith(ProgramAnnotator.COMMENT_PREFIX));
		assertFalse(eol, eol.contains("Tr0ub4dor"));

		String stored = ProgramAnnotator.storedResultJson(program);
		assertNotNull(stored);
		assertFalse(stored.contains("Tr0ub4dor"));
		assertEquals(stored, DependencyReportWriter.toJson(DependencyReportReader.fromJson(stored)));
	}

	@Test
	public void testRescanClearsStaleCommentsAndKeepsAnalystComments() throws Exception {
		runAnalyzer(ScanOptions.defaults());
		Listing listing = program.getListing();
		Address conn = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000);
		Address stale = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402100);
		Address main = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);

		String mainPlate = listing.getComment(CommentType.PLATE, main);
		assertNotNull(mainPlate);
		assertTrue(mainPlate, mainPlate.contains("references connection_string"));
		assertTrue(mainPlate, mainPlate.contains("references url"));
		assertFalse(mainPlate, mainPlate.contains("Tr0ub4dor"));

		int tx = program.startTransaction("analyst");
		try {
			listing.setComment(conn, CommentType.EOL,
				"analyst note\n" + listing.getComment(CommentType.EOL, conn));
			listing.setComment(stale, CommentType.EOL,
				ProgramAnnotator.COMMENT_PREFIX + " stale endpoint from an earlier run");
			listing.setComment(main, CommentType.PLATE,
				"keep me\n" + ProgramAnnotator.COMMENT_PREFIX + " stale plate line");
		}
		finally {
			program.endTransaction(tx, true);
		}

		runAnalyzer(ScanOptions.defaults());
		assertNull(listing.getComment(CommentType.EOL, stale));
		String eol = listing.getComment(CommentType.EOL, conn);
		assertTrue(eol, eol.startsWith("analyst note\n" + ProgramAnnotator.COMMENT_PREFIX));
		assertEquals(eol, eol.indexOf(ProgramAnnotator.COMMENT_PREFIX),
			eol.lastIndexOf(ProgramAnnotator.COMMENT_PREFIX));
		mainPlate = listing.getComment(CommentType.PLATE, main);
		assertTrue(mainPlate, mainPlate.startsWith("keep me\n"));
		assertFalse(mainPlate, mainPlate.contains("stale plate line"));
		assertTrue(mainPlate, mainPlate.contains("references connection_string"));
	}

	@Test
	public void testCommentOptionCanBeDisabled() throws Exception {
		runAnalyzer(ScanOptions.defaults().withWriteComments(false));
		Address conn = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000);
		assertNull(program.getListing().getComment(CommentType.EOL, conn));
		assertTrue(program.getBookmarkManager().getBookmarkCount() > 0);
	}

	@Test
	public void testTwoScansProduceIdenticalJson() throws Exception {
		String first = DependencyReportWriter.toJson(runAnalyzer(ScanOptions.defaults()));
		String second = DependencyReportWriter.toJson(runAnalyzer(ScanOptions.defaults()));
		assertEquals(first, second);
	}

	@Test
	public void testMemoryLoadsAreNotTreatedAsPointerArguments() throws Exception {
		// Writable .data holds raw hostname bytes; read-only .rodata holds a pointer to a
		// second raw hostname whose terminator is the last byte of the block, and a third raw
		// hostname that runs to the end of the block with no terminator at all; the adjacent
		// block begins with a NUL byte. None is left as a defined string (auto-analysis
		// defines one at the lea target that spans the block boundary, so it is cleared), so
		// each can only surface through argument resolution.
		MemoryBlock data = builder.createMemory(".data", "0x403000", 0x100);
		builder.setWrite(data, true);
		builder.setBytes("0x403000", ascii("db-shadow.example.test") + " 00");
		builder.setBytes("0x402100", "e8 21 40 00 00 00 00 00");
		builder.setBytes("0x4021e8", ascii("db-standby.example.test") + " 00");
		builder.createMemory(".rodata2", "0x404000", 0x10);
		builder.setBytes("0x404000", ascii("db.example.test!"));
		builder.createMemory(".rodata3", "0x404010", 0x10);

		// loader at 0x401040:
		//   mov rdi,[rip+X] -> 0x403000        48 8b 3d disp32   (7 bytes, ends 0x401047)
		//   call 0x401100                      e8 rel32          (5 bytes, ends 0x40104c)
		//   mov rdi,[rip+Y] -> 0x402100        48 8b 3d disp32   (7 bytes, ends 0x401053)
		//   call 0x401100                      e8 rel32          (5 bytes, ends 0x401058)
		//   lea rdi,[rip+Z] -> 0x404000        48 8d 3d disp32   (7 bytes, ends 0x40105f)
		//   call 0x401100                      e8 rel32          (5 bytes, ends 0x401064)
		//   ret                                c3
		String code = "48 8b 3d " + le32(0x403000 - 0x401047) + "e8 " + le32(0x401100 - 0x40104c) +
			"48 8b 3d " + le32(0x402100 - 0x401053) + "e8 " + le32(0x401100 - 0x401058) +
			"48 8d 3d " + le32(0x404000 - 0x40105f) + "e8 " + le32(0x401100 - 0x401064) + "c3";
		builder.setBytes("0x401040", code, true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "loader");
		builder.clearCodeUnits("0x404000", "0x40401f", false);
		assertNull(program.getListing().getDefinedDataContaining(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x404000)));

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		List<String> values = r.endpoints().stream().map(Endpoint::value).toList();

		// The load from writable memory is not a constant: the call site says so and the
		// .data string (which Ghidra defines because the load references it) is only linked
		// heuristically, never as a resolved argument.
		ApiCallSite first = r.apiCallSites().stream().filter(
			c -> c.address().equals("00401047")).findFirst().orElseThrow();
		assertTrue(first.notes().toString(),
			first.notes().contains("endpoint argument not a constant"));
		for (Endpoint e : r.endpoints()) {
			if (e.value().equals("db-shadow.example.test")) {
				assertTrue(e.notes().toString(),
					e.notes().stream().noneMatch(n -> n.startsWith("passed as argument")));
				assertTrue(e.nearestNetworkCall().heuristic());
			}
			assertFalse(e.value(), e.value().contains("403000"));
		}

		Endpoint standby = r.endpoints().stream().filter(
			e -> e.value().equals("db-standby.example.test")).findFirst().orElseThrow(
				() -> new AssertionError("pointer loaded from read-only memory not resolved: " +
					values));
		assertEquals(EndpointKind.HOSTNAME, standby.kind());
		assertEquals("004021e8", standby.address());
		assertEquals(List.of("loader"), standby.referencingFunctions());
		assertTrue(standby.notes().toString(),
			standby.notes().contains("passed as argument 0 to PQconnectdb at 00401053"));
		assertNotNull(standby.nearestNetworkCall());
		assertEquals("PQconnectdb", standby.nearestNetworkCall().api());
		assertEquals("00401053", standby.nearestNetworkCall().address());

		// Bytes that run to the end of the block without a terminator are not a string, even
		// when the next initialized block supplies a NUL.
		for (Endpoint e : r.endpoints()) {
			assertFalse(e.value(), e.value().startsWith("db.example.test"));
			assertNotEquals("00404000", e.address());
		}
		ApiCallSite unterminated = r.apiCallSites().stream().filter(
			c -> c.address().equals("0040105f")).findFirst().orElseThrow();
		assertTrue(unterminated.notes().toString(),
			unterminated.notes().contains("endpoint argument not a constant"));
	}

	@Test
	public void testNamespacedFunctionsGetPlateCommentsAndQualifiedNames() throws Exception {
		Namespace svc = builder.createNamespace("svc");
		Function main = program.getFunctionManager().getFunctionAt(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000));
		int tx = program.startTransaction("namespace");
		try {
			main.setParentNamespace(svc);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals("svc::main", main.getName(true));

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		Endpoint conn = find(r, EndpointKind.CONNECTION_STRING);
		assertEquals(List.of("svc::main"), conn.referencingFunctions());
		assertEquals("svc::main", conn.nearestNetworkCall().function());

		String plate = program.getListing().getComment(CommentType.PLATE, main.getEntryPoint());
		assertNotNull("plate comment missing on namespaced function", plate);
		assertTrue(plate, plate.contains("references connection_string"));
		assertFalse(plate, plate.contains("Tr0ub4dor"));
	}

	@Test
	public void testSharedEndpointLinksToFirstCallSiteByAddress() throws Exception {
		// second at 0x401040 passes the same connection string to PQconnectdb.
		String code = "48 8d 3d " + le32(0x402000 - 0x401047) + "e8 " + le32(0x401100 - 0x40104c) +
			"c3";
		builder.setBytes("0x401040", code, true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "second");

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		Endpoint conn = find(r, EndpointKind.CONNECTION_STRING);
		assertEquals(List.of("main", "second"), conn.referencingFunctions());
		assertEquals("00401007", conn.nearestNetworkCall().address());
		assertEquals("main", conn.nearestNetworkCall().function());
		assertFalse(conn.nearestNetworkCall().heuristic());
		assertTrue(conn.notes().toString(), conn.notes().contains(
			"passed to 2 call sites; the link shows the first by address"));
		assertTrue(conn.notes().toString(),
			conn.notes().contains("passed as argument 0 to PQconnectdb at 00401047"));
	}

	@Test
	public void testCustomApiTableNotesAppearOnCallSites() throws Exception {
		File table = createTempFile("apis", ".json");
		Files.writeString(table.toPath(), "{\"apis\":[{\"name\":\"PQconnectdb\"," +
			"\"category\":\"database\",\"protocolHint\":\"postgresql\",\"hostArgument\":0," +
			"\"notes\":\"vendor wrapper; see sustainment runbook\"}]}");
		ScanResult r = runAnalyzer(ScanOptions.defaults().withApiTablePath(table.getPath()));
		assertTrue(r.warnings().toString(), r.warnings().isEmpty());
		List<String> apis = r.apiCallSites().stream().map(ApiCallSite::api).toList();
		assertEquals(List.of("PQconnectdb"), apis);
		assertTrue(r.apiCallSites().get(0).notes().toString(),
			r.apiCallSites().get(0).notes().contains("vendor wrapper; see sustainment runbook"));
	}

	@Test
	public void testStoredResultIsInvalidatedByOptionsAndProgramChanges() throws Exception {
		ScanOptions defaults = ScanOptions.defaults();
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));
		assertNull(ProgramAnnotator.storedResultJson(program, defaults.withMinStringLength(8)));
		assertNull(ProgramAnnotator.storedResultJson(program,
			defaults.withCategories(true, true, true, true, false)));

		File table = createTempFile("apis", ".json");
		Files.writeString(table.toPath(), "{\"apis\":[{\"name\":\"PQconnectdb\"," +
			"\"category\":\"database\",\"protocolHint\":\"postgresql\",\"hostArgument\":0}]}");
		ScanOptions custom = defaults.withApiTablePath(table.getPath());
		assertNull(ProgramAnnotator.storedResultJson(program, custom));
		runAnalyzer(custom);
		assertNotNull(ProgramAnnotator.storedResultJson(program, custom));
		Files.writeString(table.toPath(), "{\"apis\":[{\"name\":\"PQconnectdb\"," +
			"\"category\":\"database\",\"protocolHint\":\"postgresql\",\"hostArgument\":0," +
			"\"notes\":\"edited\"}]}");
		assertNull("edited table content must invalidate the stored result",
			ProgramAnnotator.storedResultJson(program, custom));

		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));
		builder.setBytes("0x401040", "c3", true);
		builder.createFunction("0x401040");
		assertNull("new function must invalidate the stored result",
			ProgramAnnotator.storedResultJson(program, defaults));
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));
	}

	@Test
	public void testStoredResultIsInvalidatedByInPlaceEdits() throws Exception {
		ScanOptions defaults = ScanOptions.defaults();
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));
		int functions = program.getFunctionManager().getFunctionCount();
		long instructions = program.getListing().getNumInstructions();
		long data = program.getListing().getNumDefinedData();

		// Same-length patch of one byte inside the defined URL string.
		builder.setBytes("0x402087", "7a");
		assertNull("patched string bytes must invalidate the stored result",
			ProgramAnnotator.storedResultJson(program, defaults));
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));

		Address mainAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
		int tx = program.startTransaction("rename");
		try {
			program.getFunctionManager().getFunctionAt(mainAddr).setName("service_entry",
				SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertNull("renamed function must invalidate the stored result",
			ProgramAnnotator.storedResultJson(program, defaults));
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));

		Address from = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401100);
		Address to = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000);
		tx = program.startTransaction("reference");
		try {
			program.getReferenceManager().addMemoryReference(from, to, RefType.DATA,
				SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertNull("added reference must invalidate the stored result",
			ProgramAnnotator.storedResultJson(program, defaults));
		runAnalyzer(defaults);
		assertNotNull(ProgramAnnotator.storedResultJson(program, defaults));

		assertEquals(functions, program.getFunctionManager().getFunctionCount());
		assertEquals(instructions, program.getListing().getNumInstructions());
		assertEquals(data, program.getListing().getNumDefinedData());
	}

	@Test
	public void testUnresolvedOrUnlistedOptionSelectorDoesNotReadPointerArgument() throws Exception {
		builder.setBytes("0x402100", ascii("http://ignored.example.test/x") + " 00");

		// setter at 0x401040:
		//   mov esi,0x2a (not in the table)     be 2a 00 00 00    (5 bytes, ends 0x401045)
		//   lea rdx,[rip+X] -> 0x402100         48 8d 15 disp32   (7 bytes, ends 0x40104c)
		//   call 0x401110                       e8 rel32          (5 bytes, ends 0x401051)
		//   mov esi,edi (selector from caller)  89 fe             (2 bytes, ends 0x401053)
		//   lea rdx,[rip+Y] -> 0x402100         48 8d 15 disp32   (7 bytes, ends 0x40105a)
		//   call 0x401110                       e8 rel32          (5 bytes, ends 0x40105f)
		//   ret                                 c3
		String code = "be 2a 00 00 00 " + "48 8d 15 " + le32(0x402100 - 0x40104c) + "e8 " +
			le32(0x401110 - 0x401051) + "89 fe " + "48 8d 15 " + le32(0x402100 - 0x40105a) +
			"e8 " + le32(0x401110 - 0x40105f) + "c3";
		builder.setBytes("0x401040", code, true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "setter");

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		ApiCallSite unlisted = r.apiCallSites().stream().filter(
			c -> c.address().equals("0040104c")).findFirst().orElseThrow();
		assertTrue(unlisted.notes().toString(),
			unlisted.notes().contains("option 42 not in API table"));
		ApiCallSite unresolved = r.apiCallSites().stream().filter(
			c -> c.address().equals("0040105a")).findFirst().orElseThrow();
		assertTrue(unresolved.notes().toString(),
			unresolved.notes().contains("option selector not a constant"));
		for (ApiCallSite c : List.of(unlisted, unresolved)) {
			assertFalse(c.notes().toString(),
				c.notes().contains("endpoint argument not a constant"));
		}
		// Neither call is treated as passing the pointer argument: if the string surfaces at
		// all it is through the string scan, linked only heuristically.
		for (Endpoint e : r.endpoints()) {
			assertTrue(e.notes().toString(), e.notes().stream().noneMatch(
				n -> n.contains("to curl_easy_setopt at 0040104c") ||
					n.contains("to curl_easy_setopt at 0040105a")));
			if (e.value().contains("ignored.example.test")) {
				assertTrue(e.notes().toString(),
					e.notes().stream().noneMatch(n -> n.startsWith("passed as argument")));
				assertTrue(e.toString(),
					e.nearestNetworkCall() == null || e.nearestNetworkCall().heuristic());
			}
		}
		assertTrue(r.findings().stream().noneMatch(
			f -> f.rule().equals(Rule.RUNTIME_SUPPLIED_ENDPOINT.jsonName()) &&
				f.function().equals("setter")));
		// The genuine CURLOPT_URL call in main is unaffected.
		Endpoint url = r.endpoints().stream().filter(e -> e.value().equals(URL)).findFirst()
				.orElseThrow();
		assertEquals(Confidence.HIGH, url.confidence());
		assertEquals("00401018", url.nearestNetworkCall().address());
		assertFalse(url.nearestNetworkCall().heuristic());
	}

	@Test
	public void testAddressTakenApiReferenceIsNotTreatedAsInvocation() throws Exception {
		builder.setBytes("0x402100", ascii("http://indirect.example.test/x") + " 00");

		// loader at 0x401040 sets up what look like curl_easy_setopt arguments, then only
		// takes the address of curl_easy_setopt and stores the pointer for a later caller:
		//   mov esi,0x2712 (CURLOPT_URL)       be 12 27 00 00    (5 bytes, ends 0x401045)
		//   lea rdx,[rip+X] -> 0x402100        48 8d 15 disp32   (7 bytes, ends 0x40104c)
		//   lea rax,[rip+Y] -> 0x401110        48 8d 05 disp32   (7 bytes, ends 0x401053)
		//   mov [rbx],rax                      48 89 03          (3 bytes, ends 0x401056)
		//   ret                                c3
		String code = "be 12 27 00 00 " + "48 8d 15 " + le32(0x402100 - 0x40104c) + "48 8d 05 " +
			le32(0x401110 - 0x401053) + "48 89 03 " + "c3";
		builder.setBytes("0x401040", code, true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "loader");
		builder.createMemoryReference("0x40104c", "0x401110", RefType.DATA, SourceType.ANALYSIS);

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		ApiCallSite taken = r.apiCallSites().stream().filter(
			c -> c.address().equals("0040104c")).findFirst().orElseThrow();
		assertEquals("curl_easy_setopt", taken.api());
		assertEquals("loader", taken.function());
		assertTrue(taken.notes().toString(),
			taken.notes().contains("address taken; call is indirect; arguments not recovered"));
		assertTrue(taken.notes().toString(), taken.notes().stream().noneMatch(
			n -> n.startsWith("option ") || n.contains("argument not a constant")));
		// The pointer load is never treated as passing the URL: if the string surfaces at all
		// it is through the string scan, linked only heuristically.
		for (Endpoint e : r.endpoints()) {
			assertTrue(e.notes().toString(), e.notes().stream().noneMatch(
				n -> n.contains("to curl_easy_setopt at 0040104c")));
			if (e.value().contains("indirect.example.test")) {
				assertTrue(e.notes().toString(),
					e.notes().stream().noneMatch(n -> n.startsWith("passed as argument")));
				assertTrue(e.toString(),
					e.nearestNetworkCall() == null || e.nearestNetworkCall().heuristic());
			}
		}
		assertTrue(r.findings().toString(), r.findings().stream().noneMatch(
			f -> f.function().equals("loader") &&
				(f.rule().equals(Rule.RUNTIME_SUPPLIED_ENDPOINT.jsonName()) ||
					f.rule().equals(Rule.TLS_VERIFICATION_DISABLED.jsonName()))));
		// The genuine CURLOPT_URL call in main is unaffected.
		Endpoint url = r.endpoints().stream().filter(e -> e.value().equals(URL)).findFirst()
				.orElseThrow();
		assertEquals(Confidence.HIGH, url.confidence());
		assertEquals("00401018", url.nearestNetworkCall().address());
		assertFalse(url.nearestNetworkCall().heuristic());
	}

	@Test
	public void testCallThroughImportSlotIsTreatedAsInvocation() throws Exception {
		builder.setBytes("0x402100", ascii("http://iat.example.test/wfs") + " 00");
		// Import-table style slot holding the address of curl_easy_setopt.
		builder.createMemory(".idata", "0x403000", 0x10);
		builder.setBytes("0x403000", "10 11 40 00 00 00 00 00");
		builder.applyDataType("0x403000", new PointerDataType());

		// caller at 0x401040 invokes curl_easy_setopt through the slot:
		//   mov esi,0x2712 (CURLOPT_URL)       be 12 27 00 00    (5 bytes, ends 0x401045)
		//   lea rdx,[rip+X] -> 0x402100        48 8d 15 disp32   (7 bytes, ends 0x40104c)
		//   call qword ptr [rip+Y] -> 0x403000 ff 15 disp32      (6 bytes, ends 0x401052)
		//   ret                                c3
		String code = "be 12 27 00 00 " + "48 8d 15 " + le32(0x402100 - 0x40104c) + "ff 15 " +
			le32(0x403000 - 0x401052) + "c3";
		builder.setBytes("0x401040", code, true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "caller");

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		ApiCallSite site = r.apiCallSites().stream().filter(
			c -> c.address().equals("0040104c")).findFirst().orElseThrow();
		assertEquals("curl_easy_setopt", site.api());
		assertEquals("caller", site.function());
		assertTrue(site.notes().toString(), site.notes().contains("indirect call"));
		assertTrue(site.notes().toString(), site.notes().contains("option CURLOPT_URL"));
		assertTrue(site.notes().toString(),
			site.notes().stream().noneMatch(n -> n.startsWith("address taken")));
		Endpoint url = r.endpoints().stream().filter(
			e -> e.value().equals("http://iat.example.test/wfs")).findFirst().orElseThrow();
		assertEquals(Confidence.HIGH, url.confidence());
		assertTrue(url.notes().toString(),
			url.notes().contains("passed as argument 2 to curl_easy_setopt at 0040104c"));
		assertEquals("0040104c", url.nearestNetworkCall().address());
		assertEquals("caller", url.nearestNetworkCall().function());
		assertFalse(url.nearestNetworkCall().heuristic());
	}

	@Test
	public void testProgramNameIsRedacted() throws Exception {
		ProgramBuilder named = new ProgramBuilder("svc password=Hunter22Secret", ProgramBuilder._X64,
			"gcc", this);
		try {
			named.createMemory(".text", "0x401000", 0x10);
			named.setBytes("0x401000", "c3", true);
			named.createFunction("0x401000");
			ProgramDB p = named.getProgram();
			int tx = p.startTransaction("scan");
			ScanResult r;
			try {
				r = new DependencyScanner(p, ScanOptions.defaults(), TaskMonitor.DUMMY).scan();
			}
			finally {
				p.endTransaction(tx, true);
			}
			assertEquals("svc password=" + Redactor.MASK, r.program().name());
			assertFalse(DependencyReportWriter.toJson(r).contains("Hunter22Secret"));
			assertFalse(DependencyReportWriter.toMarkdown(r).contains("Hunter22Secret"));
		}
		finally {
			named.dispose();
		}
	}

	@Test
	public void testSockaddrPortHeuristicIsLimitedToSockaddrCallers() throws Exception {
		builder.setBytes("0x401120", "c3");
		builder.disassemble("0x401120", 1);
		builder.createFunction("0x401120");
		builder.createLabel("0x401120", "connect");

		// open_socket at 0x401040: mov word ptr [rsp+2],0x901f (htons(8080)); call connect; ret
		builder.setBytes("0x401040", "66 c7 44 24 02 1f 90 " + "e8 " + le32(0x401120 - 0x40104c) +
			"c3", true);
		builder.createFunction("0x401040");
		builder.createLabel("0x401040", "open_socket");
		// wide_store at 0x401060: mov dword ptr [rsp+4],0x901f; call connect; ret
		builder.setBytes("0x401060", "c7 44 24 04 1f 90 00 00 " + "e8 " +
			le32(0x401120 - 0x40106d) + "c3", true);
		builder.createFunction("0x401060");
		builder.createLabel("0x401060", "wide_store");
		// not_socket at 0x401080: same 16-bit store, but the callee takes no sockaddr
		builder.setBytes("0x401080", "66 c7 44 24 02 1f 90 " + "e8 " + le32(0x401100 - 0x40108c) +
			"c3", true);
		builder.createFunction("0x401080");
		builder.createLabel("0x401080", "not_socket");

		ScanResult r = runAnalyzer(ScanOptions.defaults());
		List<Endpoint> ports = r.endpoints().stream().filter(e -> e.kind() == EndpointKind.PORT)
				.toList();
		assertEquals(ports.toString(), 1, ports.size());
		Endpoint port = ports.get(0);
		assertEquals("8080", port.value());
		assertEquals("00401040", port.address());
		assertEquals(List.of("open_socket"), port.referencingFunctions());
		assertEquals(Confidence.LOW, port.confidence());
		assertTrue(port.notes().toString(),
			port.notes().stream().anyMatch(n -> n.contains("sockaddr heuristic") &&
				n.contains("connect")));
		assertNotNull(port.nearestNetworkCall());
		assertEquals("connect", port.nearestNetworkCall().api());

		ScanResult off = runAnalyzer(ScanOptions.defaults().withPortHeuristics(false));
		assertTrue(off.endpoints().stream().noneMatch(e -> e.kind() == EndpointKind.PORT));
	}

	private static String ascii(String s) {
		StringBuilder sb = new StringBuilder();
		for (byte b : s.getBytes(StandardCharsets.US_ASCII)) {
			sb.append(String.format("%02x ", b));
		}
		return sb.toString().trim();
	}

	private static Endpoint find(ScanResult r, EndpointKind kind) {
		return r.endpoints().stream().filter(e -> e.kind() == kind).findFirst().orElseThrow(
			() -> new AssertionError("no endpoint of kind " + kind + " in " + r.endpoints()));
	}
}
