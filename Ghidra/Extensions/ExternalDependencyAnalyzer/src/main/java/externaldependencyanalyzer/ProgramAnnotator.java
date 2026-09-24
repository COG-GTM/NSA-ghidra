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

import java.util.*;

import externaldependencyanalyzer.DependencyModel.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Writes scan results into the program: bookmarks, comments and a property summary. All text
 * comes from the already-redacted {@link ScanResult}.
 */
public final class ProgramAnnotator {

	public static final String BOOKMARK_CATEGORY = "External Dependency";
	public static final String PROPERTY_LIST = "External Dependency Summary";
	public static final String RESULT_JSON_PROPERTY = "Result JSON";
	public static final String RESULT_JSON_STATUS_PROPERTY = "Result JSON status";
	public static final String COMMENT_PREFIX = "[External Dependency]";

	private static final int MAX_STORED_JSON = 8 * 1024 * 1024;

	private ProgramAnnotator() {
	}

	public static void annotate(Program program, ScanResult result, ScanOptions options,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		BookmarkManager bookmarks = program.getBookmarkManager();

		if (options.writeBookmarks()) {
			bookmarks.removeBookmarks(BookmarkType.NOTE, BOOKMARK_CATEGORY, monitor);
			bookmarks.removeBookmarks(BookmarkType.WARNING, BOOKMARK_CATEGORY, monitor);
			bookmarks.removeBookmarks(BookmarkType.INFO, BOOKMARK_CATEGORY, monitor);
		}
		if (options.writeComments()) {
			removeAnalyzerComments(program, CommentType.EOL, monitor);
			removeAnalyzerComments(program, CommentType.PLATE, monitor);
		}

		Map<String, List<String>> byFunction = new TreeMap<>();
		for (Endpoint e : result.endpoints()) {
			monitor.checkCancelled();
			Address addr = parse(program, e.address());
			if (addr == null) {
				continue;
			}
			String text = e.kind().jsonName() + ": " + e.value() +
				(e.protocolHint().isEmpty() ? "" : " [" + e.protocolHint() + "]") +
				" (" + e.confidence().jsonName() + ")" +
				(e.nearestNetworkCall() == null ? ""
						: " -> " + e.nearestNetworkCall().api() + "@" +
							e.nearestNetworkCall().address() +
							(e.nearestNetworkCall().heuristic() ? " (heuristic)" : ""));
			if (options.writeBookmarks()) {
				bookmarks.setBookmark(addr, BookmarkType.NOTE, BOOKMARK_CATEGORY, text);
			}
			if (options.writeComments()) {
				setComment(listing, addr, CommentType.EOL, text);
				for (String fn : e.referencingFunctions()) {
					byFunction.computeIfAbsent(fn, k -> new ArrayList<>())
							.add("references " + e.kind().jsonName() + ": " + e.value() + " @ " +
								e.address());
				}
			}
		}
		if (options.writeComments()) {
			SymbolTable symbols = program.getSymbolTable();
			for (Map.Entry<String, List<String>> fe : byFunction.entrySet()) {
				monitor.checkCancelled();
				Function fn = findFunction(program, symbols, fe.getKey());
				if (fn == null) {
					continue;
				}
				for (String line : fe.getValue()) {
					setComment(listing, fn.getEntryPoint(), CommentType.PLATE, line);
				}
			}
		}

		for (ApiCallSite c : result.apiCallSites()) {
			monitor.checkCancelled();
			Address addr = parse(program, c.address());
			if (addr == null) {
				continue;
			}
			String text = "call " + c.api() + " [" + c.category() + "]" +
				(c.notes().isEmpty() ? "" : " " + String.join("; ", c.notes()));
			if (options.writeBookmarks()) {
				bookmarks.setBookmark(addr, BookmarkType.INFO, BOOKMARK_CATEGORY, text);
			}
			if (options.writeComments()) {
				setComment(listing, addr, CommentType.EOL, text);
			}
		}

		for (Finding f : result.findings()) {
			monitor.checkCancelled();
			Address addr = parse(program, f.address());
			if (addr == null) {
				continue;
			}
			String text = f.severity().jsonName() + " " + f.rule() + ": " + f.detail();
			if (options.writeBookmarks()) {
				bookmarks.setBookmark(addr, BookmarkType.WARNING, BOOKMARK_CATEGORY, text);
			}
			if (options.writeComments()) {
				setComment(listing, addr, CommentType.PLATE, text);
			}
		}

		writeSummary(program, result);
	}

	private static Function findFunction(Program program, SymbolTable symbols, String name) {
		FunctionManager fm = program.getFunctionManager();
		Function fn = null;
		for (Symbol s : symbols.getSymbols(name)) {
			Function f = fm.getFunctionAt(s.getAddress());
			if (f != null &&
				(fn == null || f.getEntryPoint().compareTo(fn.getEntryPoint()) < 0)) {
				fn = f;
			}
		}
		return fn;
	}

	/** Removes every comment line written by a previous run, keeping analyst-authored lines. */
	private static void removeAnalyzerComments(Program program, CommentType type,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		AddressIterator it = listing.getCommentAddressIterator(type, program.getMemory(), true);
		List<Address> touched = new ArrayList<>();
		while (it.hasNext()) {
			monitor.checkCancelled();
			Address a = it.next();
			String c = listing.getComment(type, a);
			if (c != null && c.contains(COMMENT_PREFIX)) {
				touched.add(a);
			}
		}
		for (Address a : touched) {
			StringBuilder sb = new StringBuilder();
			for (String l : listing.getComment(type, a).split("\n")) {
				if (!l.startsWith(COMMENT_PREFIX)) {
					if (sb.length() > 0) {
						sb.append('\n');
					}
					sb.append(l);
				}
			}
			listing.setComment(a, type, sb.length() == 0 ? null : sb.toString());
		}
	}

	private static void setComment(Listing listing, Address addr, CommentType type,
			String text) {
		String line = COMMENT_PREFIX + " " + text;
		String existing = listing.getComment(type, addr);
		if (existing == null || existing.isEmpty()) {
			listing.setComment(addr, type, line);
			return;
		}
		if (Arrays.asList(existing.split("\n")).contains(line)) {
			return;
		}
		listing.setComment(addr, type, existing + "\n" + line);
	}

	private static void writeSummary(Program program, ScanResult result) {
		Options opts = program.getOptions(PROPERTY_LIST);
		for (String name : opts.getOptionNames()) {
			if (name.startsWith("Endpoints by kind.") || name.startsWith("Findings by severity.") ||
				name.startsWith("API call sites by category.")) {
				opts.removeOption(name);
			}
		}
		opts.setInt("Endpoint count", result.endpoints().size());
		opts.setInt("API call site count", result.apiCallSites().size());
		opts.setInt("Finding count", result.findings().size());
		for (Map.Entry<String, Integer> e : result.countsByKind().entrySet()) {
			opts.setInt("Endpoints by kind." + e.getKey(), e.getValue());
		}
		for (Map.Entry<String, Integer> e : result.countsBySeverity().entrySet()) {
			opts.setInt("Findings by severity." + e.getKey(), e.getValue());
		}
		for (Map.Entry<String, Integer> e : result.countsByApiCategory().entrySet()) {
			opts.setInt("API call sites by category." + e.getKey(), e.getValue());
		}
		String json = DependencyReportWriter.toJson(result);
		if (json.length() <= MAX_STORED_JSON) {
			opts.setString(RESULT_JSON_PROPERTY, json);
			if (opts.contains(RESULT_JSON_STATUS_PROPERTY)) {
				opts.removeOption(RESULT_JSON_STATUS_PROPERTY);
			}
		}
		else {
			if (opts.contains(RESULT_JSON_PROPERTY)) {
				opts.removeOption(RESULT_JSON_PROPERTY);
			}
			opts.setString(RESULT_JSON_STATUS_PROPERTY, "not stored: result exceeds size limit");
		}
	}

	/** Returns the stored JSON from a previous analyzer run, or null. */
	public static String storedResultJson(Program program) {
		Options opts = program.getOptions(PROPERTY_LIST);
		if (!opts.contains(RESULT_JSON_PROPERTY)) {
			return null;
		}
		String s = opts.getString(RESULT_JSON_PROPERTY, null);
		return s == null || s.isBlank() ? null : s;
	}

	private static Address parse(Program program, String s) {
		try {
			return program.getAddressFactory().getAddress(s);
		}
		catch (RuntimeException e) {
			return null;
		}
	}
}
