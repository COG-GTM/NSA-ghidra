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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;

/**
 * Table of network and authentication APIs, loaded from
 * {@code data/external_dependency_apis.json} in this module or from an analyst-supplied file.
 */
public final class ApiTable {

	public static final String DEFAULT_FILE_NAME = "external_dependency_apis.json";

	private static final int MAX_FILE_BYTES = 4 * 1024 * 1024;
	private static final int MAX_NOTES_LENGTH = 256;
	private static final List<String> DECORATIONS = List.of("imp_", "thunk_");
	private static final Pattern DUPLICATE_SUFFIX = Pattern.compile("_\\d+$");

	/** One recognised API. Argument indices are zero-based; -1 means "not applicable". */
	public record ApiEntry(String name, String category, String protocolHint, String notes,
			int hostArgument, int portArgument, int optionArgument, int verifyModeArgument,
			Map<Long, String> optionValues, boolean sockaddr) {

		public boolean hasHostArgument() {
			return hostArgument >= 0;
		}

		public boolean hasPortArgument() {
			return portArgument >= 0;
		}

		public boolean hasOptionArgument() {
			return optionArgument >= 0;
		}

		public boolean hasVerifyModeArgument() {
			return verifyModeArgument >= 0;
		}
	}

	private final Map<String, ApiEntry> byName = new TreeMap<>();
	private final String source;
	private final String contentHash;

	private ApiTable(String source, String contentHash) {
		this.source = source;
		this.contentHash = contentHash;
	}

	public String getSource() {
		return source;
	}

	/** SHA-256 of the JSON the table was loaded from; identical tables give identical hashes. */
	public String getContentHash() {
		return contentHash;
	}

	public Collection<ApiEntry> entries() {
		return Collections.unmodifiableCollection(byName.values());
	}

	public int size() {
		return byName.size();
	}

	/**
	 * Looks up a symbol name, tolerating leading underscores, {@code A}/{@code W} suffixes,
	 * PLT/thunk decorations and the {@code _N} suffix Ghidra appends to duplicate symbols.
	 */
	public ApiEntry lookup(String symbolName) {
		if (symbolName == null) {
			return null;
		}
		String n = normalize(symbolName);
		ApiEntry e = lookupWithCharsetSuffix(n);
		if (e != null) {
			return e;
		}
		Matcher dup = DUPLICATE_SUFFIX.matcher(n);
		if (dup.find() && dup.start() > 0) {
			return lookupWithCharsetSuffix(n.substring(0, dup.start()));
		}
		return null;
	}

	private ApiEntry lookupWithCharsetSuffix(String n) {
		ApiEntry e = byName.get(n);
		if (e != null) {
			return e;
		}
		if (n.length() > 1 && (n.endsWith("A") || n.endsWith("W"))) {
			return byName.get(n.substring(0, n.length() - 1));
		}
		return null;
	}

	static String normalize(String symbolName) {
		String n = symbolName;
		int at = n.indexOf('@');
		if (at > 0) {
			n = n.substring(0, at);
		}
		boolean changed = true;
		while (changed && n.length() > 1) {
			changed = false;
			while (n.startsWith("_") && n.length() > 1) {
				n = n.substring(1);
			}
			for (String prefix : DECORATIONS) {
				if (n.startsWith(prefix) && n.length() > prefix.length()) {
					n = n.substring(prefix.length());
					changed = true;
				}
			}
		}
		return n;
	}

	/** Loads the bundled table shipped with the module. */
	public static ApiTable loadDefault() throws IOException {
		ResourceFile f = Application.findDataFileInAnyModule(DEFAULT_FILE_NAME);
		if (f == null) {
			throw new IOException("Bundled API table not found");
		}
		try (InputStream in = f.getInputStream()) {
			return load(in, "module:" + DEFAULT_FILE_NAME);
		}
	}

	/**
	 * Loads an analyst-supplied table, falling back to the bundled table on any error. Details
	 * are written to the Ghidra log only.
	 */
	public static ApiTable loadOrDefault(String customPath, List<String> warnings) {
		if (customPath != null && !customPath.isBlank()) {
			File f = new File(customPath.trim());
			try {
				if (!f.isFile() || !f.canRead()) {
					throw new IOException("not a readable file");
				}
				try (InputStream in = new FileInputStream(f)) {
					return load(in, f.getAbsolutePath());
				}
			}
			catch (IOException | RuntimeException e) {
				Msg.warn(ApiTable.class, "Custom API table rejected: " + f + " (" + e.getMessage() + ")");
				warnings.add("Custom API table could not be loaded; bundled table used");
			}
		}
		try {
			return loadDefault();
		}
		catch (IOException e) {
			Msg.error(ApiTable.class, "Bundled API table could not be loaded", e);
			warnings.add("API table unavailable; API call sites were not scanned");
			return new ApiTable("none", "none");
		}
	}

	static InputStream readBounded(InputStream in) throws IOException {
		byte[] data = in.readNBytes(MAX_FILE_BYTES + 1);
		if (data.length > MAX_FILE_BYTES) {
			throw new IOException("file exceeds size limit");
		}
		return new ByteArrayInputStream(data);
	}

	public static String sha256(byte[] data) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			StringBuilder sb = new StringBuilder();
			for (byte b : md.digest(data)) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	static ApiTable load(InputStream in, String source) throws IOException {
		byte[] data = readBounded(in).readAllBytes();
		ApiTable table = new ApiTable(source, sha256(data));
		JsonElement root;
		try (Reader r = new InputStreamReader(new ByteArrayInputStream(data),
			StandardCharsets.UTF_8)) {
			root = JsonParser.parseReader(r);
		}
		catch (JsonParseException e) {
			throw new IOException("malformed JSON");
		}
		if (!root.isJsonObject() || !root.getAsJsonObject().has("apis") ||
			!root.getAsJsonObject().get("apis").isJsonArray()) {
			throw new IOException("missing \"apis\" array");
		}
		for (JsonElement el : root.getAsJsonObject().getAsJsonArray("apis")) {
			if (!el.isJsonObject()) {
				throw new IOException("api entry is not an object");
			}
			ApiEntry entry = parseEntry(el.getAsJsonObject());
			table.byName.put(entry.name(), entry);
		}
		return table;
	}

	private static ApiEntry parseEntry(JsonObject o) throws IOException {
		String name = str(o, "name", null);
		if (name == null || name.isBlank() || name.length() > 255 ||
			!name.matches("[A-Za-z0-9_@.$?]+")) {
			throw new IOException("invalid api name");
		}
		String category = str(o, "category", "other");
		if (!category.matches("[a-z0-9_-]{1,32}")) {
			throw new IOException("invalid category for " + name);
		}
		Map<Long, String> optionValues = new TreeMap<>();
		if (o.has("optionValues") && o.get("optionValues").isJsonObject()) {
			for (Map.Entry<String, JsonElement> kv : o.getAsJsonObject("optionValues")
					.entrySet()) {
				try {
					String optionName = kv.getValue().getAsString();
					if (!optionName.matches("[A-Za-z0-9_]{1,64}")) {
						throw new IOException("invalid option name for " + name);
					}
					optionValues.put(Long.parseLong(kv.getKey().trim()), optionName);
				}
				catch (NumberFormatException | IllegalStateException e) {
					throw new IOException("invalid optionValues for " + name);
				}
			}
		}
		String protocolHint = str(o, "protocolHint", "");
		if (!protocolHint.matches("[A-Za-z0-9_./+-]{0,64}")) {
			throw new IOException("invalid protocolHint for " + name);
		}
		return new ApiEntry(name, category, protocolHint, sanitizeNotes(str(o, "notes", "")),
			intArg(o, "hostArgument"), intArg(o, "portArgument"), intArg(o, "optionArgument"),
			intArg(o, "verifyModeArgument"), Collections.unmodifiableMap(optionValues),
			bool(o, "sockaddr"));
	}

	private static boolean bool(JsonObject o, String key) throws IOException {
		JsonElement e = o.get(key);
		if (e == null || e.isJsonNull()) {
			return false;
		}
		if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isBoolean()) {
			throw new IOException("field " + key + " is not a boolean");
		}
		return e.getAsBoolean();
	}

	private static String str(JsonObject o, String key, String dflt) throws IOException {
		JsonElement e = o.get(key);
		if (e == null || e.isJsonNull()) {
			return dflt;
		}
		if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
			throw new IOException("field " + key + " is not a string");
		}
		String s = e.getAsString();
		return s.length() > 1024 ? s.substring(0, 1024) : s;
	}

	/** Free-text metadata is analyst-controlled and flows into every output; keep it inert. */
	static String sanitizeNotes(String notes) {
		String s = notes.replaceAll("[\\p{Cntrl}]+", " ").trim();
		if (s.length() > MAX_NOTES_LENGTH) {
			s = s.substring(0, MAX_NOTES_LENGTH);
		}
		return Redactor.redact(s).text();
	}

	private static int intArg(JsonObject o, String key) throws IOException {
		JsonElement e = o.get(key);
		if (e == null || e.isJsonNull()) {
			return -1;
		}
		try {
			int v = e.getAsInt();
			if (v < 0 || v > 31) {
				throw new IOException("argument index out of range for " + key);
			}
			return v;
		}
		catch (NumberFormatException | IllegalStateException ex) {
			throw new IOException("invalid integer for " + key);
		}
	}
}
