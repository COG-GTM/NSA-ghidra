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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;

/**
 * Identifies the inputs of a scan: the scan-affecting options, the content of the API table that
 * was actually used, and the program state the scan reads. That state is digested rather than
 * counted, so an in-place edit that keeps the aggregate shape of the program (patched string
 * bytes, a renamed function, a retyped data unit, an added or removed reference) still
 * invalidates the stored result. A stored result is only reused when the fingerprint of the
 * requested scan equals the one recorded with the result.
 */
public final class ScanFingerprint {

	private static final String VERSION = "2";
	private static final int CHUNK = 64 * 1024;

	private ScanFingerprint() {
	}

	public static String compute(Program program, ScanOptions options) {
		ApiTable table = ApiTable.loadOrDefault(options.apiTablePath(), new ArrayList<>());
		return compute(program, options, table);
	}

	static String compute(Program program, ScanOptions options, ApiTable table) {
		List<String> parts = new ArrayList<>();
		parts.add("v" + VERSION);
		parts.add("options=" + options.endpoints() + "," + options.connectionStrings() + "," +
			options.protocolHints() + "," + options.apiCallSites() + "," + options.findings() + "," +
			options.portHeuristics() + "," + options.minStringLength());
		parts.add("apiTable=" + table.getContentHash());
		String sha = program.getExecutableSHA256();
		parts.add("executable=" + (sha == null ? "" : sha));
		parts.add("language=" + program.getLanguageID() + "/" + program.getCompilerSpec()
				.getCompilerSpecID());
		parts.add("memory=" + memoryDigest(program));
		parts.add("code=" + codeDigest(program));
		parts.add("data=" + dataDigest(program));
		parts.add("symbols=" + symbolDigest(program));
		parts.add("references=" + referenceDigest(program));
		return ApiTable.sha256(String.join("|", parts).getBytes(StandardCharsets.UTF_8));
	}

	/** Block layout and permissions plus the bytes of every initialized block. */
	private static String memoryDigest(Program program) {
		Digest d = new Digest();
		byte[] buf = new byte[CHUNK];
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			d.text(b.getName()).addr(b.getStart()).addr(b.getEnd())
					.text((b.isInitialized() ? "i" : "u") + (b.isWrite() ? "w" : "r") +
						(b.isExecute() ? "x" : "-"));
			if (!b.isInitialized()) {
				continue;
			}
			try (InputStream in = b.getData()) {
				if (in == null) {
					continue;
				}
				int n;
				while ((n = in.read(buf)) > 0) {
					d.bytes(buf, n);
				}
			}
			catch (IOException | RuntimeException e) {
				Msg.debug(ScanFingerprint.class, "Block bytes unavailable for fingerprint: " +
					b.getName(), e);
				d.text("unreadable");
			}
		}
		return d.hex();
	}

	/** Function entry points, reported names, bodies and thunk targets, plus instruction bounds. */
	private static String codeDigest(Program program) {
		Digest d = new Digest();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			d.addr(f.getEntryPoint()).text(f.getName(true)).addr(f.getBody().getMinAddress())
					.addr(f.getBody().getMaxAddress()).text(Long.toString(f.getBody().getNumAddresses()));
			Function thunked = f.getThunkedFunction(false);
			if (thunked != null) {
				d.addr(thunked.getEntryPoint());
			}
			if (f.isExternal()) {
				d.text("external");
			}
		}
		Listing listing = program.getListing();
		for (Instruction instr : listing.getInstructions(true)) {
			d.addr(instr.getMinAddress()).text(Integer.toString(instr.getLength()));
		}
		return d.hex();
	}

	/** Every defined data unit with its address, type and length. */
	private static String dataDigest(Program program) {
		Digest d = new Digest();
		for (Data data : program.getListing().getDefinedData(true)) {
			d.addr(data.getMinAddress()).text(data.getDataType().getName())
					.text(Integer.toString(data.getLength()));
		}
		return d.hex();
	}

	/** Non-dynamic symbols: address, qualified name and type. */
	private static String symbolDigest(Program program) {
		Digest d = new Digest();
		SymbolIterator it = program.getSymbolTable().getAllSymbols(false);
		while (it.hasNext()) {
			Symbol s = it.next();
			d.addr(s.getAddress()).text(s.getName(true)).text(s.getSymbolType().toString());
		}
		return d.hex();
	}

	/** Every memory reference: source, destination, type and operand. */
	private static String referenceDigest(Program program) {
		Digest d = new Digest();
		Address min = program.getMemory().getMinAddress();
		if (min == null) {
			return d.hex();
		}
		ReferenceIterator it = program.getReferenceManager().getReferenceIterator(min);
		while (it.hasNext()) {
			Reference r = it.next();
			d.addr(r.getFromAddress()).addr(r.getToAddress()).text(r.getReferenceType().getName())
					.text(Integer.toString(r.getOperandIndex()));
		}
		return d.hex();
	}

	private static final class Digest {
		private final MessageDigest md;

		Digest() {
			try {
				md = MessageDigest.getInstance("SHA-256");
			}
			catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException("SHA-256 unavailable", e);
			}
		}

		Digest text(String s) {
			md.update(s.getBytes(StandardCharsets.UTF_8));
			md.update((byte) 0);
			return this;
		}

		Digest addr(Address a) {
			return text(a == null ? "" : a.toString(true));
		}

		Digest bytes(byte[] b, int n) {
			md.update(b, 0, n);
			return this;
		}

		String hex() {
			return HexFormat.of().formatHex(md.digest());
		}
	}
}
