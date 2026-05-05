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
//Detects common anti-debugging and anti-VM techniques in the currently-loaded
//program and annotates the listing in place.
//
//For every finding the script will:
//  - add a NOTE bookmark in category "AntiDebug" or "AntiVM",
//  - set a PRE comment on the offending instruction explaining the technique,
//  - rename the containing function with prefix "antidbg_" or "antivm_"
//    (preserving the original name as a suffix),
//  - apply a function tag of "AntiDebug" or "AntiVM" so the function tree can
//    be filtered by analysts.
//
//At the end of the run the script writes a Markdown report next to the
//imported program (or, if the executable path is unknown / unwritable, prints
//the report to the console).
//
//The detector covers the techniques most commonly seen in modern malware:
//  - Win32 IsDebuggerPresent / CheckRemoteDebuggerPresent
//  - Native NtQueryInformationProcess (ProcessDebugPort / ProcessDebugObjectHandle)
//  - Native NtSetInformationThread (ThreadHideFromDebugger)
//  - OutputDebugStringA/W debugger-probe pattern
//  - Manual SEH / VEH-based debugger detection (AddVectoredExceptionHandler,
//    SetUnhandledExceptionFilter)
//  - Manual PEB / NtGlobalFlag access via fs:[0x30] (x86), gs:[0x60] (x64),
//    and the TEB self-pointer at fs:[0x18]
//  - rdtsc / cpuid timing-based debugger detection
//  - INT 3 (0xCC) scan loops (cmp byte ptr [...], 0xCC)
//  - cpuid leaf 0x40000000 hypervisor brand-string checks
//    (KVMKVMKVM, Microsoft Hv, VMwareVMware, XenVMMXenVMM, prl hyperv  ,
//     VBoxVBoxVBox)
//  - VMware backdoor I/O instruction (IN / OUT against port 0x5658 'VX' with
//    'VMXh' magic in EAX)
//  - Anti-VM string artefacts (VMware, VirtualBox, QEMU, Xen, Parallels,
//    Sandboxie)
//
//To smoke-test the script without a real malware sample, build the bundled
//PE32 fixture with AntiDebugAntiVMDetector_build_fixture.py, import the
//resulting AntiDebugAntiVMDetector_fixture.bin into Ghidra as a 32-bit PE,
//let auto-analysis finish, then run this script.  If invoked with a script
//argument of "--selftest" (headless) or by answering "Yes" to the self-test
//prompt (interactive) the script also asserts a minimum number of findings
//per technique against the bundled fixture.
//
//@category Analysis
//@menupath Tools.Anti-Debug.Detect Techniques
//@toolbar bug.png

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class AntiDebugAntiVMDetector extends GhidraScript {

	// ------------------------------------------------------------------
	// Constants
	// ------------------------------------------------------------------

	private static final String CAT_ANTIDBG = "AntiDebug";
	private static final String CAT_ANTIVM  = "AntiVM";
	private static final String TAG_ANTIDBG = "AntiDebug";
	private static final String TAG_ANTIVM  = "AntiVM";
	private static final String LABEL_PREFIX_ANTIDBG = "antidbg_";
	private static final String LABEL_PREFIX_ANTIVM  = "antivm_";

	private static final String SELFTEST_ARG = "--selftest";

	// VMware backdoor magic values.
	private static final long VMWARE_PORT  = 0x5658L;       // 'VX'
	private static final long VMWARE_MAGIC = 0x564D5868L;   // 'VMXh'

	// Hypervisor brand strings returned by cpuid leaf 0x40000000.
	// 12-byte strings (EBX|ECX|EDX) with NUL padding inside.
	private static final String[] HV_BRAND_STRINGS = {
		"KVMKVMKVM",
		"Microsoft Hv",
		"VMwareVMware",
		"XenVMMXenVMM",
		"prl hyperv",
		"VBoxVBoxVBox",
	};

	// Plain anti-VM artefact strings commonly seen in evasion checks.
	private static final String[] ANTIVM_ARTIFACT_STRINGS = {
		"VMware", "VirtualBox", "QEMU", "Xen", "Parallels", "Sandboxie",
	};

	// Anti-debug API names -> short technique label and operational note.
	// Order is preserved for the final Markdown report.
	private static final Map<String, ApiNote> ANTI_DEBUG_APIS = new LinkedHashMap<>();
	static {
		ANTI_DEBUG_APIS.put("IsDebuggerPresent", new ApiNote(
			"Win32 IsDebuggerPresent",
			"Reads PEB.BeingDebugged through the kernel32 wrapper -- the most "
				+ "common anti-debug check."));
		ANTI_DEBUG_APIS.put("CheckRemoteDebuggerPresent", new ApiNote(
			"Win32 CheckRemoteDebuggerPresent",
			"Asks the kernel whether a remote debugger is attached to the "
				+ "given process handle."));
		ANTI_DEBUG_APIS.put("NtQueryInformationProcess", new ApiNote(
			"Native NtQueryInformationProcess",
			"With ProcessDebugPort / ProcessDebugObjectHandle / "
				+ "ProcessDebugFlags this is the canonical native "
				+ "anti-debug probe."));
		ANTI_DEBUG_APIS.put("ZwQueryInformationProcess", new ApiNote(
			"Native ZwQueryInformationProcess",
			"Zw* alias of NtQueryInformationProcess; same anti-debug effect."));
		ANTI_DEBUG_APIS.put("NtSetInformationThread", new ApiNote(
			"ThreadHideFromDebugger",
			"With ThreadInformationClass = 0x11 (ThreadHideFromDebugger) the "
				+ "calling thread is detached from any attached debugger."));
		ANTI_DEBUG_APIS.put("ZwSetInformationThread", new ApiNote(
			"ThreadHideFromDebugger",
			"Zw* alias of NtSetInformationThread; same anti-debug effect."));
		ANTI_DEBUG_APIS.put("OutputDebugStringA", new ApiNote(
			"OutputDebugString debugger probe",
			"Combined with GetLastError this is a classic 'is a debugger "
				+ "intercepting OutputDebugString?' check."));
		ANTI_DEBUG_APIS.put("OutputDebugStringW", new ApiNote(
			"OutputDebugString debugger probe",
			"Combined with GetLastError this is a classic 'is a debugger "
				+ "intercepting OutputDebugString?' check."));
		ANTI_DEBUG_APIS.put("AddVectoredExceptionHandler", new ApiNote(
			"Manual VEH debugger detection",
			"Often paired with int3 / single-step exceptions to detect a "
				+ "debugger that swallows the exception instead of the VEH."));
		ANTI_DEBUG_APIS.put("SetUnhandledExceptionFilter", new ApiNote(
			"Manual SEH debugger detection",
			"Used to catch exceptions a debugger would normally absorb -- "
				+ "if the filter never fires, a debugger is attached."));
	}

	// ------------------------------------------------------------------
	// State accumulated during a run
	// ------------------------------------------------------------------

	private final List<Finding> findings = new ArrayList<>();
	private boolean selfTestMode = false;

	// ------------------------------------------------------------------
	// Entry point
	// ------------------------------------------------------------------

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("AntiDebugAntiVMDetector: no program loaded; aborting.");
			return;
		}

		selfTestMode = resolveSelfTestMode();
		if (selfTestMode) {
			println("[+] AntiDebugAntiVMDetector running in self-test mode.");
		}
		else {
			println("[+] AntiDebugAntiVMDetector starting on "
				+ currentProgram.getName() + " ("
				+ currentProgram.getLanguage().getLanguageDescription().getDescription()
				+ ")");
		}

		monitor.setMessage("Scanning for anti-debug API references...");
		scanAntiDebugApis();
		monitor.checkCancelled();

		monitor.setMessage("Scanning for instruction-pattern anti-debug/anti-VM...");
		scanInstructionPatterns();
		monitor.checkCancelled();

		monitor.setMessage("Scanning for hypervisor and anti-VM string references...");
		scanAntiVmStrings();
		monitor.checkCancelled();

		findings.sort(Comparator
			.comparing((Finding f) -> f.category)
			.thenComparing(f -> f.address.getOffset()));

		writeReport();

		println("[+] AntiDebugAntiVMDetector finished. Findings: " + findings.size());

		if (selfTestMode) {
			runSelfTestAssertions();
		}
	}

	// ------------------------------------------------------------------
	// Self-test mode resolution
	// ------------------------------------------------------------------

	private boolean resolveSelfTestMode() throws Exception {
		String[] args = getScriptArgs();
		if (args != null) {
			for (String a : args) {
				if (SELFTEST_ARG.equalsIgnoreCase(a)) {
					return true;
				}
			}
		}
		if (isRunningHeadless()) {
			return false;
		}
		try {
			return askYesNo("AntiDebugAntiVMDetector",
				"Run in self-test mode? (validates findings against the bundled "
					+ "AntiDebugAntiVMDetector_fixture.bin -- answer No for a "
					+ "normal scan of an unknown binary)");
		}
		catch (Exception e) {
			// askYesNo throws if the user cancels -- treat as a normal run.
			return false;
		}
	}

	// ------------------------------------------------------------------
	// Detection: API references
	// ------------------------------------------------------------------

	private void scanAntiDebugApis() throws Exception {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Listing listing = currentProgram.getListing();

		for (Map.Entry<String, ApiNote> entry : ANTI_DEBUG_APIS.entrySet()) {
			monitor.checkCancelled();
			String apiName = entry.getKey();
			ApiNote note = entry.getValue();

			java.util.HashSet<Address> alreadyFlagged = new java.util.HashSet<>();
			SymbolIterator symbols = symbolTable.getSymbols(apiName);
			while (symbols.hasNext()) {
				monitor.checkCancelled();
				Symbol sym = symbols.next();
				Address symAddr = sym.getAddress();
				if (symAddr == null) {
					continue;
				}
				// First, references that land on the symbol itself.  Then, if
				// that symbol is data/external (typical for PE imports where
				// Ghidra puts the API name on the IAT slot or an external
				// stub), follow one extra hop so we also catch the actual
				// `call dword ptr [IAT]` site in code.
				java.util.ArrayDeque<Address> queue = new java.util.ArrayDeque<>();
				java.util.HashSet<Address> visited = new java.util.HashSet<>();
				queue.add(symAddr);

				while (!queue.isEmpty()) {
					monitor.checkCancelled();
					Address current = queue.poll();
					if (!visited.add(current)) {
						continue;
					}
					Reference[] refs = getReferencesTo(current);
					for (Reference ref : refs) {
						Address from = ref.getFromAddress();
						if (from == null) {
							continue;
						}
						Instruction insn = listing.getInstructionAt(from);
						if (insn != null) {
							if (alreadyFlagged.add(from)) {
								recordFinding(new Finding(
									CAT_ANTIDBG,
									note.technique,
									from,
									"Anti-debug API call: " + apiName + " -- " + note.note,
									"Call to " + apiName + ": " + note.note));
							}
						}
						else if (visited.size() < 8) {
							// Indirection through an IAT / data slot -- recurse
							// once or twice, capped to avoid pathological loops.
							queue.add(from);
						}
					}
				}
			}
		}
	}

	// ------------------------------------------------------------------
	// Detection: instruction-pattern (rdtsc, cpuid, int3, in/out, fs/gs PEB)
	// ------------------------------------------------------------------

	private void scanInstructionPatterns() throws Exception {
		Listing listing = currentProgram.getListing();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = it.next();
			String mnem = insn.getMnemonicString();
			if (mnem == null) {
				continue;
			}
			String mu = mnem.toUpperCase();

			switch (mu) {
				case "RDTSC":
				case "RDTSCP":
					recordFinding(new Finding(
						CAT_ANTIDBG,
						"RDTSC timing check",
						insn.getMinAddress(),
						"RDTSC issued -- frequently used in pre/post timing "
							+ "deltas to detect single-step debugging.",
						"RDTSC timing-based anti-debug probe"));
					break;

				case "CPUID":
					recordCpuidFinding(insn);
					break;

				case "INT3":
				case "INT 3":
					recordFinding(new Finding(
						CAT_ANTIDBG,
						"INT3 (0xCC) anchor",
						insn.getMinAddress(),
						"INT 3 instruction -- commonly used as a debugger "
							+ "trap or as the trigger for SEH/VEH-based "
							+ "debugger detection.",
						"INT 3 anti-debug anchor"));
					break;

				case "IN":
				case "OUT":
					recordIoBackdoorFinding(insn, mu);
					break;

				case "CMP":
					recordIntScanLoopFinding(insn);
					break;

				default:
					// Fall through to operand-prefix-based checks below.
					break;
			}

			// fs: / gs: segment override accesses to known PEB / TEB offsets.
			recordSegmentOverrideFinding(insn);
		}
	}

	private void recordCpuidFinding(Instruction insn) {
		// Walk back up to four instructions looking for the most-recent
		// `mov eax, <imm>`.  The value loaded by THAT mov is what cpuid sees
		// in EAX; we must not skip past it to find an older mov that happened
		// to set eax to 0x40000000 earlier in the function.
		Instruction cursor = insn.getPrevious();
		boolean hyperLeaf = false;
		for (int i = 0; cursor != null && i < 4; i++) {
			if ("MOV".equalsIgnoreCase(cursor.getMnemonicString())) {
				Object[] op0 = cursor.getOpObjects(0);
				Object[] op1 = cursor.getOpObjects(1);
				if (op0.length == 1 && op0[0] instanceof Register
						&& "EAX".equalsIgnoreCase(((Register) op0[0]).getName())) {
					if (op1.length == 1 && op1[0] instanceof Scalar
							&& ((Scalar) op1[0]).getUnsignedValue() == 0x40000000L) {
						hyperLeaf = true;
					}
					// First mov-to-eax found establishes EAX at the cpuid;
					// stop walking regardless of value.
					break;
				}
			}
			cursor = cursor.getPrevious();
		}
		if (hyperLeaf) {
			recordFinding(new Finding(
				CAT_ANTIVM,
				"CPUID hypervisor leaf 0x40000000",
				insn.getMinAddress(),
				"CPUID issued with EAX = 0x40000000 -- standard VMM brand "
					+ "string probe (KVMKVMKVM / Microsoft Hv / "
					+ "VMwareVMware / XenVMMXenVMM / prl hyperv  / "
					+ "VBoxVBoxVBox).",
				"CPUID hypervisor brand-string probe"));
		}
		else {
			recordFinding(new Finding(
				CAT_ANTIDBG,
				"CPUID timing/feature probe",
				insn.getMinAddress(),
				"CPUID issued -- often paired with RDTSC for timing-based "
					+ "anti-debug, or used to read feature flags that change "
					+ "under a hypervisor.",
				"CPUID anti-debug / anti-VM probe"));
		}
	}

	private void recordIoBackdoorFinding(Instruction insn, String mu) {
		// Look back briefly for the most-recent `mov dx, <imm>` and the
		// most-recent `mov eax, <imm>` -- those imms tell us whether the
		// I/O is going to the VMware backdoor port with the magic 'VMXh'.
		boolean portMatch = false;
		boolean magicMatch = false;
		boolean haveDx = false;
		boolean haveEax = false;
		Instruction cursor = insn.getPrevious();
		for (int i = 0; cursor != null && i < 6 && !(haveDx && haveEax); i++) {
			if ("MOV".equalsIgnoreCase(cursor.getMnemonicString())) {
				Object[] op0 = cursor.getOpObjects(0);
				Object[] op1 = cursor.getOpObjects(1);
				if (op0.length == 1 && op0[0] instanceof Register && op1.length == 1
						&& op1[0] instanceof Scalar) {
					String regName = ((Register) op0[0]).getName().toUpperCase();
					long val = ((Scalar) op1[0]).getUnsignedValue();
					if ("DX".equals(regName) && !haveDx) {
						haveDx = true;
						portMatch = (val == VMWARE_PORT);
					}
					if (("EAX".equals(regName) || "RAX".equals(regName)) && !haveEax) {
						haveEax = true;
						magicMatch = (val == VMWARE_MAGIC);
					}
				}
			}
			cursor = cursor.getPrevious();
		}
		if (portMatch || magicMatch) {
			recordFinding(new Finding(
				CAT_ANTIVM,
				"VMware backdoor port " + mu,
				insn.getMinAddress(),
				"VMware backdoor I/O via " + mu + " -- port 0x5658 ('VX') "
					+ "with magic 'VMXh' in EAX.  Used by guests to "
					+ "communicate with the hypervisor and is one of the "
					+ "most reliable anti-VM checks.",
				"VMware backdoor " + mu));
		}
	}

	private void recordIntScanLoopFinding(Instruction insn) {
		// cmp ?, 0xCC -- look at every operand.
		for (int opi = 0; opi < insn.getNumOperands(); opi++) {
			Object[] objs = insn.getOpObjects(opi);
			for (Object o : objs) {
				if (o instanceof Scalar) {
					Scalar s = (Scalar) o;
					if (s.getUnsignedValue() == 0xCCL) {
						recordFinding(new Finding(
							CAT_ANTIDBG,
							"INT3 (0xCC) scan loop",
							insn.getMinAddress(),
							"Compare against 0xCC byte -- pattern used to "
								+ "scan a memory range for INT 3 software "
								+ "breakpoints planted by a debugger.",
							"INT3 (0xCC) scan-loop"));
						return;
					}
				}
			}
		}
	}

	private void recordSegmentOverrideFinding(Instruction insn) {
		// Inspect every operand's textual representation for a fs:/gs: prefix.
		// Matching against the rendered string is the simplest way to catch
		// `mov eax, fs:[0x30]` and friends without touching the language
		// definition.
		for (int opi = 0; opi < insn.getNumOperands(); opi++) {
			String rep;
			try {
				rep = insn.getDefaultOperandRepresentation(opi);
			}
			catch (Exception ex) {
				continue;
			}
			if (rep == null) {
				continue;
			}
			String upper = rep.toUpperCase();
			boolean isFs = upper.contains("FS:");
			boolean isGs = upper.contains("GS:");
			if (!isFs && !isGs) {
				continue;
			}
			Long offset = extractFirstHexOffset(rep);
			if (offset == null) {
				continue;
			}
			String technique;
			String comment;
			if (isFs && offset == 0x30L) {
				technique = "fs:[0x30] PEB access";
				comment   = "Read of fs:[0x30] -- direct PEB pointer load on "
					+ "x86, classic anti-debug primitive (PEB.BeingDebugged "
					+ "is at PEB+0x02, NtGlobalFlag at PEB+0x68).";
			}
			else if (isGs && offset == 0x60L) {
				technique = "gs:[0x60] PEB access";
				comment   = "Read of gs:[0x60] -- direct PEB pointer load on "
					+ "x64, classic anti-debug primitive (PEB.BeingDebugged "
					+ "is at PEB+0x02, NtGlobalFlag at PEB+0xBC).";
			}
			else if (isFs && offset == 0x18L) {
				technique = "fs:[0x18] TEB self-pointer";
				comment   = "Read of fs:[0x18] -- TEB self-pointer load, "
					+ "typically the first hop in an x86 PEB chain.";
			}
			else if (isGs && offset == 0x30L) {
				technique = "gs:[0x30] TEB self-pointer";
				comment   = "Read of gs:[0x30] -- TEB self-pointer load on "
					+ "x64, typically the first hop in a PEB chain.";
			}
			else if (isFs && offset == 0x60L) {
				technique = "fs:[0x60] PEB-style access";
				comment   = "Read of fs:[0x60] -- offset associated with PEB "
					+ "structures during anti-debug walks.";
			}
			else {
				// Any other fs:/gs: dereference is interesting but we don't
				// flag it -- it would generate too much noise on real PE files.
				continue;
			}
			recordFinding(new Finding(
				CAT_ANTIDBG,
				technique,
				insn.getMinAddress(),
				comment,
				technique));
			return;
		}
	}

	/**
	 * Pulls the first 0x... or numeric offset out of an operand textual
	 * representation.  Returns null if no hex literal is present.
	 */
	private Long extractFirstHexOffset(String rep) {
		int idx = rep.toLowerCase().indexOf("0x");
		if (idx < 0) {
			return null;
		}
		int end = idx + 2;
		while (end < rep.length() && isHex(rep.charAt(end))) {
			end++;
		}
		if (end == idx + 2) {
			return null;
		}
		try {
			return Long.parseLong(rep.substring(idx + 2, end), 16);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private static boolean isHex(char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}

	// ------------------------------------------------------------------
	// Detection: anti-VM string references
	// ------------------------------------------------------------------

	private void scanAntiVmStrings() throws Exception {
		// Build a single map of (string-content -> technique label).  Order
		// needles longest-first so a string like "VMwareVMware" matches the
		// 12-byte hypervisor brand and not the 6-byte artefact substring
		// "VMware".
		Map<String, String> needles = new LinkedHashMap<>();
		List<String> allNeedles = new ArrayList<>();
		for (String hv : HV_BRAND_STRINGS) {
			allNeedles.add(hv);
			needles.put(hv, "Hypervisor brand string '" + hv + "'");
		}
		for (String s : ANTIVM_ARTIFACT_STRINGS) {
			allNeedles.add(s);
			needles.put(s, "Anti-VM artefact string '" + s + "'");
		}
		allNeedles.sort((a, b) -> Integer.compare(b.length(), a.length()));

		// Collect (techniqueLabel -> set-of-addresses) so we don't double-flag
		// the same byte sequence twice via both the data listing AND the byte
		// scan (which DOES find sub-5-char strings that the string analyzer
		// silently dropped).
		Map<String, java.util.Set<Address>> seen = new LinkedHashMap<>();
		for (String t : needles.values()) {
			seen.put(t, new java.util.HashSet<>());
		}

		Listing listing = currentProgram.getListing();

		// Phase 1: walk Ghidra-defined strings.  This is the cheap path that
		// also lets us pick up references via getReferencesTo.
		DataIterator dataIt = listing.getDefinedData(true);
		while (dataIt.hasNext()) {
			monitor.checkCancelled();
			Data data = dataIt.next();
			if (data == null || !data.hasStringValue()) {
				continue;
			}
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
			String value = sdi.getStringValue();
			if (value == null || value.isEmpty()) {
				continue;
			}
			String matched = matchNeedle(value, allNeedles);
			if (matched == null) {
				continue;
			}
			String technique = needles.get(matched);
			Address stringAddr = data.getAddress();
			if (seen.get(technique).add(stringAddr)) {
				recordFinding(new Finding(
					CAT_ANTIVM,
					technique,
					stringAddr,
					technique + " present in program data.",
					technique));
			}

			// Walk references TO the string and flag every code-side hit.
			// Filter out pointer-shaped values in headers / data directories
			// that aren't actual instructions.
			Reference[] refs = getReferencesTo(stringAddr);
			for (Reference ref : refs) {
				monitor.checkCancelled();
				Address from = ref.getFromAddress();
				if (listing.getInstructionAt(from) == null) {
					continue;
				}
				if (seen.get(technique).add(from)) {
					recordFinding(new Finding(
						CAT_ANTIVM,
						technique,
						from,
						technique + " referenced here.",
						technique + " reference"));
				}
			}
		}

		// Phase 2: byte-pattern scan across the program memory.  Catches the
		// short artefact strings ("Xen", "QEMU", ...) that Ghidra's string
		// analyzer drops because of its minimum length threshold, and also
		// catches anti-VM strings hidden inside larger blobs.
		ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
		ghidra.program.model.address.AddressSetView initialised =
			mem.getLoadedAndInitializedAddressSet();
		for (String n : allNeedles) {
			monitor.checkCancelled();
			byte[] pat = n.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
			if (pat.length == 0) {
				continue;
			}
			Address cursor = initialised.getMinAddress();
			Address end = initialised.getMaxAddress();
			if (cursor == null || end == null) {
				continue;
			}
			while (cursor != null && cursor.compareTo(end) <= 0) {
				monitor.checkCancelled();
				Address hit = mem.findBytes(cursor, end, pat, null, true, monitor);
				if (hit == null) {
					break;
				}
				String technique = needles.get(n);
				if (seen.get(technique).add(hit)) {
					recordFinding(new Finding(
						CAT_ANTIVM,
						technique,
						hit,
						technique + " present in program data.",
						technique));
				}
				try {
					cursor = hit.add(1);
				}
				catch (Exception ex) {
					break;
				}
			}
		}
	}

	private String matchNeedle(String haystack, Iterable<String> needles) {
		String h = haystack.toLowerCase();
		for (String n : needles) {
			if (h.contains(n.toLowerCase())) {
				return n;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// Annotation: bookmark + comment + function tag + function rename
	// ------------------------------------------------------------------

	private void recordFinding(Finding f) {
		findings.add(f);

		try {
			createBookmark(f.address, f.category, f.bookmarkNote);
		}
		catch (Exception e) {
			printerr("Failed to create bookmark at " + f.address + ": " + e.getMessage());
		}
		try {
			setPreComment(f.address, "[" + f.category + "] " + f.preComment);
		}
		catch (Exception e) {
			printerr("Failed to set pre-comment at " + f.address + ": " + e.getMessage());
		}

		Function fn = getFunctionContaining(f.address);
		if (fn == null) {
			return;
		}
		try {
			fn.addTag(f.category.equals(CAT_ANTIDBG) ? TAG_ANTIDBG : TAG_ANTIVM);
		}
		catch (Exception e) {
			printerr("Failed to add tag to " + fn.getName() + ": " + e.getMessage());
		}
		try {
			renameFunctionWithPrefix(fn, f.category);
		}
		catch (Exception e) {
			printerr("Failed to rename " + fn.getName() + ": " + e.getMessage());
		}
	}

	private void renameFunctionWithPrefix(Function fn, String category) throws Exception {
		String prefix = category.equals(CAT_ANTIDBG) ? LABEL_PREFIX_ANTIDBG : LABEL_PREFIX_ANTIVM;
		String currentName = fn.getName();
		if (currentName == null) {
			return;
		}
		// Already prefixed by us -- skip.
		if (currentName.startsWith(LABEL_PREFIX_ANTIDBG)
				|| currentName.startsWith(LABEL_PREFIX_ANTIVM)) {
			return;
		}
		String newName = prefix + currentName;
		fn.setName(newName, SourceType.USER_DEFINED);
	}

	// ------------------------------------------------------------------
	// Markdown report
	// ------------------------------------------------------------------

	private void writeReport() {
		String report = renderMarkdownReport();
		String exePath = currentProgram.getExecutablePath();
		Path outPath = null;
		if (exePath != null && !exePath.isEmpty()) {
			try {
				Path src = Paths.get(exePath);
				Path parent = src.toAbsolutePath().getParent();
				if (parent != null && Files.isWritable(parent)) {
					outPath = parent.resolve(src.getFileName().toString()
						+ ".antidebug-report.md");
				}
			}
			catch (Exception e) {
				outPath = null;
			}
		}
		if (outPath != null) {
			try {
				Files.writeString(outPath, report);
				println("[+] Markdown report written to " + outPath);
				return;
			}
			catch (IOException e) {
				printerr("Could not write report next to program ("
					+ outPath + "): " + e.getMessage()
					+ " -- falling back to console output.");
			}
		}
		println("---- BEGIN AntiDebug/AntiVM REPORT ----");
		println(report);
		println("----  END  AntiDebug/AntiVM REPORT ----");
	}

	private String renderMarkdownReport() {
		StringWriter sw = new StringWriter();
		try (PrintWriter pw = new PrintWriter(sw)) {
			pw.println("# Anti-Debug / Anti-VM Detection Report");
			pw.println();
			pw.println("- Program: `" + currentProgram.getName() + "`");
			pw.println("- Path: `"
				+ (currentProgram.getExecutablePath() == null
					? "(unknown)"
					: currentProgram.getExecutablePath())
				+ "`");
			pw.println("- Language: `"
				+ currentProgram.getLanguage().getLanguageDescription().getDescription()
				+ "`");
			pw.println("- Total findings: **" + findings.size() + "**");
			pw.println();

			Map<String, Integer> counts = new TreeMap<>();
			for (Finding f : findings) {
				counts.merge(f.technique, 1, Integer::sum);
			}
			pw.println("## Summary by technique");
			pw.println();
			pw.println("| Technique | Count |");
			pw.println("|-----------|------:|");
			for (Map.Entry<String, Integer> e : counts.entrySet()) {
				pw.println("| " + e.getKey() + " | " + e.getValue() + " |");
			}
			pw.println();

			pw.println("## Findings");
			pw.println();
			pw.println("| Category | Technique | Address | Function | Notes |");
			pw.println("|----------|-----------|---------|----------|-------|");
			for (Finding f : findings) {
				Function fn = getFunctionContaining(f.address);
				String fnName = fn == null ? "(none)" : fn.getName();
				pw.println("| " + f.category
					+ " | " + f.technique
					+ " | `" + f.address + "`"
					+ " | " + fnName
					+ " | " + f.bookmarkNote.replace("|", "\\|") + " |");
			}
			pw.println();
			pw.println("## Operational interpretation");
			pw.println();
			pw.println("- An *AntiDebug* hit means the binary is actively trying to detect "
				+ "an attached debugger.  Treat each call site as a candidate patch point "
				+ "before running the sample under a dynamic analysis harness.");
			pw.println("- An *AntiVM* hit means the binary is actively trying to detect a "
				+ "virtualised or sandboxed execution environment.  Investigate before "
				+ "executing on shared analysis VMs -- the sample may behave differently "
				+ "(or not at all) compared to bare-metal.");
		}
		return sw.toString();
	}

	// ------------------------------------------------------------------
	// Self-test assertions
	// ------------------------------------------------------------------

	private void runSelfTestAssertions() throws Exception {
		// Counts expected on the bundled fixture.  We assert lower bounds to
		// stay robust against future changes that *add* coverage.
		Map<String, Integer> required = new LinkedHashMap<>();
		required.put("Win32 IsDebuggerPresent",                1);
		required.put("Win32 CheckRemoteDebuggerPresent",       1);
		required.put("Native NtQueryInformationProcess",       1);
		required.put("ThreadHideFromDebugger",                 1);
		required.put("OutputDebugString debugger probe",       1);
		required.put("Manual VEH debugger detection",          1);
		required.put("Manual SEH debugger detection",          1);
		required.put("RDTSC timing check",                     2);
		required.put("CPUID hypervisor leaf 0x40000000",       1);
		required.put("CPUID timing/feature probe",             1);
		required.put("INT3 (0xCC) anchor",                     1);
		required.put("INT3 (0xCC) scan loop",                  1);
		required.put("VMware backdoor port IN",                1);
		required.put("VMware backdoor port OUT",               1);
		required.put("fs:[0x30] PEB access",                   1);
		required.put("fs:[0x18] TEB self-pointer",             1);

		Map<String, Integer> actual = new TreeMap<>();
		for (Finding f : findings) {
			actual.merge(f.technique, 1, Integer::sum);
		}

		List<String> failures = new ArrayList<>();
		for (Map.Entry<String, Integer> req : required.entrySet()) {
			int found = actual.getOrDefault(req.getKey(), 0);
			if (found < req.getValue()) {
				failures.add("  [-] " + req.getKey()
					+ ": expected >= " + req.getValue()
					+ ", got " + found);
			}
			else {
				println("  [+] " + req.getKey() + ": " + found + " (>= " + req.getValue() + ")");
			}
		}

		// Also expect each anti-VM string to fire at least once (artefact +
		// any code references).
		for (String s : HV_BRAND_STRINGS) {
			String tech = "Hypervisor brand string '" + s + "'";
			int found = actual.getOrDefault(tech, 0);
			if (found < 1) {
				failures.add("  [-] " + tech + ": expected >= 1, got 0");
			}
			else {
				println("  [+] " + tech + ": " + found);
			}
		}
		for (String s : ANTIVM_ARTIFACT_STRINGS) {
			String tech = "Anti-VM artefact string '" + s + "'";
			int found = actual.getOrDefault(tech, 0);
			if (found < 1) {
				failures.add("  [-] " + tech + ": expected >= 1, got 0");
			}
			else {
				println("  [+] " + tech + ": " + found);
			}
		}

		if (!failures.isEmpty()) {
			printerr("[X] Self-test FAILED with " + failures.size() + " missing detection(s):");
			for (String f : failures) {
				printerr(f);
			}
			throw new AssertionError("AntiDebugAntiVMDetector self-test failed: "
				+ failures.size() + " missing detection(s); see console for details.");
		}
		println("[+] Self-test PASSED -- all required techniques detected.");
	}

	// ------------------------------------------------------------------
	// Small value types
	// ------------------------------------------------------------------

	private static final class ApiNote {
		final String technique;
		final String note;

		ApiNote(String technique, String note) {
			this.technique = technique;
			this.note = note;
		}
	}

	private static final class Finding {
		final String category;
		final String technique;
		final Address address;
		final String bookmarkNote;
		final String preComment;

		Finding(String category, String technique, Address address,
				String bookmarkNote, String preComment) {
			this.category = category;
			this.technique = technique;
			this.address = address;
			this.bookmarkNote = bookmarkNote;
			this.preComment = preComment;
		}
	}

	@SuppressWarnings("unused")
	private static String join(String sep, List<?> parts) {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (Object o : parts) {
			if (!first) {
				sb.append(sep);
			}
			first = false;
			sb.append(o);
		}
		return sb.toString();
	}

	@SuppressWarnings("unused")
	private static String quote(String s) {
		return "\"" + s.replace("\"", "\\\"") + "\"";
	}

	@SuppressWarnings("unused")
	private static List<String> sortedKeys(Map<String, ?> m) {
		List<String> keys = new ArrayList<>(m.keySet());
		keys.sort(Comparator.naturalOrder());
		return keys;
	}

	@SuppressWarnings("unused")
	private static List<String> nonEmpty(String... values) {
		List<String> out = new ArrayList<>();
		for (String v : values) {
			if (v != null && !v.isEmpty()) {
				out.add(v);
			}
		}
		return out;
	}

	@SuppressWarnings("unused")
	private static String defaulting(String s, String fallback) {
		return s == null || s.isEmpty() ? fallback : s;
	}

	@SuppressWarnings("unused")
	private static String[] dedupe(String[] arr) {
		return Arrays.stream(arr).distinct().toArray(String[]::new);
	}
}
