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
package suspiciouspatternanalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that detects suspicious patterns commonly found in malware:
 * <ul>
 *   <li>Anti-debugging techniques (IsDebuggerPresent, timing checks)</li>
 *   <li>Process injection APIs (VirtualAllocEx, WriteProcessMemory)</li>
 *   <li>Shellcode patterns (NOP sleds, GetPC techniques)</li>
 *   <li>XOR-based obfuscation loops</li>
 * </ul>
 * 
 * Findings are reported as WARNING bookmarks for easy navigation and triage.
 */
public class SuspiciousPatternAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "Suspicious Pattern Detector";
    private static final String DESCRIPTION = 
        "Identifies suspicious patterns commonly found in malware including " +
        "anti-debugging, process injection, shellcode, and obfuscation techniques.";

    private static final String BOOKMARK_CATEGORY = "Suspicious";

    private static final Set<String> ANTI_DEBUG_APIS = Set.of(
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", 
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "QueryPerformanceCounter",
        "GetTickCount",
        "GetTickCount64"
    );

    private static final Set<String> INJECTION_APIS = Set.of(
        "VirtualAllocEx",
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "RtlCreateUserThread",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtWriteVirtualMemory"
    );

    private static final Set<String> EVASION_APIS = Set.of(
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32FirstW",
        "Process32Next",
        "Process32NextW",
        "OpenProcess",
        "TerminateProcess",
        "RegSetValueExA",
        "RegSetValueExW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW"
    );

    private static final Set<String> CRYPTO_APIS = Set.of(
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptGenKey",
        "CryptDeriveKey"
    );

    private static final String OPTION_DETECT_ANTI_DEBUG = "Detect Anti-Debugging";
    private static final String OPTION_DETECT_INJECTION = "Detect Process Injection";
    private static final String OPTION_DETECT_SHELLCODE = "Detect Shellcode Patterns";
    private static final String OPTION_DETECT_XOR_LOOPS = "Detect XOR Obfuscation";
    private static final String OPTION_DETECT_EVASION = "Detect Evasion/Persistence";
    private static final String OPTION_DETECT_CRYPTO = "Detect Crypto APIs";
    private static final String OPTION_MIN_NOP_SLED = "Minimum NOP Sled Length";

    private boolean detectAntiDebug = true;
    private boolean detectInjection = true;
    private boolean detectShellcode = true;
    private boolean detectXorLoops = true;
    private boolean detectEvasion = true;
    private boolean detectCrypto = true;
    private int minNopSledLength = 8;

    public SuspiciousPatternAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        String format = program.getExecutableFormat();
        return format.contains("PE") || 
               format.contains("ELF") || 
               format.contains("Mach-O") ||
               format.contains("Raw");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refMgr = program.getReferenceManager();
        int findingsCount = 0;

        monitor.setMessage("Scanning for suspicious patterns...");
        monitor.setMaximum(4);

        // 1. Detect suspicious API calls
        monitor.setProgress(1);
        monitor.setMessage("Checking for suspicious API calls...");
        if (detectAntiDebug || detectInjection || detectEvasion || detectCrypto) {
            findingsCount += scanForSuspiciousAPIs(program, symbolTable, refMgr, 
                                                    bookmarkMgr, monitor, log);
        }

        // 2. Detect shellcode patterns (NOP sleds, common sequences)
        monitor.setProgress(2);
        monitor.setMessage("Scanning for shellcode patterns...");
        if (detectShellcode) {
            findingsCount += scanForShellcodePatterns(program, set, bookmarkMgr, 
                                                       monitor, log);
        }

        // 3. Detect XOR obfuscation loops
        monitor.setProgress(3);
        monitor.setMessage("Detecting XOR obfuscation...");
        if (detectXorLoops) {
            findingsCount += scanForXorLoops(program, set, bookmarkMgr, monitor, log);
        }

        // 4. Detect suspicious instruction sequences
        monitor.setProgress(4);
        monitor.setMessage("Analyzing instruction patterns...");
        findingsCount += scanForSuspiciousInstructions(program, set, bookmarkMgr, monitor, log);

        log.appendMsg(NAME, "Analysis complete. Found " + findingsCount + " suspicious patterns.");
        return findingsCount > 0;
    }

    /**
     * Scans for references to suspicious Windows APIs.
     * 
     * @param program the program being analyzed
     * @param symbolTable the program's symbol table
     * @param refMgr the reference manager
     * @param bookmarkMgr the bookmark manager for flagging findings
     * @param monitor task monitor for cancellation
     * @param log message log for reporting
     * @return count of suspicious patterns found
     * @throws CancelledException if analysis is cancelled
     */
    private int scanForSuspiciousAPIs(Program program, SymbolTable symbolTable,
            ReferenceManager refMgr, BookmarkManager bookmarkMgr, 
            TaskMonitor monitor, MessageLog log) throws CancelledException {

        int count = 0;
        SymbolIterator symbols = symbolTable.getExternalSymbols();

        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            String name = symbol.getName();

            String threatType = null;
            String severity = null;

            if (detectAntiDebug && ANTI_DEBUG_APIS.contains(name)) {
                threatType = "Anti-Debugging";
                severity = "MEDIUM";
            } else if (detectInjection && INJECTION_APIS.contains(name)) {
                threatType = "Process Injection";
                severity = "HIGH";
            } else if (detectEvasion && EVASION_APIS.contains(name)) {
                threatType = "Evasion/Persistence";
                severity = "MEDIUM";
            } else if (detectCrypto && CRYPTO_APIS.contains(name)) {
                threatType = "Cryptographic";
                severity = "LOW";
            }

            if (threatType != null) {
                Reference[] refs = refMgr.getReferencesTo(symbol.getAddress());
                for (Reference ref : refs) {
                    Address callSite = ref.getFromAddress();
                    String comment = String.format("[%s] %s: Call to %s detected", 
                                                    severity, threatType, name);
                    
                    bookmarkMgr.setBookmark(callSite, BookmarkType.WARNING, 
                                            BOOKMARK_CATEGORY, comment);
                    count++;
                    log.appendMsg(NAME, comment + " at " + callSite);
                }
            }
        }
        return count;
    }

    /**
     * Scans for common shellcode patterns like NOP sleds and GetPC techniques.
     * 
     * @param program the program being analyzed
     * @param set address set to analyze
     * @param bookmarkMgr the bookmark manager for flagging findings
     * @param monitor task monitor for cancellation
     * @param log message log for reporting
     * @return count of suspicious patterns found
     * @throws CancelledException if analysis is cancelled
     */
    private int scanForShellcodePatterns(Program program, AddressSetView set,
            BookmarkManager bookmarkMgr, TaskMonitor monitor, MessageLog log) 
            throws CancelledException {

        int count = 0;
        Memory memory = program.getMemory();
        AddressSetView executableSet = memory.getExecuteSet();
        AddressSetView searchSet = set.intersect(executableSet);

        if (searchSet.isEmpty()) {
            searchSet = set.intersect(memory.getLoadedAndInitializedAddressSet());
        }

        count += findNopSleds(program, searchSet, bookmarkMgr, monitor, log);
        count += findShellcodeSequences(program, searchSet, bookmarkMgr, monitor, log);

        return count;
    }

    /**
     * Finds NOP sleds (sequences of 0x90 bytes).
     */
    private int findNopSleds(Program program, AddressSetView set, 
            BookmarkManager bookmarkMgr, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        int count = 0;
        Memory memory = program.getMemory();

        for (AddressRange range : set) {
            monitor.checkCancelled();
            Address addr = range.getMinAddress();
            Address maxAddr = range.getMaxAddress();

            int nopCount = 0;
            Address sledStart = null;

            while (addr.compareTo(maxAddr) <= 0) {
                try {
                    byte b = memory.getByte(addr);
                    if (b == (byte)0x90) {
                        if (sledStart == null) {
                            sledStart = addr;
                        }
                        nopCount++;
                    } else {
                        if (nopCount >= minNopSledLength && sledStart != null) {
                            String comment = String.format(
                                "[HIGH] Shellcode: NOP sled detected (%d bytes)", nopCount);
                            bookmarkMgr.setBookmark(sledStart, BookmarkType.WARNING,
                                                    BOOKMARK_CATEGORY, comment);
                            count++;
                            log.appendMsg(NAME, comment + " at " + sledStart);
                        }
                        nopCount = 0;
                        sledStart = null;
                    }
                    addr = addr.add(1);
                } catch (MemoryAccessException | AddressOutOfBoundsException e) {
                    break;
                }
            }

            if (nopCount >= minNopSledLength && sledStart != null) {
                String comment = String.format(
                    "[HIGH] Shellcode: NOP sled detected (%d bytes)", nopCount);
                bookmarkMgr.setBookmark(sledStart, BookmarkType.WARNING,
                                        BOOKMARK_CATEGORY, comment);
                count++;
                log.appendMsg(NAME, comment + " at " + sledStart);
            }
        }
        return count;
    }

    /**
     * Searches for known shellcode byte sequences using pattern matching.
     */
    private int findShellcodeSequences(Program program, AddressSetView set,
            BookmarkManager bookmarkMgr, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Shellcode Patterns");
        List<Address> findings = new ArrayList<>();

        // GetPC technique: call $+5; pop reg (position-independent code)
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x58},
            "GetPC (call $+5; pop eax)");
        
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5B},
            "GetPC (call $+5; pop ebx)");
        
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x59},
            "GetPC (call $+5; pop ecx)");

        // PEB access via FS segment (common in shellcode for API resolution)
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{0x64, (byte)0xA1, 0x30, 0x00, 0x00, 0x00},
            "PEB Access via fs:[0x30]");

        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{0x64, (byte)0x8B, 0x15, 0x30, 0x00, 0x00, 0x00},
            "PEB Access via fs:[0x30]");

        // GS segment PEB access (x64)
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{0x65, 0x48, (byte)0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00},
            "PEB Access via gs:[0x60] (x64)");

        // Syscall instruction (direct system call, used to bypass hooks)
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{0x0F, 0x05},
            "Direct syscall (x64)");

        // SYSENTER instruction
        addShellcodePattern(searcher, program, bookmarkMgr, findings, log,
            new byte[]{0x0F, 0x34},
            "SYSENTER instruction");

        searcher.search(program, set, monitor);
        return findings.size();
    }

    private void addShellcodePattern(MemoryBytePatternSearcher searcher, Program program,
            BookmarkManager bookmarkMgr, List<Address> findings, MessageLog log,
            byte[] pattern, String description) {

        GenericMatchAction<String> action = new GenericMatchAction<>(description) {
            @Override
            public void apply(Program prog, Address addr, Match match) {
                String comment = String.format("[HIGH] Shellcode: %s pattern detected", description);
                bookmarkMgr.setBookmark(addr, BookmarkType.WARNING, BOOKMARK_CATEGORY, comment);
                findings.add(addr);
                log.appendMsg(NAME, comment + " at " + addr);
            }
        };

        GenericByteSequencePattern<String> bytePattern = 
            new GenericByteSequencePattern<>(pattern, action);
        searcher.addPattern(bytePattern);
    }

    /**
     * Scans for XOR-based decryption/obfuscation loops.
     * 
     * @param program the program being analyzed
     * @param set address set to analyze
     * @param bookmarkMgr the bookmark manager for flagging findings
     * @param monitor task monitor for cancellation
     * @param log message log for reporting
     * @return count of suspicious patterns found
     * @throws CancelledException if analysis is cancelled
     */
    private int scanForXorLoops(Program program, AddressSetView set,
            BookmarkManager bookmarkMgr, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        int count = 0;
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(set, true);

        Address xorStart = null;
        int xorCount = 0;
        int instrWindow = 0;

        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString().toLowerCase();

            if (mnemonic.equals("xor")) {
                String op0 = instr.getDefaultOperandRepresentation(0);
                String op1 = instr.getDefaultOperandRepresentation(1);

                if (!op0.equals(op1)) {
                    if (xorStart == null) {
                        xorStart = instr.getAddress();
                    }
                    xorCount++;
                    instrWindow = 0;
                }
            }
            
            if (mnemonic.startsWith("loop") || mnemonic.equals("jnz") || 
                mnemonic.equals("jne") || mnemonic.equals("jnb") || mnemonic.equals("jb")) {
                if (xorCount >= 1 && xorStart != null && instrWindow < 20) {
                    String comment = String.format(
                        "[MEDIUM] Obfuscation: Potential XOR decryption loop (%d XOR ops)", xorCount);
                    bookmarkMgr.setBookmark(xorStart, BookmarkType.WARNING, 
                                            BOOKMARK_CATEGORY, comment);
                    count++;
                    log.appendMsg(NAME, comment + " at " + xorStart);
                }
                xorStart = null;
                xorCount = 0;
                instrWindow = 0;
            }

            if (mnemonic.equals("ret") || mnemonic.equals("retn") || mnemonic.equals("call")) {
                xorStart = null;
                xorCount = 0;
                instrWindow = 0;
            }

            instrWindow++;
            if (instrWindow > 30) {
                xorStart = null;
                xorCount = 0;
            }
        }
        return count;
    }

    /**
     * Scans for other suspicious instruction patterns.
     */
    private int scanForSuspiciousInstructions(Program program, AddressSetView set,
            BookmarkManager bookmarkMgr, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        int count = 0;
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(set, true);

        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString().toLowerCase();

            // Detect INT 2D (anti-debugging)
            if (mnemonic.equals("int")) {
                String operand = instr.getDefaultOperandRepresentation(0);
                if (operand.equals("0x2d") || operand.equals("2Dh") || operand.equals("0x2D")) {
                    String comment = "[MEDIUM] Anti-Debugging: INT 2D detected";
                    bookmarkMgr.setBookmark(instr.getAddress(), BookmarkType.WARNING,
                                            BOOKMARK_CATEGORY, comment);
                    count++;
                    log.appendMsg(NAME, comment + " at " + instr.getAddress());
                }
            }

            // Detect RDTSC (timing-based anti-debugging)
            if (mnemonic.equals("rdtsc")) {
                String comment = "[LOW] Anti-Debugging: RDTSC timing instruction";
                bookmarkMgr.setBookmark(instr.getAddress(), BookmarkType.WARNING,
                                        BOOKMARK_CATEGORY, comment);
                count++;
                log.appendMsg(NAME, comment + " at " + instr.getAddress());
            }

            // Detect CPUID (VM detection)
            if (mnemonic.equals("cpuid")) {
                String comment = "[LOW] Evasion: CPUID instruction (potential VM detection)";
                bookmarkMgr.setBookmark(instr.getAddress(), BookmarkType.WARNING,
                                        BOOKMARK_CATEGORY, comment);
                count++;
                log.appendMsg(NAME, comment + " at " + instr.getAddress());
            }
        }
        return count;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_DETECT_ANTI_DEBUG, detectAntiDebug, null,
            "Flag calls to anti-debugging APIs (IsDebuggerPresent, timing functions, etc.)");
        options.registerOption(OPTION_DETECT_INJECTION, detectInjection, null,
            "Flag calls to process injection APIs (VirtualAllocEx, WriteProcessMemory, etc.)");
        options.registerOption(OPTION_DETECT_SHELLCODE, detectShellcode, null,
            "Detect shellcode patterns like NOP sleds and GetPC techniques");
        options.registerOption(OPTION_DETECT_XOR_LOOPS, detectXorLoops, null,
            "Detect XOR-based obfuscation/decryption loops");
        options.registerOption(OPTION_DETECT_EVASION, detectEvasion, null,
            "Flag calls to process enumeration and persistence APIs");
        options.registerOption(OPTION_DETECT_CRYPTO, detectCrypto, null,
            "Flag calls to cryptographic APIs");
        options.registerOption(OPTION_MIN_NOP_SLED, minNopSledLength, null,
            "Minimum consecutive NOP bytes to flag as a potential sled");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        detectAntiDebug = options.getBoolean(OPTION_DETECT_ANTI_DEBUG, detectAntiDebug);
        detectInjection = options.getBoolean(OPTION_DETECT_INJECTION, detectInjection);
        detectShellcode = options.getBoolean(OPTION_DETECT_SHELLCODE, detectShellcode);
        detectXorLoops = options.getBoolean(OPTION_DETECT_XOR_LOOPS, detectXorLoops);
        detectEvasion = options.getBoolean(OPTION_DETECT_EVASION, detectEvasion);
        detectCrypto = options.getBoolean(OPTION_DETECT_CRYPTO, detectCrypto);
        minNopSledLength = options.getInt(OPTION_MIN_NOP_SLED, minNopSledLength);
    }
}
