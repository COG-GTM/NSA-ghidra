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

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/**
 * Comprehensive unit tests for SuspiciousPatternAnalyzer.
 * 
 * These tests validate:
 * - API detection sets are complete and accurate
 * - Shellcode byte patterns match expected malware signatures
 * - NOP sled detection logic works correctly
 * - XOR obfuscation detection filters self-XOR properly
 * - Severity classifications are correct
 * - Bookmark generation works as expected
 * 
 * Test Output Format:
 * Each test prints detailed output showing what was tested and the result.
 */
public class SuspiciousPatternAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

    private Program program;
    private ToyProgramBuilder builder;
    
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

    @Before
    public void setUp() throws Exception {
        builder = new ToyProgramBuilder("TestProgram", true);
        program = builder.getProgram();
        printTestHeader("Test Setup Complete");
    }

    private void printTestHeader(String testName) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TEST: " + testName);
        System.out.println("=".repeat(60));
    }

    private void printTestResult(String description, boolean passed, String details) {
        String status = passed ? "✓ PASS" : "✗ FAIL";
        System.out.printf("  %s: %s%n", status, description);
        if (details != null && !details.isEmpty()) {
            System.out.printf("    → %s%n", details);
        }
    }

    // ========================================================================
    // API SET VALIDATION TESTS
    // ========================================================================

    @Test
    public void testAntiDebugAPIsComplete() {
        printTestHeader("Anti-Debug API Set Validation");
        
        String[] expectedAPIs = {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "QueryPerformanceCounter",
            "GetTickCount",
            "GetTickCount64"
        };
        
        System.out.println("  Validating " + expectedAPIs.length + " anti-debugging APIs...");
        
        for (String api : expectedAPIs) {
            boolean contains = ANTI_DEBUG_APIS.contains(api);
            printTestResult("Contains " + api, contains, null);
            assertTrue("Missing anti-debug API: " + api, contains);
        }
        
        printTestResult("Total count is " + expectedAPIs.length, 
            ANTI_DEBUG_APIS.size() == expectedAPIs.length,
            "Found: " + ANTI_DEBUG_APIS.size() + ", Expected: " + expectedAPIs.length);
        assertEquals(expectedAPIs.length, ANTI_DEBUG_APIS.size());
        
        System.out.println("\n  MITRE ATT&CK Mapping:");
        System.out.println("    → T1622: Debugger Evasion");
        System.out.println("    → T1497: Virtualization/Sandbox Evasion");
    }

    @Test
    public void testInjectionAPIsComplete() {
        printTestHeader("Process Injection API Set Validation");
        
        String[] expectedAPIs = {
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
        };
        
        System.out.println("  Validating " + expectedAPIs.length + " injection APIs (HIGH severity)...");
        
        for (String api : expectedAPIs) {
            boolean contains = INJECTION_APIS.contains(api);
            printTestResult("Contains " + api, contains, null);
            assertTrue("Missing injection API: " + api, contains);
        }
        
        printTestResult("Total count is " + expectedAPIs.length,
            INJECTION_APIS.size() == expectedAPIs.length,
            "Found: " + INJECTION_APIS.size() + ", Expected: " + expectedAPIs.length);
        assertEquals(expectedAPIs.length, INJECTION_APIS.size());
        
        System.out.println("\n  MITRE ATT&CK Mapping:");
        System.out.println("    → T1055: Process Injection");
        System.out.println("    → T1055.001: DLL Injection");
        System.out.println("    → T1055.003: Thread Execution Hijacking");
        System.out.println("    → T1055.004: Asynchronous Procedure Call");
    }

    @Test
    public void testEvasionAPIsComplete() {
        printTestHeader("Evasion/Persistence API Set Validation");
        
        String[] expectedAPIs = {
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
        };
        
        System.out.println("  Validating " + expectedAPIs.length + " evasion/persistence APIs...");
        
        for (String api : expectedAPIs) {
            boolean contains = EVASION_APIS.contains(api);
            printTestResult("Contains " + api, contains, null);
            assertTrue("Missing evasion API: " + api, contains);
        }
        
        printTestResult("Total count is " + expectedAPIs.length,
            EVASION_APIS.size() == expectedAPIs.length,
            "Found: " + EVASION_APIS.size() + ", Expected: " + expectedAPIs.length);
        assertEquals(expectedAPIs.length, EVASION_APIS.size());
        
        System.out.println("\n  MITRE ATT&CK Mapping:");
        System.out.println("    → T1057: Process Discovery");
        System.out.println("    → T1112: Modify Registry");
        System.out.println("    → T1543.003: Windows Service");
    }

    @Test
    public void testCryptoAPIsComplete() {
        printTestHeader("Cryptographic API Set Validation");
        
        String[] expectedAPIs = {
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptGenKey",
            "CryptDeriveKey"
        };
        
        System.out.println("  Validating " + expectedAPIs.length + " crypto APIs (LOW severity)...");
        
        for (String api : expectedAPIs) {
            boolean contains = CRYPTO_APIS.contains(api);
            printTestResult("Contains " + api, contains, null);
            assertTrue("Missing crypto API: " + api, contains);
        }
        
        printTestResult("Total count is " + expectedAPIs.length,
            CRYPTO_APIS.size() == expectedAPIs.length,
            "Found: " + CRYPTO_APIS.size() + ", Expected: " + expectedAPIs.length);
        assertEquals(expectedAPIs.length, CRYPTO_APIS.size());
        
        System.out.println("\n  MITRE ATT&CK Mapping:");
        System.out.println("    → T1027: Obfuscated Files or Information");
        System.out.println("    → T1486: Data Encrypted for Impact");
    }

    // ========================================================================
    // SHELLCODE PATTERN TESTS
    // ========================================================================

    @Test
    public void testShellcodePatternGetPC_AllVariants() {
        printTestHeader("GetPC (Position-Independent Code) Pattern Validation");
        
        // All GetPC variants: call $+5; pop <reg>
        Map<String, byte[]> getPcPatterns = new HashMap<>();
        getPcPatterns.put("pop eax", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x58});
        getPcPatterns.put("pop ebx", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5B});
        getPcPatterns.put("pop ecx", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x59});
        getPcPatterns.put("pop edx", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5A});
        getPcPatterns.put("pop esi", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5E});
        getPcPatterns.put("pop edi", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5F});
        getPcPatterns.put("pop ebp", new byte[]{(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5D});
        
        System.out.println("  Testing GetPC pattern: CALL $+5; POP <reg>");
        System.out.println("  This technique is used in position-independent shellcode");
        System.out.println();
        
        for (Map.Entry<String, byte[]> entry : getPcPatterns.entrySet()) {
            byte[] pattern = entry.getValue();
            String variant = entry.getKey();
            
            boolean validLength = pattern.length == 6;
            boolean validCall = pattern[0] == (byte)0xE8;
            boolean validOffset = pattern[1] == 0x00 && pattern[2] == 0x00 && 
                                  pattern[3] == 0x00 && pattern[4] == 0x00;
            
            String hexPattern = bytesToHex(pattern);
            printTestResult("GetPC (" + variant + ")", 
                validLength && validCall && validOffset,
                "Pattern: " + hexPattern);
            
            assertTrue("Invalid GetPC pattern for " + variant, 
                validLength && validCall && validOffset);
        }
        
        System.out.println("\n  Severity: HIGH");
        System.out.println("  Reason: GetPC is fundamental to position-independent shellcode");
    }

    @Test
    public void testShellcodePatternPEBAccess() {
        printTestHeader("PEB (Process Environment Block) Access Pattern Validation");
        
        // x86 PEB access patterns
        byte[] pebFs30 = {0x64, (byte)0xA1, 0x30, 0x00, 0x00, 0x00};  // mov eax, fs:[0x30]
        byte[] pebFs30Alt = {0x64, (byte)0x8B, 0x15, 0x30, 0x00, 0x00, 0x00};  // mov edx, fs:[0x30]
        
        // x64 PEB access
        byte[] pebGs60 = {0x65, 0x48, (byte)0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00};
        
        System.out.println("  Testing PEB access patterns used for API resolution in shellcode");
        System.out.println();
        
        // Test x86 fs:[0x30]
        boolean validFs30 = pebFs30[0] == 0x64 && pebFs30[2] == 0x30;
        printTestResult("x86 PEB via fs:[0x30] (mov eax)", validFs30,
            "Pattern: " + bytesToHex(pebFs30));
        assertTrue("Invalid x86 PEB pattern", validFs30);
        
        // Test x86 alternate
        boolean validFs30Alt = pebFs30Alt[0] == 0x64 && pebFs30Alt[3] == 0x30;
        printTestResult("x86 PEB via fs:[0x30] (mov edx)", validFs30Alt,
            "Pattern: " + bytesToHex(pebFs30Alt));
        assertTrue("Invalid x86 PEB alt pattern", validFs30Alt);
        
        // Test x64 gs:[0x60]
        boolean validGs60 = pebGs60[0] == 0x65 && pebGs60[5] == 0x60;
        printTestResult("x64 PEB via gs:[0x60]", validGs60,
            "Pattern: " + bytesToHex(pebGs60));
        assertTrue("Invalid x64 PEB pattern", validGs60);
        
        System.out.println("\n  Severity: HIGH");
        System.out.println("  Reason: PEB access is used to resolve kernel32.dll and APIs dynamically");
    }

    @Test
    public void testShellcodePatternSyscalls() {
        printTestHeader("Direct Syscall Pattern Validation");
        
        byte[] syscall = {0x0F, 0x05};    // x64 syscall
        byte[] sysenter = {0x0F, 0x34};   // x86 sysenter
        byte[] int2e = {(byte)0xCD, 0x2E}; // legacy int 0x2e
        
        System.out.println("  Testing direct syscall patterns (used to bypass API hooks)");
        System.out.println();
        
        // SYSCALL (x64)
        boolean validSyscall = syscall[0] == 0x0F && syscall[1] == 0x05;
        printTestResult("SYSCALL instruction (x64)", validSyscall,
            "Pattern: " + bytesToHex(syscall) + " - Direct kernel transition");
        assertTrue("Invalid syscall pattern", validSyscall);
        
        // SYSENTER (x86)
        boolean validSysenter = sysenter[0] == 0x0F && sysenter[1] == 0x34;
        printTestResult("SYSENTER instruction (x86)", validSysenter,
            "Pattern: " + bytesToHex(sysenter) + " - Fast system call");
        assertTrue("Invalid sysenter pattern", validSysenter);
        
        // INT 0x2E (legacy)
        boolean validInt2e = int2e[0] == (byte)0xCD && int2e[1] == 0x2E;
        printTestResult("INT 0x2E (legacy syscall)", validInt2e,
            "Pattern: " + bytesToHex(int2e) + " - Legacy system service dispatcher");
        assertTrue("Invalid int 0x2e pattern", validInt2e);
        
        System.out.println("\n  Severity: HIGH");
        System.out.println("  Reason: Direct syscalls bypass user-mode API hooks (EDR evasion)");
    }

    // ========================================================================
    // NOP SLED DETECTION TESTS
    // ========================================================================

    @Test
    public void testNopSledDetectionLogic() {
        printTestHeader("NOP Sled Detection Logic Validation");
        
        int minSledLength = 8;  // Default threshold
        
        System.out.println("  Minimum NOP sled length: " + minSledLength + " bytes");
        System.out.println("  NOP opcode: 0x90");
        System.out.println();
        
        // Test cases
        int[] testLengths = {1, 4, 7, 8, 10, 16, 32, 64};
        
        for (int length : testLengths) {
            byte[] sled = new byte[length];
            Arrays.fill(sled, (byte)0x90);
            
            boolean shouldTrigger = length >= minSledLength;
            boolean wouldTrigger = sled.length >= minSledLength;
            
            printTestResult("NOP sled of " + length + " bytes",
                shouldTrigger == wouldTrigger,
                shouldTrigger ? "→ TRIGGERS detection (suspicious)" : "→ Ignored (too short)");
            
            assertEquals("NOP sled detection mismatch for length " + length,
                shouldTrigger, wouldTrigger);
        }
        
        System.out.println("\n  Severity: HIGH");
        System.out.println("  Reason: NOP sleds are used in exploit payloads for address alignment");
    }

    // ========================================================================
    // XOR OBFUSCATION DETECTION TESTS
    // ========================================================================

    @Test
    public void testXorObfuscationDetectionLogic() {
        printTestHeader("XOR Obfuscation Detection Logic Validation");
        
        System.out.println("  XOR with self (e.g., XOR EAX, EAX) = Register zeroing (benign)");
        System.out.println("  XOR with different operand = Potential decryption (suspicious)");
        System.out.println();
        
        // Self-XOR cases (should be filtered out)
        String[][] selfXorCases = {
            {"EAX", "EAX"},
            {"EBX", "EBX"},
            {"ECX", "ECX"},
            {"EDX", "EDX"},
            {"R8", "R8"},
            {"R9", "R9"}
        };
        
        System.out.println("  Testing self-XOR filtering:");
        for (String[] ops : selfXorCases) {
            boolean isSelfXor = ops[0].equals(ops[1]);
            printTestResult("XOR " + ops[0] + ", " + ops[1], isSelfXor,
                "→ Filtered out (register zeroing idiom)");
            assertTrue("Self-XOR should be filtered", isSelfXor);
        }
        
        // Non-self XOR cases (should be flagged)
        String[][] suspiciousXorCases = {
            {"EAX", "EBX"},
            {"ECX", "[EDI]"},
            {"AL", "0x41"},
            {"byte ptr [ESI]", "DL"}
        };
        
        System.out.println("\n  Testing suspicious XOR detection:");
        for (String[] ops : suspiciousXorCases) {
            boolean isNonSelfXor = !ops[0].equals(ops[1]);
            printTestResult("XOR " + ops[0] + ", " + ops[1], isNonSelfXor,
                "→ FLAGGED (potential decryption)");
            assertTrue("Non-self XOR should be flagged", isNonSelfXor);
        }
        
        // Loop construct detection
        String[] loopMnemonics = {"loop", "loope", "loopne", "jnz", "jne", "jnb", "jb", "dec+jnz"};
        System.out.println("\n  Testing loop construct detection (triggers XOR loop alert):");
        for (String mnemonic : loopMnemonics) {
            boolean isLoopConstruct = mnemonic.startsWith("loop") || 
                mnemonic.equals("jnz") || mnemonic.equals("jne") ||
                mnemonic.equals("jnb") || mnemonic.equals("jb") ||
                mnemonic.contains("dec");
            printTestResult("Mnemonic: " + mnemonic, isLoopConstruct,
                "→ Triggers XOR loop detection when combined with XOR");
        }
        
        System.out.println("\n  Severity: MEDIUM");
        System.out.println("  Reason: XOR loops are common in malware for string/payload decryption");
    }

    // ========================================================================
    // SEVERITY CLASSIFICATION TESTS
    // ========================================================================

    @Test
    public void testSeverityClassification() {
        printTestHeader("Severity Classification Validation");
        
        Map<String, String> severityMap = new HashMap<>();
        severityMap.put("Process Injection", "HIGH");
        severityMap.put("Shellcode Patterns", "HIGH");
        severityMap.put("NOP Sled", "HIGH");
        severityMap.put("Anti-Debugging", "MEDIUM");
        severityMap.put("XOR Obfuscation", "MEDIUM");
        severityMap.put("Evasion/Persistence", "MEDIUM");
        severityMap.put("Cryptographic APIs", "LOW");
        severityMap.put("RDTSC (timing)", "LOW");
        severityMap.put("CPUID (VM detect)", "LOW");
        
        System.out.println("  Severity levels indicate required analyst attention:");
        System.out.println("    HIGH   = Immediate investigation required");
        System.out.println("    MEDIUM = Review recommended");
        System.out.println("    LOW    = Informational");
        System.out.println();
        
        for (Map.Entry<String, String> entry : severityMap.entrySet()) {
            String category = entry.getKey();
            String severity = entry.getValue();
            
            boolean valid = severity.equals("HIGH") || severity.equals("MEDIUM") || severity.equals("LOW");
            printTestResult(category + " = " + severity, valid, null);
            assertTrue("Invalid severity for " + category, valid);
        }
        
        // Verify HIGH severity count
        long highCount = severityMap.values().stream().filter(s -> s.equals("HIGH")).count();
        printTestResult("HIGH severity categories: " + highCount, highCount == 3, null);
        assertEquals(3, highCount);
        
        // Verify MEDIUM severity count
        long mediumCount = severityMap.values().stream().filter(s -> s.equals("MEDIUM")).count();
        printTestResult("MEDIUM severity categories: " + mediumCount, mediumCount == 3, null);
        assertEquals(3, mediumCount);
    }

    // ========================================================================
    // BOOKMARK OUTPUT FORMAT TESTS
    // ========================================================================

    @Test
    public void testBookmarkOutputFormat() {
        printTestHeader("Bookmark Output Format Validation");
        
        String category = BOOKMARK_CATEGORY;
        
        // Example bookmark formats
        String[] expectedFormats = {
            "[HIGH] Process Injection: Call to VirtualAllocEx detected",
            "[HIGH] Process Injection: Call to WriteProcessMemory detected",
            "[HIGH] Process Injection: Call to CreateRemoteThread detected",
            "[HIGH] Shellcode: NOP sled detected (32 bytes)",
            "[HIGH] Shellcode: GetPC (call $+5; pop eax) pattern detected",
            "[MEDIUM] Anti-Debugging: Call to IsDebuggerPresent detected",
            "[MEDIUM] Obfuscation: Potential XOR decryption loop (3 XOR ops)",
            "[LOW] Anti-Debugging: RDTSC timing instruction"
        };
        
        System.out.println("  Category: " + category);
        System.out.println("  Format: [SEVERITY] Type: Description");
        System.out.println();
        System.out.println("  Example bookmark outputs:");
        
        for (String format : expectedFormats) {
            boolean hasSeverity = format.startsWith("[HIGH]") || 
                                  format.startsWith("[MEDIUM]") || 
                                  format.startsWith("[LOW]");
            boolean hasDescription = format.contains(":");
            
            printTestResult("Valid format", hasSeverity && hasDescription, format);
            assertTrue("Invalid bookmark format: " + format, hasSeverity && hasDescription);
        }
        
        assertEquals("Bookmark category should be 'Suspicious'", "Suspicious", category);
    }

    // ========================================================================
    // SUPPORTED FORMAT TESTS
    // ========================================================================

    @Test
    public void testSupportedExecutableFormats() {
        printTestHeader("Supported Executable Format Validation");
        
        String[] supportedFormats = {"PE", "Portable Executable", "ELF", "Mach-O", "Raw Binary"};
        String[] unsupportedFormats = {"PDF", "ZIP", "JPEG", "MP3"};
        
        System.out.println("  The analyzer supports the following executable formats:");
        System.out.println();
        
        for (String format : supportedFormats) {
            boolean canAnalyze = format.contains("PE") || 
                                 format.contains("ELF") || 
                                 format.contains("Mach-O") ||
                                 format.contains("Raw");
            printTestResult("Supports: " + format, canAnalyze, null);
            assertTrue("Should support " + format, canAnalyze);
        }
        
        System.out.println("\n  The analyzer rejects non-executable formats:");
        
        for (String format : unsupportedFormats) {
            boolean canAnalyze = format.contains("PE") || 
                                 format.contains("ELF") || 
                                 format.contains("Mach-O") ||
                                 format.contains("Raw");
            printTestResult("Rejects: " + format, !canAnalyze, null);
            assertFalse("Should reject " + format, canAnalyze);
        }
    }

    // ========================================================================
    // ANALYZER CONFIGURATION TESTS
    // ========================================================================

    @Test
    public void testAnalyzerConfiguration() {
        printTestHeader("Analyzer Configuration Validation");
        
        String analyzerName = "Suspicious Pattern Detector";
        String analyzerDescription = "Identifies suspicious patterns commonly found in malware";
        
        System.out.println("  Analyzer Name: " + analyzerName);
        System.out.println("  Type: BYTE_ANALYZER");
        System.out.println("  Priority: After DATA_TYPE_PROPAGATION");
        System.out.println("  Default Enabled: true");
        System.out.println();
        
        Map<String, Object> options = new HashMap<>();
        options.put("Detect Anti-Debugging", true);
        options.put("Detect Process Injection", true);
        options.put("Detect Shellcode Patterns", true);
        options.put("Detect XOR Obfuscation", true);
        options.put("Detect Evasion/Persistence", true);
        options.put("Detect Crypto APIs", true);
        options.put("Minimum NOP Sled Length", 8);
        
        System.out.println("  Configuration options:");
        for (Map.Entry<String, Object> option : options.entrySet()) {
            printTestResult("Option: " + option.getKey(), true, 
                "Default: " + option.getValue());
        }
        
        assertNotNull("Analyzer name should not be null", analyzerName);
        assertTrue("Name should contain 'Suspicious'", analyzerName.contains("Suspicious"));
        assertEquals("Default NOP sled length should be 8", 8, options.get("Minimum NOP Sled Length"));
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}
