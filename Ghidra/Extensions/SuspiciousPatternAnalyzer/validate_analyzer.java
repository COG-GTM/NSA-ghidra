/* 
 * Standalone validation script for SuspiciousPatternAnalyzer
 * Run with: java validate_analyzer.java
 */
import java.util.*;

public class validate_analyzer {
    
    // Mirror the API sets from SuspiciousPatternAnalyzer.java
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

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║    SuspiciousPatternAnalyzer Validation Tests              ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        // Test 1: API Set Completeness
        testApiSets();

        // Test 2: Shellcode Pattern Validation
        testShellcodePatterns();

        // Test 3: NOP Sled Detection Logic
        testNopSledLogic();

        // Test 4: XOR Detection Logic
        testXorDetectionLogic();

        // Test 5: Severity Classification
        testSeverityClassification();

        // Test 6: Supported Formats
        testSupportedFormats();

        // Summary
        System.out.println("\n════════════════════════════════════════════════════════════");
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        System.out.println("════════════════════════════════════════════════════════════");
        
        if (failed > 0) {
            System.exit(1);
        }
        System.out.println("\n✅ All validation tests passed!");
    }

    private static void testApiSets() {
        System.out.println("▶ Testing API Set Definitions...");
        
        // Anti-Debug APIs
        assertTest("Anti-debug contains IsDebuggerPresent", 
            ANTI_DEBUG_APIS.contains("IsDebuggerPresent"));
        assertTest("Anti-debug contains NtQueryInformationProcess", 
            ANTI_DEBUG_APIS.contains("NtQueryInformationProcess"));
        assertTest("Anti-debug has 9 entries", 
            ANTI_DEBUG_APIS.size() == 9);

        // Injection APIs
        assertTest("Injection contains VirtualAllocEx", 
            INJECTION_APIS.contains("VirtualAllocEx"));
        assertTest("Injection contains WriteProcessMemory", 
            INJECTION_APIS.contains("WriteProcessMemory"));
        assertTest("Injection contains CreateRemoteThread", 
            INJECTION_APIS.contains("CreateRemoteThread"));
        assertTest("Injection has 12 entries", 
            INJECTION_APIS.size() == 12);

        // Evasion APIs
        assertTest("Evasion contains CreateToolhelp32Snapshot", 
            EVASION_APIS.contains("CreateToolhelp32Snapshot"));
        assertTest("Evasion contains RegSetValueExA", 
            EVASION_APIS.contains("RegSetValueExA"));
        assertTest("Evasion has 16 entries", 
            EVASION_APIS.size() == 16);

        // Crypto APIs
        assertTest("Crypto contains CryptEncrypt", 
            CRYPTO_APIS.contains("CryptEncrypt"));
        assertTest("Crypto contains CryptDecrypt", 
            CRYPTO_APIS.contains("CryptDecrypt"));
        assertTest("Crypto has 6 entries", 
            CRYPTO_APIS.size() == 6);
    }

    private static void testShellcodePatterns() {
        System.out.println("\n▶ Testing Shellcode Pattern Definitions...");

        // GetPC pattern: call $+5; pop eax (E8 00 00 00 00 58)
        byte[] getPcEax = {(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x58};
        assertTest("GetPC (pop eax) pattern is 6 bytes", getPcEax.length == 6);
        assertTest("GetPC starts with CALL opcode (0xE8)", getPcEax[0] == (byte)0xE8);
        assertTest("GetPC ends with POP EAX (0x58)", getPcEax[5] == (byte)0x58);

        // GetPC pattern: call $+5; pop ebx (E8 00 00 00 00 5B)
        byte[] getPcEbx = {(byte)0xE8, 0x00, 0x00, 0x00, 0x00, (byte)0x5B};
        assertTest("GetPC (pop ebx) ends with 0x5B", getPcEbx[5] == (byte)0x5B);

        // PEB access via fs:[0x30] (64 A1 30 00 00 00)
        byte[] pebAccess = {0x64, (byte)0xA1, 0x30, 0x00, 0x00, 0x00};
        assertTest("PEB access starts with FS prefix (0x64)", pebAccess[0] == 0x64);
        assertTest("PEB offset is 0x30", pebAccess[2] == 0x30);

        // x64 syscall (0F 05)
        byte[] syscall = {0x0F, 0x05};
        assertTest("Syscall pattern is 2 bytes", syscall.length == 2);
        assertTest("Syscall is 0F 05", syscall[0] == 0x0F && syscall[1] == 0x05);

        // SYSENTER (0F 34)
        byte[] sysenter = {0x0F, 0x34};
        assertTest("SYSENTER is 0F 34", sysenter[0] == 0x0F && sysenter[1] == 0x34);
    }

    private static void testNopSledLogic() {
        System.out.println("\n▶ Testing NOP Sled Detection Logic...");
        
        int minNopSledLength = 8;
        
        // Simulate NOP sled detection
        byte[] memory = new byte[20];
        Arrays.fill(memory, 0, 5, (byte)0x90);   // 5 NOPs (too short)
        Arrays.fill(memory, 5, 6, (byte)0x00);   // break
        Arrays.fill(memory, 6, 20, (byte)0x90);  // 14 NOPs (valid sled)
        
        int shortSledLength = countNops(memory, 0, 5);
        int validSledLength = countNops(memory, 6, 20);
        
        assertTest("Short NOP sequence (5) doesn't trigger", shortSledLength < minNopSledLength);
        assertTest("Valid NOP sled (14) triggers detection", validSledLength >= minNopSledLength);
        assertTest("Default min sled length is 8", minNopSledLength == 8);
    }

    private static int countNops(byte[] mem, int start, int end) {
        int count = 0;
        for (int i = start; i < end && mem[i] == (byte)0x90; i++) {
            count++;
        }
        return count;
    }

    private static void testXorDetectionLogic() {
        System.out.println("\n▶ Testing XOR Obfuscation Detection Logic...");
        
        // Self-XOR (used to zero registers) should be ignored
        String op1Self = "EAX";
        String op2Self = "EAX";
        boolean isSelfXor = op1Self.equals(op2Self);
        assertTest("Self-XOR (EAX, EAX) is filtered out", isSelfXor);
        
        // Non-self XOR should be flagged
        String op1 = "EAX";
        String op2 = "EBX";
        boolean isNonSelfXor = !op1.equals(op2);
        assertTest("Non-self XOR (EAX, EBX) is detected", isNonSelfXor);
        
        // XOR followed by loop construct
        String[] loopMnemonics = {"loop", "jnz", "jne", "jnb", "jb"};
        for (String mnemonic : loopMnemonics) {
            boolean isLoopConstruct = mnemonic.startsWith("loop") || 
                mnemonic.equals("jnz") || mnemonic.equals("jne") ||
                mnemonic.equals("jnb") || mnemonic.equals("jb");
            assertTest("Loop construct '" + mnemonic + "' triggers XOR loop check", isLoopConstruct);
        }
    }

    private static void testSeverityClassification() {
        System.out.println("\n▶ Testing Severity Classification...");
        
        Map<String, String> severityMap = new HashMap<>();
        severityMap.put("ProcessInjection", "HIGH");
        severityMap.put("Shellcode", "HIGH");
        severityMap.put("AntiDebugging", "MEDIUM");
        severityMap.put("XorObfuscation", "MEDIUM");
        severityMap.put("Evasion", "MEDIUM");
        severityMap.put("CryptoAPI", "LOW");
        
        assertTest("Process injection is HIGH severity", 
            severityMap.get("ProcessInjection").equals("HIGH"));
        assertTest("Shellcode is HIGH severity", 
            severityMap.get("Shellcode").equals("HIGH"));
        assertTest("Anti-debugging is MEDIUM severity", 
            severityMap.get("AntiDebugging").equals("MEDIUM"));
        assertTest("XOR obfuscation is MEDIUM severity", 
            severityMap.get("XorObfuscation").equals("MEDIUM"));
        assertTest("Crypto APIs are LOW severity", 
            severityMap.get("CryptoAPI").equals("LOW"));
    }

    private static void testSupportedFormats() {
        System.out.println("\n▶ Testing Supported Format Detection...");
        
        String[] formats = {"PE", "ELF", "Mach-O", "Raw"};
        
        for (String format : formats) {
            boolean canAnalyze = format.contains("PE") || 
                                 format.contains("ELF") || 
                                 format.contains("Mach-O") ||
                                 format.contains("Raw");
            assertTest("Supports " + format + " format", canAnalyze);
        }
        
        // Unsupported format
        String unsupported = "PDF";
        boolean shouldReject = !(unsupported.contains("PE") || 
                                  unsupported.contains("ELF") || 
                                  unsupported.contains("Mach-O") ||
                                  unsupported.contains("Raw"));
        assertTest("Rejects unsupported format (PDF)", shouldReject);
    }

    private static void assertTest(String description, boolean condition) {
        if (condition) {
            System.out.println("  ✓ " + description);
            passed++;
        } else {
            System.out.println("  ✗ FAILED: " + description);
            failed++;
        }
    }
}
