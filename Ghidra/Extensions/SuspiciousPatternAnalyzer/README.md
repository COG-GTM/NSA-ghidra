# Suspicious Pattern Analyzer for Ghidra

A Ghidra extension that automatically detects suspicious patterns commonly found in malware during binary analysis. This analyzer helps security researchers and malware analysts quickly identify potentially malicious code by flagging anti-debugging techniques, process injection APIs, shellcode patterns, and obfuscation indicators.

## Value Proposition

### Problem
Manual malware analysis is time-consuming. Analysts must search through thousands of functions looking for indicators of malicious behavior. Common patterns like anti-debugging checks, process injection, and shellcode are easy to miss in large binaries.

### Solution
This analyzer **automatically scans binaries** and creates navigable bookmarks for suspicious patterns, allowing analysts to:
- **Save hours** of manual review time
- **Prioritize analysis** by severity (HIGH/MEDIUM/LOW)
- **Never miss** common malware techniques
- **Document findings** for reports with standardized categories

## Features

### 1. Anti-Debugging Detection
Flags calls to APIs commonly used to detect debuggers:
- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess`, `NtSetInformationThread`
- Timing-based checks (`QueryPerformanceCounter`, `GetTickCount`, `RDTSC`)
- `INT 2D` instruction (debugger detection)

### 2. Process Injection Detection (HIGH Severity)
Identifies API patterns used for code injection:
- `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- `NtMapViewOfSection`, `NtUnmapViewOfSection`
- `QueueUserAPC`, `SetWindowsHookEx`
- `RtlCreateUserThread`, `NtWriteVirtualMemory`

### 3. Shellcode Pattern Detection (HIGH Severity)
Recognizes common shellcode constructs:
- **NOP sleds** (configurable minimum length)
- **GetPC techniques** (`CALL $+5; POP reg`) for position-independent code
- **PEB access** via `FS:[0x30]` (x86) or `GS:[0x60]` (x64)
- **Direct syscalls** (`SYSCALL`, `SYSENTER` instructions)

### 4. Obfuscation Detection
Identifies encryption/decoding routines:
- **XOR loops** used for string/payload decryption
- XOR with non-self operands followed by loop constructs

### 5. Evasion & Persistence Detection
Flags APIs used for:
- Process enumeration (`CreateToolhelp32Snapshot`, `Process32Next`)
- Process manipulation (`OpenProcess`, `TerminateProcess`)
- Registry persistence (`RegSetValueEx`)
- Service creation (`CreateService`, `StartService`)

### 6. Cryptographic API Detection
Tracks usage of Windows Crypto APIs:
- `CryptEncrypt`, `CryptDecrypt`
- `CryptAcquireContext`, `CryptGenKey`, `CryptDeriveKey`

## Installation

### Building from Source

```bash
# From Ghidra root directory
cd /path/to/ghidra
gradle -p Ghidra/Extensions/SuspiciousPatternAnalyzer buildExtension
```

The built extension will be in:
```
Ghidra/Extensions/SuspiciousPatternAnalyzer/dist/
```

### Installing the Extension

1. Open Ghidra
2. Go to **File → Install Extensions**
3. Click the **+** button
4. Navigate to the `.zip` file in the `dist/` directory
5. Restart Ghidra

## Usage

### Automatic Analysis
The analyzer runs automatically when you import a binary. Findings appear as **WARNING bookmarks** in the Bookmark window.

### Manual Analysis
1. Open **Analysis → One Shot → Suspicious Pattern Detector**
2. Select address range to analyze
3. Review findings in the Bookmark window

### Navigating Findings
1. Open **Window → Bookmarks**
2. Filter by category: **Suspicious**
3. Double-click any bookmark to navigate to the finding
4. Sort by severity in the comment column

### Configuration Options
Go to **Analysis → Auto Analyze → Suspicious Pattern Detector** to configure:

| Option | Default | Description |
|--------|---------|-------------|
| Detect Anti-Debugging | ✓ | Flag anti-debugging API calls |
| Detect Process Injection | ✓ | Flag injection-related APIs (HIGH severity) |
| Detect Shellcode Patterns | ✓ | Find NOP sleds, GetPC, PEB access |
| Detect XOR Obfuscation | ✓ | Identify XOR-based decryption loops |
| Detect Evasion/Persistence | ✓ | Flag process enumeration & persistence APIs |
| Detect Crypto APIs | ✓ | Track cryptographic function usage |
| Minimum NOP Sled Length | 8 | Consecutive NOPs required to flag as sled |

## Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **HIGH** | 🔴 | Immediate attention: process injection, shellcode |
| **MEDIUM** | 🟡 | Suspicious: anti-debugging, XOR loops, evasion |
| **LOW** | 🟢 | Informational: crypto APIs, RDTSC, CPUID |

## Example Output

After analysis, the Bookmark window shows:
```
Address      | Category   | Description
-------------|------------|--------------------------------------------
0x00401234   | Suspicious | [HIGH] Process Injection: Call to VirtualAllocEx detected
0x00401256   | Suspicious | [HIGH] Process Injection: Call to WriteProcessMemory detected
0x00401280   | Suspicious | [HIGH] Process Injection: Call to CreateRemoteThread detected
0x00402000   | Suspicious | [HIGH] Shellcode: NOP sled detected (32 bytes)
0x00402100   | Suspicious | [HIGH] Shellcode: GetPC (call $+5; pop eax) pattern detected
0x00403000   | Suspicious | [MEDIUM] Anti-Debugging: Call to IsDebuggerPresent detected
0x00403050   | Suspicious | [MEDIUM] Obfuscation: Potential XOR decryption loop (3 XOR ops)
0x00404000   | Suspicious | [LOW] Anti-Debugging: RDTSC timing instruction
```

## Technical Details

### Supported Formats
- **PE** (Windows executables, DLLs)
- **ELF** (Linux executables, shared objects)
- **Mach-O** (macOS executables)
- **Raw** binary files

### Analysis Type
- **Byte Analyzer** - Scans raw bytes for patterns
- **Priority** - Runs after data type propagation

### Performance
- Efficient byte pattern matching using `MemoryBytePatternSearcher`
- Parallel-friendly design
- Configurable to skip irrelevant checks

## Use Cases

1. **Malware Triage** - Quickly assess if a sample exhibits malicious behavior
2. **Incident Response** - Identify IOCs in suspicious binaries
3. **Threat Intelligence** - Catalog techniques used by malware families
4. **Red Team Tool Analysis** - Understand evasion techniques
5. **Student Learning** - Understand common malware patterns

## Extending the Analyzer

To add new detection patterns, modify:
- `ANTI_DEBUG_APIS` - Add API names to detect
- `INJECTION_APIS` - Add injection-related APIs
- `findShellcodeSequences()` - Add byte patterns
- `scanForSuspiciousInstructions()` - Add instruction-based detections

## License

Apache License 2.0 - See LICENSE file

## Credits

Created with Windsurf AI assistance demonstrating:
- Codebase understanding of Ghidra's analyzer architecture
- Domain expertise in malware analysis techniques
- Production-quality plugin development
