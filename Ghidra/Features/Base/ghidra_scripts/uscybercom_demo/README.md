# USCYBERCOM Demo Materials

This directory contains demo materials for demonstrating Cognition AI capabilities (Devin and Windsurf) to US Cyber Command, mapped to the USCYBERCOM Problem Set 3rd Edition.

## Demo Overview

| Demo | USCYBERCOM Problem | Cognition Tool | Description |
|------|-------------------|----------------|-------------|
| Demo 2 | 4.8, 3.1, 1.1 | Devin | Malware Analysis Automation Script |
| Demo 3 | 5.3 | Devin | Autonomous Bug Fix / Test Coverage |

---

## Demo 2: Malware Analysis Automation Script

**USCYBERCOM Problem Alignment:**
- Problem 4.8 (Cyber Analysis Tools)
- Problem 3.1 (AI-assisted Threat Hunting)
- Problem 1.1 (Threat Detection)

### Prompt to Copy/Paste into Ask Devin

```
Create a PyGhidra script for NSA-ghidra that automates malware triage and IOC extraction. The script should:

1. Detect suspicious Windows API calls commonly used by malware:
   - Process injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
   - Credential theft (CredEnumerate, LsaRetrievePrivateData)
   - Persistence (RegSetValueEx, CreateService)
   - Anti-analysis/evasion (IsDebuggerPresent, CheckRemoteDebuggerPresent)
   - Network communication (InternetOpen, WSAStartup, socket, connect)
   - Cryptographic operations (CryptEncrypt, BCryptEncrypt)

2. Extract network IOCs from strings (IP addresses, URLs, domains, emails)

3. Calculate a threat score (0-100) based on findings

4. Output a structured report suitable for SIEM integration

Build on the existing YARA integration pattern at Ghidra/Features/Base/ghidra_scripts/RunYARAFromGhidra.py

Repo: COG-GTM/NSA-ghidra
```

### What Devin Will Produce

The script (`MalwareTriageScript.py`) will:
- Scan for 60+ suspicious Windows API calls across 7 categories
- Extract IP addresses, URLs, domains, and email addresses from strings
- Detect encryption-related patterns (potential ransomware indicators)
- Calculate a threat score (0-100) with severity classification
- Output a structured JSON report for SIEM/SOAR integration

### Sample Output

```
======================================================================
AUTOMATED MALWARE TRIAGE SCRIPT
USCYBERCOM Problem Set: 4.8 (Cyber Analysis Tools) + 3.1 (AI Threat Hunting)
======================================================================

[*] Analyzing: suspicious_sample.exe
[1/5] Extracting strings...
[2/5] Scanning for suspicious API calls...
[3/5] Extracting network IOCs...
[4/5] Detecting encryption patterns...
[5/5] Calculating threat score...

THREAT SCORE: 75/100 (HIGH)

SUSPICIOUS API CALLS:
  [PROCESS_INJECTION] (3 found)
    - VirtualAllocEx @ 0x00401234 [HIGH]
    - WriteProcessMemory @ 0x00401256 [HIGH]
    - CreateRemoteThread @ 0x00401278 [HIGH]
  [NETWORK] (2 found)
    - InternetOpenA @ 0x00402000 [MEDIUM]
    - HttpSendRequestA @ 0x00402100 [MEDIUM]

NETWORK IOCs:
  [IP_ADDRESSES] (1 found)
    - 192.168.1.100
  [URLS] (1 found)
    - http://malicious-c2.com/beacon
```

---

## Demo 3: Autonomous Bug Fix / Test Coverage

**USCYBERCOM Problem Alignment:**
- Problem 5.3 (Automated Incident Response)

### Option A: Find and Fix a Bug

#### Prompt to Copy/Paste into Ask Devin

```
Analyze the memory search feature in NSA-ghidra and identify any issues with regular expression matching, particularly around buffer boundary handling. If you find a bug, propose and implement a fix with appropriate tests.

Focus on these files:
- Ghidra/Features/Base/src/main/java/ghidra/features/base/memsearch/matcher/RegExByteMatcher.java
- Ghidra/Features/Base/src/main/java/ghidra/features/base/memsearch/searcher/MemorySearcher.java

Repo: COG-GTM/NSA-ghidra
```

### Option B: Add Test Coverage

#### Prompt to Copy/Paste into Ask Devin

```
Analyze the Ghidra Decompiler module and add unit test coverage for under-tested classes. Focus on:

1. Identify classes in Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/ that have no corresponding test files
2. Create comprehensive unit tests for at least one of these classes (e.g., ClangToken classes or PrettyPrinter.java)
3. Ensure tests follow existing test patterns in the codebase

Repo: COG-GTM/NSA-ghidra
```

### What Devin Will Demonstrate

- **Code Understanding:** Devin analyzes complex multi-file interactions in a 15,000+ file codebase
- **Bug Detection:** Identifies root causes of issues (e.g., buffer boundary handling)
- **Production-Quality Fixes:** Implements fixes with appropriate test coverage
- **Audit Trail:** All changes logged via Deep Wiki for provenance and compliance

---

## Key Talking Points

1. **NSA-ghidra is USCYBERCOM's flagship tool** - Demonstrating AI enhancement of their own open-source project is immediately relevant

2. **Already Deployed in DoD** - Windsurf at Army Software Factory, Treasury (2,500 licenses), NAVAIR, NASA

3. **FedRAMP High / IL5-IL6 Ready** - Windsurf is the only AI-assisted coding tool authorized for Army use

4. **Explainable AI** - Every action logged via Deep Wiki for provenance and auditability (addresses Problem 3.3)

5. **Federal Security Compliance** - STIG-compliant code suggestions (V-220629 through V-220641)

---

## Files in This Directory

- `README.md` - This file (demo instructions and prompts)
- `MalwareTriageScript.py` - Ready-to-run malware analysis script (Demo 2 output)

---

**Prepared by:** Devin (Cognition AI)  
**For:** Jake Cosme, Cognition AI  
**Meeting:** US Cyber Command Demo
