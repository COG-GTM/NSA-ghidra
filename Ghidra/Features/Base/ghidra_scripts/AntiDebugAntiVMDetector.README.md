# AntiDebugAntiVMDetector — Anti-Debug / Anti-VM detector for Ghidra

A Ghidra script for federal reverse-engineering analysts that scans the
currently-loaded program for the most common anti-debugging and anti-VM
techniques and annotates the listing in place.

The script is a single Java file plus a synthetic test fixture, all under
`Ghidra/Features/Base/ghidra_scripts/`:

| File | Purpose |
|------|---------|
| `AntiDebugAntiVMDetector.java` | The detector script. |
| `AntiDebugAntiVMDetector.README.md` | This document. |
| `AntiDebugAntiVMDetector_build_fixture.py` | Builder for the synthetic PE32 test fixture (`AntiDebugAntiVMDetector_fixture.bin`). The repository follows Ghidra's contribution policy of *not* committing self-generated binaries; the analyst regenerates the fixture locally before running the self-test (see below). |

## What the script detects

| Category | Technique | How it is matched |
|----------|-----------|-------------------|
| AntiDebug | `IsDebuggerPresent` | Symbol references (incl. IAT indirection). |
| AntiDebug | `CheckRemoteDebuggerPresent` | Symbol references. |
| AntiDebug | `NtQueryInformationProcess` / `ZwQueryInformationProcess` | Symbol references. |
| AntiDebug | `NtSetInformationThread` / `ZwSetInformationThread` (`ThreadHideFromDebugger`) | Symbol references. |
| AntiDebug | `OutputDebugStringA` / `OutputDebugStringW` debugger probe | Symbol references. |
| AntiDebug | Manual SEH / VEH (`AddVectoredExceptionHandler`, `SetUnhandledExceptionFilter`) | Symbol references. |
| AntiDebug | PEB / NtGlobalFlag access via `fs:[0x30]` (x86), `gs:[0x60]` (x64), TEB self at `fs:[0x18]` / `gs:[0x30]` | Operand text + offset. |
| AntiDebug | RDTSC / RDTSCP timing checks | Mnemonic match. |
| AntiDebug | CPUID timing / feature probe | Mnemonic match. |
| AntiDebug | INT 3 anchor (single `0xCC`) | Mnemonic match. |
| AntiDebug | INT 3 (`0xCC`) scan loop | `cmp ?, 0xCC` pattern. |
| AntiVM | CPUID hypervisor leaf `0x40000000` brand-string probe | `mov eax, 0x40000000` followed by `cpuid` (within 4 instructions). |
| AntiVM | VMware backdoor `IN` / `OUT` against port `0x5658` ('VX') with `'VMXh'` magic | Mnemonic + small backwards window for `mov dx, 0x5658` / `mov eax, 0x564D5868`. |
| AntiVM | Hypervisor brand strings (`KVMKVMKVM`, `Microsoft Hv`, `VMwareVMware`, `XenVMMXenVMM`, `prl hyperv  `, `VBoxVBoxVBox`) | Defined-data string scan + reference walk. |
| AntiVM | Anti-VM artefact strings (`VMware`, `VirtualBox`, `QEMU`, `Xen`, `Parallels`, `Sandboxie`) | Defined-data string scan + reference walk. |

For every finding the script:

1. Adds a `NOTE` bookmark in category `AntiDebug` or `AntiVM`.
2. Sets a `PRE` comment on the offending instruction explaining the technique.
3. Renames the containing function with prefix `antidbg_` / `antivm_`,
   preserving the original name as a suffix
   (e.g. `FUN_00401000` → `antidbg_FUN_00401000`).
4. Applies a function tag of `AntiDebug` or `AntiVM` so the function tree can
   be filtered with the **Function Tag Window**.

At the end of the run the script writes a Markdown report next to the
imported program (`<program>.antidebug-report.md`) summarising every finding
with technique name, address, containing function, and a one-sentence
operational interpretation. If file I/O is blocked, the report is printed to
the script console instead.

## Running the detector from the Ghidra UI

1. Open a program in CodeBrowser and let auto-analysis finish.
2. Open **Window → Script Manager**.
3. Find **AntiDebugAntiVMDetector** under the *Analysis* category.
4. Click the green run arrow.
5. Answer **No** to the self-test prompt for a normal scan, or **Yes** to
   validate against the bundled fixture.
6. Inspect the new bookmarks (**Window → Bookmarks**), function tags
   (**Window → Function Tags**), and the generated Markdown report.

## Running headless

```sh
support/analyzeHeadless <project_dir> <project_name> \
    -import path/to/sample.exe \
    -postScript AntiDebugAntiVMDetector.java
```

To run the self-test in headless mode, build the fixture first (it is **not**
committed to the repository), then point `analyzeHeadless` at the freshly
built `.bin` and pass `--selftest` as a script argument:

```sh
python3 Ghidra/Features/Base/ghidra_scripts/AntiDebugAntiVMDetector_build_fixture.py
support/analyzeHeadless <project_dir> <project_name> \
    -import Ghidra/Features/Base/ghidra_scripts/AntiDebugAntiVMDetector_fixture.bin \
    -scriptPath Ghidra/Features/Base/ghidra_scripts \
    -postScript AntiDebugAntiVMDetector.java --selftest \
    -deleteProject
```

The builder script has no third-party dependencies (Python 3 standard library
only) and produces a deterministic 2 048-byte PE32 every time, so the
`-import` path above is stable across runs and machines.

The script throws an `AssertionError` if any required technique is missing,
which causes `analyzeHeadless` to exit non-zero.

## Self-test against the synthetic fixture

The builder produces `AntiDebugAntiVMDetector_fixture.bin`, a hand-crafted,
intentionally *non-runnable* PE32 (file extension `.bin` so it cannot be
double-clicked). Its entry point is a single `int 3` followed by a `ret` and
then the synthetic detection patterns -- it does not perform any real action
when loaded.

Build it locally before running the self-test:

```sh
python3 Ghidra/Features/Base/ghidra_scripts/AntiDebugAntiVMDetector_build_fixture.py
```

The builder uses only the Python 3 standard library and produces the same
2 048-byte file every time. The fixture is **not** committed to the repository
(per Ghidra's `CONTRIBUTING.md` policy on self-generated binaries) and is
regenerated on demand.

The fixture exercises every detection branch in the script:

- Calls (via the IAT) to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
  `NtQueryInformationProcess`, `NtSetInformationThread`, `OutputDebugStringA`,
  `AddVectoredExceptionHandler`, and `SetUnhandledExceptionFilter`.
- An RDTSC / RDTSC pair with `sub eax, esi` between them.
- `CPUID` with `EAX = 0x40000000` (hypervisor brand probe) and a generic
  leaf-1 `CPUID`.
- A bare `INT 3` byte followed by an `INT 3` scan loop
  (`cmp byte ptr [esi], 0xCC; je $+4`).
- The VMware backdoor sequence (`mov eax, 'VMXh'; mov dx, 0x5658; in/out`).
- `mov eax, fs:[0x30]`, `mov eax, fs:[0x18]`, and `mov eax, fs:[0x60]`.
- 12 anti-VM strings (six hypervisor brands plus six artefact names),
  each referenced by code.

## Walkthrough — what to expect on the fixture

After running the script with **Self-test mode = Yes** against the bundled
fixture, the script console prints a checklist of detections:

```
[+] AntiDebugAntiVMDetector running in self-test mode.
[+] Win32 IsDebuggerPresent: 1 (>= 1)
[+] Win32 CheckRemoteDebuggerPresent: 1 (>= 1)
[+] Native NtQueryInformationProcess: 1 (>= 1)
[+] ThreadHideFromDebugger: 1 (>= 1)
[+] OutputDebugString debugger probe: 1 (>= 1)
[+] Manual VEH debugger detection: 1 (>= 1)
[+] Manual SEH debugger detection: 1 (>= 1)
[+] RDTSC timing check: 2 (>= 2)
[+] CPUID hypervisor leaf 0x40000000: 1 (>= 1)
[+] CPUID timing/feature probe: 1 (>= 1)
[+] INT3 (0xCC) anchor: 1 (>= 1)
[+] INT3 (0xCC) scan loop: 1 (>= 1)
[+] VMware backdoor port IN: 1 (>= 1)
[+] VMware backdoor port OUT: 1 (>= 1)
[+] fs:[0x30] PEB access: 1 (>= 1)
[+] fs:[0x18] TEB self-pointer: 1 (>= 1)
[+] Hypervisor brand string 'KVMKVMKVM': ...
... (one line per anti-VM string) ...
[+] Self-test PASSED -- all required techniques detected.
```

Open the **Bookmark Manager** afterwards to see one bookmark per finding,
grouped by `AntiDebug` and `AntiVM` categories. The single function in the
fixture is renamed to a name like `antidbg_FUN_00401000` and tagged with both
`AntiDebug` and `AntiVM`.

## Operational interpretation

- An *AntiDebug* hit means the binary is actively trying to detect an
  attached debugger. Treat each call site as a candidate patch point before
  running the sample under a dynamic analysis harness.
- An *AntiVM* hit means the binary is actively trying to detect a virtualised
  or sandboxed execution environment. Investigate before executing on shared
  analysis VMs -- the sample may behave differently (or not at all) compared
  to bare-metal.

## Limitations / known gaps

- Detection is purely static and pattern-based. Dynamically constructed
  syscall numbers, encrypted strings, and obfuscated control flow can hide
  techniques from this script.
- The PEB-offset detection relies on the disassembler emitting a textual
  `fs:` / `gs:` segment override. If the language definition for an exotic
  PE variant doesn't, that branch will silently skip.
- The INT-3 scan-loop heuristic flags any `cmp ?, 0xCC` instruction and may
  produce false positives in code that legitimately compares against
  `0xCC` for non-debug reasons.
