#!/usr/bin/env python3
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Builds a small, benign synthetic PE32 fixture that exercises every detection
# branch in AntiDebugAntiVMDetector.java.  The output is intentionally NOT a
# runnable program -- the entry point is a single int3 followed by ret -- and
# the file is written with a .bin extension so it cannot be double-clicked into
# execution.  Ghidra still recognises it as a PE32 by magic and runs the full
# import / disassembly / string analysis pipeline against it.
#
# Usage (from a checkout of this repo):
#   python3 AntiDebugAntiVMDetector_build_fixture.py
#
# Re-run after editing if the fixture needs to be regenerated.  The output is
# fully deterministic.

import os
import struct
import sys

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def pad_to(buf, target_len, fill=b"\x00"):
    if len(buf) > target_len:
        raise ValueError("buffer already exceeds target length")
    return buf + fill * (target_len - len(buf))


# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

IMAGE_BASE       = 0x00400000
SECTION_ALIGN    = 0x00001000
FILE_ALIGN       = 0x00000200
ENTRY_RVA        = 0x00001000      # start of .text
TEXT_RVA         = 0x00001000
RDATA_RVA        = 0x00002000
IDATA_RVA        = 0x00003000
SIZE_OF_HEADERS  = 0x00000200

# ---------------------------------------------------------------------------
# Imports table description
# ---------------------------------------------------------------------------
# Two DLLs, with the functions in the order they will be called from .text.
# Order matters: it determines IAT slot indices, which we patch into the
# call-through-IAT instructions below.

IMPORTS = [
    ("KERNEL32.dll", [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "AddVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
    ]),
    ("ntdll.dll", [
        "NtQueryInformationProcess",
        "NtSetInformationThread",
    ]),
]


# ---------------------------------------------------------------------------
# Strings emitted in .rdata
# ---------------------------------------------------------------------------
# Each tuple is (label, byte string). We keep null terminators explicit so
# Ghidra's string analyser locks onto each entry as a separate string.

ANTI_VM_STRINGS = [
    ("HV_KVM",       b"KVMKVMKVM\x00\x00\x00\x00"),
    ("HV_MS_HV",     b"Microsoft Hv\x00"),
    ("HV_VMWARE",    b"VMwareVMware\x00"),
    ("HV_XEN",       b"XenVMMXenVMM\x00"),
    ("HV_PARALLELS", b"prl hyperv  \x00"),
    ("HV_VBOX",      b"VBoxVBoxVBox\x00"),
    ("S_VMWARE",     b"VMware\x00"),
    ("S_VBOX",       b"VirtualBox\x00"),
    ("S_QEMU",       b"QEMU\x00"),
    ("S_XEN",        b"Xen\x00"),
    ("S_PARALLELS",  b"Parallels\x00"),
    ("S_SANDBOXIE",  b"Sandboxie\x00"),
]


# ---------------------------------------------------------------------------
# Build .idata
# ---------------------------------------------------------------------------
# Layout inside .idata (offsets from IDATA_RVA):
#   IID (Import Directory Table)   : (N+1) * 0x14 bytes
#   For each DLL:
#     ILT (Import Lookup Table)    : (M+1) * 4 bytes
#     IAT (Import Address Table)   : (M+1) * 4 bytes
#     DLL name                     : null-terminated
#     For each function:
#       Hint (2 bytes) + name + null
#
# We pre-compute every offset so we can patch IAT slot addresses into .text.

def build_idata():
    blob = bytearray()
    iid_size = (len(IMPORTS) + 1) * 0x14   # one extra null IID
    cursor = iid_size

    iid_entries = []          # (ilt_rva, iat_rva, name_rva)
    iat_slot_rvas = {}        # function name -> RVA of its IAT slot

    # First pass: assign offsets for each DLL's ILT, IAT, name, hint/name table
    per_dll_layout = []
    for (dll_name, funcs) in IMPORTS:
        ilt_offset = cursor
        cursor += (len(funcs) + 1) * 4
        iat_offset = cursor
        cursor += (len(funcs) + 1) * 4
        name_offset = cursor
        cursor += len(dll_name) + 1
        # Hint/name entries (2-byte hint + name + null, 2-byte aligned)
        hint_name_offsets = []
        for fn in funcs:
            if cursor & 1:
                cursor += 1
            hint_name_offsets.append(cursor)
            cursor += 2 + len(fn) + 1
        per_dll_layout.append({
            "dll": dll_name,
            "funcs": funcs,
            "ilt": ilt_offset,
            "iat": iat_offset,
            "name": name_offset,
            "hint_names": hint_name_offsets,
        })

    # Second pass: emit IID table, then per-DLL ILT/IAT/strings
    blob = bytearray(b"\x00" * iid_size)

    # Per-DLL data first; we'll splice in
    body = bytearray(b"\x00" * (cursor - iid_size))

    def write_at(buf, off, data):
        buf[off:off + len(data)] = data

    # Patch IIDs
    for i, layout in enumerate(per_dll_layout):
        ilt_rva  = IDATA_RVA + layout["ilt"]
        iat_rva  = IDATA_RVA + layout["iat"]
        name_rva = IDATA_RVA + layout["name"]
        # IMAGE_IMPORT_DESCRIPTOR (20 bytes):
        #   OriginalFirstThunk (ILT RVA) | TimeDateStamp | ForwarderChain |
        #   Name RVA | FirstThunk (IAT RVA)
        iid = struct.pack("<5I", ilt_rva, 0, 0, name_rva, iat_rva)
        blob[i * 0x14:(i + 1) * 0x14] = iid

    # ILT/IAT entries + name strings + hint/names
    for layout in per_dll_layout:
        # ILT and IAT both reference Hint/Name RVA, with high bit clear
        for j, fn in enumerate(layout["funcs"]):
            hint_name_rva = IDATA_RVA + layout["hint_names"][j]
            entry = struct.pack("<I", hint_name_rva)
            ilt_pos = layout["ilt"] - iid_size + j * 4
            iat_pos = layout["iat"] - iid_size + j * 4
            write_at(body, ilt_pos, entry)
            write_at(body, iat_pos, entry)
            # remember slot for .text patching
            iat_slot_rvas[fn] = IMAGE_BASE + IDATA_RVA + layout["iat"] + j * 4
            # hint/name table
            hn = struct.pack("<H", 0) + fn.encode("ascii") + b"\x00"
            write_at(body, layout["hint_names"][j] - iid_size, hn)
        # DLL name string
        write_at(body, layout["name"] - iid_size,
                 layout["dll"].encode("ascii") + b"\x00")

    return bytes(blob) + bytes(body), iat_slot_rvas


# ---------------------------------------------------------------------------
# Build .rdata (anti-VM strings)
# ---------------------------------------------------------------------------

def build_rdata():
    blob = bytearray()
    string_rvas = {}
    for label, data in ANTI_VM_STRINGS:
        string_rvas[label] = IMAGE_BASE + RDATA_RVA + len(blob)
        blob += data
    # 4-byte align tail
    while len(blob) & 3:
        blob.append(0)
    return bytes(blob), string_rvas


# ---------------------------------------------------------------------------
# Build .text -- raw x86-32 bytes covering every detection branch
# ---------------------------------------------------------------------------

def build_text(iat_slots, string_rvas):
    """Return the raw bytes for the .text section.  Every detection branch in
    AntiDebugAntiVMDetector.java triggers on something here."""
    code = bytearray()

    def call_iat(name):
        # call dword ptr [absolute32]   (FF 15 imm32)
        code.extend(b"\xFF\x15")
        code.extend(struct.pack("<I", iat_slots[name]))

    def mov_eax_imm32(value):
        # B8 imm32
        code.extend(b"\xB8")
        code.extend(struct.pack("<I", value & 0xFFFFFFFF))

    # ---- Anti-debug API calls (one of every kind) ----
    call_iat("IsDebuggerPresent")
    call_iat("CheckRemoteDebuggerPresent")
    call_iat("NtQueryInformationProcess")
    call_iat("NtSetInformationThread")
    call_iat("OutputDebugStringA")
    call_iat("AddVectoredExceptionHandler")
    call_iat("SetUnhandledExceptionFilter")

    # ---- RDTSC / RDTSC timing pair ----
    code.extend(b"\x0F\x31")             # rdtsc
    code.extend(b"\x8B\xF0")             # mov esi, eax
    code.extend(b"\x0F\x31")             # rdtsc
    code.extend(b"\x2B\xC6")             # sub eax, esi

    # ---- CPUID hypervisor leaf 0x40000000 ----
    mov_eax_imm32(0x40000000)
    code.extend(b"\x0F\xA2")             # cpuid

    # ---- Generic CPUID (leaf 1) ----
    mov_eax_imm32(0x00000001)
    code.extend(b"\x0F\xA2")             # cpuid

    # ---- INT3 scan loop body: cmp byte ptr [esi], 0xCC ----
    # NOTE: this comes BEFORE the INT3 anchor so Ghidra's recursive
    # disassembler doesn't bail at the INT3 byte and skip everything that
    # follows.  The bare INT3 anchor is emitted at the very end.
    code.extend(b"\x80\x3E\xCC")         # cmp byte ptr [esi], 0xCC
    code.extend(b"\x74\x02")             # jz $+4
    code.extend(b"\x90\x90")             # nop nop

    # ---- VMware backdoor I/O ----
    mov_eax_imm32(0x564D5868)            # 'VMXh'
    code.extend(b"\xB9\x0A\x00\x00\x00") # mov ecx, 0x0A
    code.extend(b"\x66\xBA\x58\x56")     # mov dx, 0x5658
    code.extend(b"\xED")                 # in eax, dx
    code.extend(b"\xEF")                 # out dx, eax (also detected)

    # ---- PEB / TEB segment-override accesses ----
    code.extend(b"\x64\xA1\x30\x00\x00\x00")  # mov eax, fs:[0x30]   (PEB)
    code.extend(b"\x64\xA1\x18\x00\x00\x00")  # mov eax, fs:[0x18]   (TEB self)
    code.extend(b"\x64\xA1\x60\x00\x00\x00")  # mov eax, fs:[0x60]   (also seen)

    # ---- String references (anti-VM artifact strings) ----
    # Generate `mov eax, imm32` against each string RVA so Ghidra creates a
    # data reference that the script can crawl back from.
    for label, _ in ANTI_VM_STRINGS:
        mov_eax_imm32(string_rvas[label])

    # ---- INT3 anchor (placed last so it does not truncate analysis) ----
    code.extend(b"\xCC")                 # int3

    # ---- Tail: ret (unreachable past INT3, but keeps the section sane) ----
    code.extend(b"\xC3")
    return bytes(code)


# ---------------------------------------------------------------------------
# Build the full PE
# ---------------------------------------------------------------------------

def build_pe():
    rdata_bytes, string_rvas = build_rdata()
    idata_bytes, iat_slots = build_idata()
    text_bytes = build_text(iat_slots, string_rvas)

    # Section raw sizes (file-aligned)
    text_raw  = align_up(len(text_bytes),  FILE_ALIGN)
    rdata_raw = align_up(len(rdata_bytes), FILE_ALIGN)
    idata_raw = align_up(len(idata_bytes), FILE_ALIGN)

    text_virt  = align_up(len(text_bytes),  SECTION_ALIGN)
    rdata_virt = align_up(len(rdata_bytes), SECTION_ALIGN)
    idata_virt = align_up(len(idata_bytes), SECTION_ALIGN)

    text_file_off  = SIZE_OF_HEADERS
    rdata_file_off = text_file_off + text_raw
    idata_file_off = rdata_file_off + rdata_raw

    image_size = align_up(IDATA_RVA + idata_virt, SECTION_ALIGN)

    # ---- DOS header (60 bytes + e_lfanew at 0x3C) ----
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)   # e_lfanew = 64

    # ---- PE signature ----
    pe_sig = b"PE\x00\x00"

    # ---- COFF header (20 bytes) ----
    NUMBER_OF_SECTIONS = 3
    SIZE_OF_OPT_HDR    = 224     # PE32 standard
    CHARACTERISTICS    = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff = struct.pack("<HHIIIHH",
        0x014c,                  # Machine = i386
        NUMBER_OF_SECTIONS,
        0,                       # TimeDateStamp
        0,                       # PointerToSymbolTable
        0,                       # NumberOfSymbols
        SIZE_OF_OPT_HDR,
        CHARACTERISTICS,
    )

    # ---- Optional header (PE32, 224 bytes) ----
    SIZE_OF_CODE        = text_raw
    SIZE_OF_INIT_DATA   = rdata_raw + idata_raw
    BASE_OF_CODE        = TEXT_RVA
    BASE_OF_DATA        = RDATA_RVA
    SIZE_OF_IMAGE       = image_size

    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010b,                  # Magic = PE32
        0x00, 0x00,              # MajorLinkerVersion / MinorLinkerVersion
        SIZE_OF_CODE,            # SizeOfCode
        SIZE_OF_INIT_DATA,       # SizeOfInitializedData
        0,                       # SizeOfUninitializedData
        ENTRY_RVA,               # AddressOfEntryPoint
        BASE_OF_CODE,
        BASE_OF_DATA,
        IMAGE_BASE,
        SECTION_ALIGN,
        FILE_ALIGN,
        4, 0,                    # OS major/minor
        0, 0,                    # Image major/minor
        4, 0,                    # Subsystem major/minor
        0,                       # Win32VersionValue
        SIZE_OF_IMAGE,
        SIZE_OF_HEADERS,
        0,                       # CheckSum
        0x0003,                  # Subsystem = WINDOWS_CUI
        0x0000,                  # DllCharacteristics
        0x00100000,              # SizeOfStackReserve
        0x00001000,              # SizeOfStackCommit
        0x00100000,              # SizeOfHeapReserve
        0x00001000,              # SizeOfHeapCommit
        0,                       # LoaderFlags
        16,                      # NumberOfRvaAndSizes
    )
    # Data directories (16 entries, each 8 bytes -> RVA, Size).  We populate
    # only IMPORT (index 1) and BASE_RELOCATION (index 5 -- empty, but kept
    # zero).
    data_dirs = bytearray(16 * 8)
    struct.pack_into("<II", data_dirs, 1 * 8, IDATA_RVA, len(idata_bytes))
    opt += bytes(data_dirs)

    # ---- Section headers (40 bytes each) ----
    def section(name, virt_size, virt_addr, raw_size, raw_ptr, characteristics):
        nm = name.encode("ascii")[:8].ljust(8, b"\x00")
        return nm + struct.pack("<IIIIIIHHI",
            virt_size,
            virt_addr,
            raw_size,
            raw_ptr,
            0,                   # PointerToRelocations
            0,                   # PointerToLinenumbers
            0,                   # NumberOfRelocations
            0,                   # NumberOfLinenumbers
            characteristics,
        )

    sec_text  = section(".text",  len(text_bytes),  TEXT_RVA,  text_raw,  text_file_off,  0x60000020)  # CODE | EXEC | READ
    sec_rdata = section(".rdata", len(rdata_bytes), RDATA_RVA, rdata_raw, rdata_file_off, 0x40000040)  # INIT_DATA | READ
    sec_idata = section(".idata", len(idata_bytes), IDATA_RVA, idata_raw, idata_file_off, 0xC0000040)  # INIT_DATA | READ | WRITE

    headers = bytes(dos) + pe_sig + coff + opt + sec_text + sec_rdata + sec_idata
    headers = pad_to(headers, SIZE_OF_HEADERS)

    # ---- Concatenate everything ----
    image = bytearray(headers)
    image.extend(text_bytes);  image.extend(b"\x00" * (text_raw  - len(text_bytes)))
    image.extend(rdata_bytes); image.extend(b"\x00" * (rdata_raw - len(rdata_bytes)))
    image.extend(idata_bytes); image.extend(b"\x00" * (idata_raw - len(idata_bytes)))
    return bytes(image)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, "AntiDebugAntiVMDetector_fixture.bin")
    image = build_pe()
    with open(out_path, "wb") as f:
        f.write(image)
    print(f"Wrote {out_path} ({len(image)} bytes)")
    print("Import into Ghidra as a 32-bit PE; run AntiDebugAntiVMDetector.java to verify.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
