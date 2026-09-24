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
# Builds the ExportExternalDependencies test fixtures from
# ExportExternalDependencies_fixture.c at test time. Nothing produced here is
# committed and nothing produced here is executed.
#
# Targets:
#   elf-x86_64    gcc (required; the test fails if it is missing)
#   elf-aarch64   aarch64-linux-gnu-gcc (skipped with a message if missing)
#   pe-x86_64     x86_64-w64-mingw32-gcc (skipped with a message if missing)
#
# Usage:
#   python3 ExportExternalDependencies_build_fixture.py <outputDir> [--list]
#
# --list prints one "<target> <path|SKIPPED reason>" line per target and is what
# the Java test consumes. Exit status is non-zero only when the required target
# cannot be built.

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "ExportExternalDependencies_fixture.c")

COMMON_FLAGS = [
    "-O1",
    "-fno-builtin",
    "-fno-inline",
    "-fno-stack-protector",
    "-fno-pie",
    "-fno-asynchronous-unwind-tables",
    "-Wall",
    "-Wno-builtin-declaration-mismatch",
]

TARGETS = [
    ("elf-x86_64", ["gcc", "x86_64-linux-gnu-gcc"],
     ["-no-pie", "-Wl,--build-id=none"], "fixture_elf_x86_64", True),
    ("elf-aarch64", ["aarch64-linux-gnu-gcc"],
     ["-no-pie", "-Wl,--build-id=none"], "fixture_elf_aarch64", False),
    ("pe-x86_64", ["x86_64-w64-mingw32-gcc"],
     [], "fixture_pe_x86_64.exe", False),
]


def find_compiler(candidates):
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None


def build(target, compiler, extra, out_name, out_dir):
    out_path = os.path.join(out_dir, out_name)
    cmd = [compiler] + COMMON_FLAGS + extra + ["-o", out_path, SOURCE]
    env = dict(os.environ, SOURCE_DATE_EPOCH="0", LC_ALL="C")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        sys.stderr.write(f"{target}: compiler exit {proc.returncode}\n{proc.stderr}\n")
        return None
    os.chmod(out_path, 0o644)
    return out_path


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__ or "usage: build_fixture.py <outputDir> [--list]\n")
        return 2
    out_dir = os.path.abspath(argv[1])
    listing = "--list" in argv[2:]
    os.makedirs(out_dir, exist_ok=True)
    if not os.path.isfile(SOURCE):
        sys.stderr.write("fixture source is missing\n")
        return 2

    failed_required = False
    for target, candidates, extra, out_name, required in TARGETS:
        compiler = find_compiler(candidates)
        if compiler is None:
            msg = f"{target} SKIPPED no compiler among {', '.join(candidates)}"
            if required:
                failed_required = True
                msg = f"{target} FAILED no compiler among {', '.join(candidates)}"
            print(msg)
            continue
        path = build(target, compiler, extra, out_name, out_dir)
        if path is None:
            if required:
                failed_required = True
                print(f"{target} FAILED compile error")
            else:
                print(f"{target} SKIPPED compile error")
            continue
        print(f"{target} {path}")
    if not listing:
        print(f"fixtures written to {out_dir}")
    return 1 if failed_required else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
