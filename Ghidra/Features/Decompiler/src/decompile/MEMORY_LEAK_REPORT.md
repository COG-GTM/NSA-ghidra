# Native Decompiler / SLEIGH Memory-Leak Report

Leak-detection audit of the native C++ sources under
`Ghidra/Features/Decompiler/src/decompile/cpp/`, using AddressSanitizer +
LeakSanitizer and Valgrind.

Environment: Ubuntu 22.04 x86_64, g++ 11.4.0, bison 3.8.2, flex 2.6.4,
valgrind 3.18.1.

---

## 1. Build setup

### 1.1 Makefile (`src/decompile/cpp/Makefile`)

Primary targets (each target must be invoked in its own `make` run — the
dependency-file selection keys off `MAKECMDGOALS` and only handles a single
goal, so `make decomp_opt sleigh_opt` fails with
`can't create sla_opt/...o: No such file or directory`):

| Target            | Binary                | Purpose                                              |
|-------------------|-----------------------|------------------------------------------------------|
| `decomp_opt` / `decomp_dbg`   | command-line decompiler console (`-D__TERMINAL__`, dbg adds `-DCPUI_DEBUG`) |
| `sleigh_opt` / `sleigh_dbg`   | SLEIGH compiler (`.slaspec` → `.sla`)                 |
| `ghidra_opt` / `ghidra_dbg`   | the `decompile` process Ghidra launches               |
| `decomp_test_dbg` / `test`    | unit-test + datatest runner (`../unittests`, `../datatests`) |
| `libsla.a`, `libdecomp.a` (+`_dbg`) | static libraries                                 |

Key variables: `CXX=g++ -std=c++11`, `DBG_CXXFLAGS=-g -Wall -Wno-sign-compare`,
`OPT_CXXFLAGS=-O2 -Wall -Wno-sign-compare`, `YACC=bison`, `LEX=flex`.

### 1.2 Gradle native build

* `Ghidra/Features/Decompiler/buildNatives.gradle` — model-based native build
  (`decompile` and `sleigh` `NativeExecutableSpec` components for
  win/linux/mac/freebsd × x86_64/arm_64). GCC flags are hardcoded at
  `binaries.all`: `-std=c++11 -Wall -O2 -Wno-sign-compare` (comment `-O2` /
  uncomment `-g` for debug). Run via `gradle buildNatives` (see `DevGuide.md`).
* `Ghidra/Features/Decompiler/build.gradle` — `generateParsers` task
  (`yaccDecompiler`, `yaccSleigh`, `lexSleigh`) regenerates the checked-in
  bison/flex outputs (`grammar.cc`, `xml.cc`, `pcodeparse.cc`, `slghparse.cc`,
  `slghscan.cc`).

### 1.3 Dependencies

* C++11 compiler (g++/clang/VisualCpp)
* `bison`, `flex` (only when regenerating parsers; generated `.cc` are checked in)
* `zlib` (`-lz`), `libbfd` + binutils headers (`-lbfd`, `decomp_*` targets only)
* `valgrind` (analysis only)

---

## 2. Build commands used

```sh
cd Ghidra/Features/Decompiler/src/decompile/cpp
sudo apt-get install -y bison flex valgrind binutils-dev zlib1g-dev

# Baseline (clean) build — both succeeded
make -j$(nproc) decomp_opt
make -j$(nproc) sleigh_opt

# Instrumented ASan+LSan build (flags injected via DBG_CXXFLAGS; the same
# variable is used at link time, so -fsanitize is applied to the link as well)
ASAN='-g -O1 -fsanitize=address -fsanitize=leak -Wall -Wno-sign-compare'
make -j$(nproc) decomp_dbg      DBG_CXXFLAGS="$ASAN"
make -j$(nproc) sleigh_dbg      DBG_CXXFLAGS="$ASAN"
make -j$(nproc) decomp_test_dbg DBG_CXXFLAGS="$ASAN"
```

For the Gradle build the equivalent injection point is
`b.cppCompiler.args` / `b.linker.args` in `buildNatives.gradle`
(`binaries.all` block).

`.sla` inputs for the decompiler runs were produced with:

```sh
for p in x86 AARCH64 PowerPC MIPS ARM 8051 68000 Toy; do
  ./sleigh_opt -a ../../../../../Processors/$p/data/languages
done
```

---

## 3. Runs performed and results

| Run | Binary | Input | LSan | Valgrind |
|-----|--------|-------|------|----------|
| Full test suite (599 unit tests + all 79 `../datatests/*.xml`) | `decomp_test_dbg` (ASan) | default paths | **clean** | — |
| SLEIGH compile, valid specs | `sleigh_dbg` (ASan), `sleigh_opt` (valgrind) | `8051.slaspec`, `x86-64.slaspec` | **clean** | **clean** |
| Decompiler session (load datatest, decompile, print C) | `decomp_dbg` (ASan), `decomp_opt` (valgrind) | `../datatests/deadvolatile.xml` | **clean** | **clean** |
| C-parser (`grammar.cc`) valid + error paths via `parse line` (struct/typedef/prototype declarations, plus 3 malformed ones) | `decomp_dbg` (ASan) | scripted console session | **clean** | — |
| SLEIGH compile, **malformed specs (semantic error mid-constructor)** | `sleigh_dbg` (ASan), `sleigh_opt` (valgrind) | `bad2/badB/badC/badD.slaspec` (§4) | **LEAKS** | **LEAKS (confirms)** |

The hand-written allocation tracking in `grammar.cc`
(`CParse::clearAllocation`, `typedec_alloc` / `typespec_alloc` /
`vecdec_alloc` / `string_alloc` / `num_alloc` lists) was exercised on both
success and error paths and is **balanced** — no leaks. Every scanner/parser
allocation in `grammar.y` is registered in one of those lists and freed by
`clearAllocation()`, which runs at the start of every `parse()` and in
`~CParse`.

The confirmed leaks are all in the **SLEIGH compiler front end**
(`slghparse.y`-generated `slghparse.cc`, `slghscan.l`-generated
`slghscan.cc`, and callees in `slgh_compile.cc`/`slghsymbol.cc`) and only on
the **error path**: when a semantic error calls `SleighCompile::reportError`
followed by `YYERROR`, bison pops/discards semantic values without freeing
them, and no `%destructor` directives are defined.

Note on severity: the standalone `sleigh` binary exits shortly after a failed
compile (and `-a` recursive mode aborts on the first failing file), so the
process-lifetime impact is bounded. The leaks matter for embedders of
`libsla.a` that keep the process alive across compile attempts.

---

## 4. Confirmed leaks

All reproduced with `./sleigh_dbg <input> /tmp/out.sla` (ASan build) and
confirmed with
`valgrind --leak-check=full --show-leak-kinds=all ./sleigh_opt <input> /tmp/out.sla`.

> Note: `make` regenerates `slghparse.cc`/`slghscan.cc` from `slghparse.y`/`slghscan.l`,
> so line numbers in generated files depend on the local bison/flex version
> (bison 3.8.2 / flex 2.6.4 here). Generated-file lines below are from that
> regeneration; the `.y`/`.l` source lines are authoritative. In the
> checked-in generated files the same sites are at `slghparse.cc:2741`
> (EqualEquation) and `slghscan.cc:1509` (find_symbol).

Common preamble used by every repro input:

```
define endian=little;
define alignment=1;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 ];
define token opbyte (8) op=(0,7);
```

### Leak 1 — `VarnodeTpl` from `OperandSymbol::getVarnode()`

* **File/line (allocation):** `slghsymbol.cc:967` (`res = new VarnodeTpl(hand,false);` in `OperandSymbol::getVarnode`)
* **Leaked:** 104 bytes / 1 object per occurrence (direct)
* **Input (`bad2.slaspec`):** preamble + `:MOV r0 is op=0x01 { r0 = undefined_var + ; }`
  (error: `Unknown varnode parameter: undefined_var`)
* **Stack:** `operator new` → `ghidra::OperandSymbol::getVarnode() slghsymbol.cc:967` (called from the `varnode: specificsymbol` / `exprblock` actions in `slghparse.y`)
* **Cause:** the `VarnodeTpl` handed to the parser as a semantic value is
  discarded by bison during error recovery (`YYERROR` from the
  `varnode: STRING` action at `slghparse.y:467`).
* **Fix:** add `%destructor { delete $$; } <varnode>` (and the other
  pointer-typed nonterminals) to `slghparse.y`, then regenerate with
  `gradle generateParsers`.

### Leak 2 — `EqualEquation` (pattern equation) in constructor pattern

* **File/line:** generated `slghparse.cc:2518`, source rule `slghparse.y:315`
  (`constraint: familysymbol '=' pexpression { $$ = new EqualEquation(...); }`)
* **Leaked:** 72 bytes direct + indirects it owns: `ConstantValue`
  (`slghparse.y:282`, generated `slghparse.cc:2433`, 24 B) and pattern
  internals — with `TokenPattern`/`InstructionPattern`
  (`slghpatexpress.cc:268` / `slghpattern.hh:91`, 56+16 B) and the
  `TokenField` created in `SleighCompile::addTokenField`
  (`slgh_compile.cc:2667`, 48 B) reachable only from it.
* **Input:** same `bad2.slaspec` as Leak 1 (also `badD.slaspec` below)
* **Cause:** the already-reduced `pequation` semantic value for the
  constructor being parsed is on the bison stack when `YYERROR` fires and is
  discarded without deletion.
* **Fix:** `%destructor { PatternEquation::release($$); } <pateq>` and
  `%destructor { PatternExpression::release($$); } <patexp>` in
  `slghparse.y` (these classes are ref-counted; use release rather than
  delete).

### Leak 3 — `ConstructTpl` from `SleighCompile::enterSection()`

* **File/line:** `slgh_compile.cc:3340` (`ConstructTpl *tpl = new ConstructTpl();`), invoked from the `rtlmid: /* EMPTY */` action at `slghparse.y:353`
* **Leaked:** 40 bytes / object (direct); 2 objects (80 B) for the macro variant
* **Input (`badD.slaspec`):** preamble + `:MOV r0 is op=0x01 { export nosym; }`
  (error: `Unknown export varnode: nosym`) — total 232 B in 5 allocations
* **Cause:** `enterSection()` allocates the `ConstructTpl` that is normally
  consumed by `endSection`/`buildConstructor`; on `YYERROR` inside the RTL
  body the template is discarded off the stack and never deleted.
* **Fix:** either `%destructor { delete $$; } <sem>`/`<sectionstart>` in
  `slghparse.y`, or track live `ConstructTpl` objects in `SleighCompile`
  (mirroring the `CParse::typedec_alloc`/`clearAllocation` pattern in
  `grammar.y`) and free them in `SleighCompile::reportError`/destructor.

### Leak 4 — macro-expansion temporaries in `createMacroUse`

* **File/line:** `slgh_compile.cc:3231` (`vector<OpTpl>` result) and
  `slgh_compile.cc:3234` (`MacroBuilder`-related allocation), plus another
  `OperandSymbol::getVarnode` `VarnodeTpl` (`slghsymbol.cc:967`)
* **Leaked:** 672 bytes / 13 allocations total for this input
* **Input (`badB.slaspec`):** preamble +
  ```
  macro m1(x) { x = nosuch; }
  :MOV r0 is op=0x01 { m1(r0); }
  ```
  (error: `Unknown varnode parameter: nosuch` inside macro body)
* **Cause:** the partially-built op vector and expression trees for the macro
  invocation are abandoned when the macro body fails to parse.
* **Fix:** same `%destructor` coverage for `<param>`/`<stmt>`/`<sem>` types;
  `ExprTree` already has helper destructors (`ExprTree::toVector` frees on
  the success path) — the error path needs the symmetric cleanup.

### Leak 5 — lexer semantic values (`find_symbol` / `scan_number`)

* **File/line:** `slghscan.cc:1494` (`string *newstring = new string(sleightext);` in `find_symbol`, from rule `slghscan.l:514`) and `slghscan.cc:1585/1588` (`lval->i = new uintb(val);` / `lval->big = new intb(val);` in `scan_number`)
* **Leaked:** 48 bytes / 3 allocations (32 B string + 2×8 B integers)
* **Input (`badC.slaspec`):** preamble + `:MOV r0 is nofield=0x01 { r0 = 1; }`
  (error: syntax error in the pattern section)
* **Cause:** classic flex/bison leak — tokens (`STRING`, `INTEGER`, `INTB`)
  whose semantic value is heap-allocated by the scanner are discarded by the
  parser during error recovery without being freed.
* **Fix:** `%destructor { delete $$; } <str> <i> <big>` in `slghparse.y`.

### Summary table

| # | Allocation site | Type | Direct bytes | Repro input | Detected by |
|---|-----------------|------|--------------|-------------|-------------|
| 1 | `slghsymbol.cc:967` `OperandSymbol::getVarnode` | `VarnodeTpl` | 104 | `bad2`, `badB` | LSan + Valgrind |
| 2 | `slghparse.y:315` (`slghparse.cc:2518`) | `EqualEquation` (+indirects) | 72 (+144 indirect) | `bad2`, `badD` | LSan + Valgrind |
| 3 | `slgh_compile.cc:3340` `enterSection` | `ConstructTpl` | 40–80 | `bad2`, `badB`, `badD` | LSan + Valgrind |
| 4 | `slgh_compile.cc:3231/3234` `createMacroUse` | op vector / macro use | 144 indirect | `badB` | LSan |
| 5 | `slghscan.cc:1494/1585/1588` lexer | `string*`/`uintb*`/`intb*` | 48 | `badC` | LSan |

Valgrind on `bad2.slaspec` (`sleigh_opt`): `definitely lost: 112 bytes in
2 blocks, indirectly lost: 144 bytes in 4 blocks, possibly lost: 104 bytes in
1 blocks` — matching the LSan totals (336 B; the `getVarnode` `VarnodeTpl` is
classified "possibly lost" by Valgrind, "direct" by LSan).

---

## 5. Recommended overall fix

Add bison `%destructor` directives to `slghparse.y` for every pointer-typed
semantic value (`<str> <i> <big> <varnode> <pateq> <patexp> <sem>
<sectionstart> <param> ...`), regenerate the parsers via the existing
`generateParsers` Gradle task, and add an allocation-tracking list in
`SleighCompile` (analogous to `CParse::clearAllocation` in `grammar.y`) for
objects such as the `enterSection` `ConstructTpl` whose ownership transfers
out of the parser stack mid-rule. No leaks exist on any success path or in
the decompiler-side parsers (`grammar.y`, `xml.y`, `pcodeparse.y`) in the
runs performed.
