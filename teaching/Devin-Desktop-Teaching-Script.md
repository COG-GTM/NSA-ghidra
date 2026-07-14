<!--
  Cognition | Devin Desktop teaching script
  Feature walkthrough: Tab · Codemaps · DeepWiki
  Example codebase: NSA/Ghidra (this repo)
-->

# Devin Desktop teaching script — Tab, Codemaps & DeepWiki (on Ghidra)

**Audience:** reverse engineers / malware analysts / tool developers new to the Devin Desktop editor who already know Ghidra.
**Goal:** by the end you can (1) write Ghidra scripts faster with **Tab**, (2) understand an unfamiliar decompiler flow with a **Codemap**, and (3) explain any C++/Java symbol in place with **DeepWiki**.
**Format:** this is a *facilitator script*. Each lesson tells you **when** to reach for the feature, **exactly where** in this repo to demonstrate it, **what** to do, and **what the learner should see**.

> This script is anchored to real locations in this checkout. All file paths are relative to the repo root. Line numbers are accurate as of authoring; if the file has since changed, search by the named symbol instead.

---

## How the three features fit together

They solve three *different* comprehension problems. Teach them in the order below — reading, then mapping, then writing — because that mirrors how an analyst actually onboards to unfamiliar mission code.

```
                        "I don't understand THIS..."
                                   |
      +----------------+----------------------+----------------------+
      |                |                      |                      |
  a single         how the pieces        what should I           (write the
  symbol           connect / the         type next /              new code)
  (a class,        execution order       repetitive edits
   a function)                             + navigation
      |                |                      |
      v                v                      v
  +--------+      +-----------+          +--------+
  | DEEPWIKI|     | CODEMAPS  |          |  TAB   |
  +--------+      +-----------+          +--------+
  hover a         generate a            inline diff-suggestions,
  symbol ->       hierarchical,         Tab to Jump, Tab to Import
  AI explains     clickable map of      while you edit
  it in prose     an execution flow
```

| Feature | Granularity | Direction of use | Best moment to use it |
|---|---|---|---|
| **DeepWiki** | One symbol | *Read* code you're looking at | You hit an unknown `class`/function and want prose, not just a type signature |
| **Codemaps** | Many files / a flow | *Understand* how code connects | You need the execution order across files before touching anything |
| **Tab** | Keystroke-level | *Write / navigate* code | You're actively editing and want speed + fewer manual imports/jumps |

---

## Lesson 0 — Setup (2 min)

1. Open this repository (`NSA-ghidra`) in the Devin Desktop editor.
2. Confirm the three surfaces are reachable:
   - **Tab**: automatic while editing. Verify it's on in **Settings → Tab** (choose **Supercomplete**; enable *Tab to Jump* and *Tab to Import*).
   - **Codemaps**: Activity Bar (left rail) → the Codemaps icon, or Command Palette (`Ctrl+Shift+P`) → **"Focus on Codemaps View"**.
   - **DeepWiki**: Activity Bar / Primary Side Bar → the DeepWiki panel.
3. Keyboard shortcuts to have on a slide:
   - Accept Tab suggestion: `Tab` · Cancel: `Esc` · Accept word-by-word: `Ctrl+→`
   - DeepWiki a symbol: hover, then `Cmd+Shift+Click` (`Ctrl+Shift+Click` on Windows/Linux)
   - Command Palette: `Ctrl+Shift+P`

---

## Lesson 1 — DeepWiki: understand a symbol without leaving the line

### When to use it
The learner is *reading* code and hits a type or function they don't recognize. A normal hover shows the signature; **DeepWiki explains what it actually does** — its role, invariants, and relationships — in prose. Reach for it the moment "what even is this?" comes up.

### Where to demonstrate (exact locations)
The native decompiler in `Ghidra/Features/Decompiler/src/decompile/cpp/` is dense, undocumented-at-a-glance C++ — the perfect place to show DeepWiki earning its keep.

Walk the learner through hovering + `Cmd+Shift+Click` on these, in order:

| # | Symbol | File | Line | Why it's a good demo |
|---|---|---|---|---|
| 1 | `class Funcdata` | `Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh` | 56 | The central container for one function's whole decompilation state — start here so everything else has a home |
| 2 | `class Varnode` | `Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh` | 73 | The atomic SSA value; DeepWiki explains address-space/offset/size better than the header comment |
| 3 | `class PcodeOp` | `Ghidra/Features/Decompiler/src/decompile/cpp/op.hh` | 63 | A single p-code operation; pairs naturally with `Varnode` |
| 4 | `class HighVariable` | `Ghidra/Features/Decompiler/src/decompile/cpp/variable.hh` | 112 | Where multiple SSA varnodes collapse into one source-level variable |
| 5 | `class Heritage` | `Ghidra/Features/Decompiler/src/decompile/cpp/heritage.hh` | 207 | The raw-p-code → SSA transform; the "aha" symbol |
| 6 | `class Sleigh` | `Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh` | 162 | Ties the decompiler back to processor definitions |

### What to do (live)
1. Open `funcdata.hh`, put the cursor on `Funcdata` at **line 56**, hover, then `Cmd+Shift+Click`.
2. Read the DeepWiki explanation aloud — point out it describes *purpose and relationships*, not just the declaration.
3. In the DeepWiki panel, click the `⋮` (top-right) → **Add to Cascade**. Now the explanation is `@`-mention context for a follow-up question like *"where is Funcdata populated?"*
4. Repeat on `Heritage` (`heritage.hh:207`) and ask the learner to predict what SSA means before revealing the explanation.

### What the learner should see
Prose explanations of unfamiliar classes, inline, with a one-click path to pull that understanding into a Cascade conversation.

---

## Lesson 2 — Codemaps: see the execution flow across files

### When to use it
DeepWiki explained the *nouns*; now the learner needs the *verbs and order* — "when a function gets decompiled, what runs, in what sequence, across which files?" That cross-file, execution-order question is exactly what a Codemap answers. Use it before making any change to a flow you don't own.

### Where to demonstrate — Flow A: the decompilation pipeline
This is the flagship demo. The path crosses the Java↔C++ bridge and several C++ subsystems, so a Codemap is dramatically clearer than manual jumping.

Suggested prompt to type into the Codemaps panel:

> *"Map what happens when a function is decompiled, from the Java DecompInterface through the native process to SSA heritage."*

The map should trace this chain (use it to sanity-check the generated nodes; click each node to jump to the location):

```
DecompInterface.decompileFunction         Java bridge: send "decompileAt" to native
  DecompInterface.java:776
        |
        v
DecompileAt::rawAction                     native command dispatch
  ghidra_process.cc:293
        |  looks up Funcdata (:296), reset (:309), perform (:310)
        v
Action::perform  ->  ActionPool::apply     the action/rule engine drives everything
  action.cc:298         action.cc:877
        |                     | iterates ops, applies Rules (:880-885)
        v                     v
Heritage::heritage           Rule::applyOp implementations
  heritage.cc:2663             e.g. RuleEarlyRemoval::applyOp  ruleaction.cc:25
        |
        +--> Heritage::placeMultiequals   heritage.cc:2599   (phi-node placement)
        +--> Heritage::rename             heritage.cc:2587   (SSA renaming)
        |
        v
   encoded C output back to Java (ghidra_process.cc:327-330)
```

Anchor cheat-sheet for the facilitator:

| Node | File | Line |
|---|---|---|
| `DecompInterface.decompileFunction` | `.../ghidra/app/decompiler/DecompInterface.java` | 776 |
| `DecompileAt::rawAction` | `.../decompile/cpp/ghidra_process.cc` | 293 |
| `Funcdata::startProcessing` | `.../decompile/cpp/funcdata.cc` | 150 |
| `Action::perform` | `.../decompile/cpp/action.cc` | 298 |
| `ActionPool::apply` | `.../decompile/cpp/action.cc` | 877 |
| `Heritage::heritage` | `.../decompile/cpp/heritage.cc` | 2663 |
| `Heritage::placeMultiequals` | `.../decompile/cpp/heritage.cc` | 2599 |
| `Heritage::rename` | `.../decompile/cpp/heritage.cc` | 2587 |

### Where to demonstrate — Flow B: the ELF loader (a second, contrasting flow)
Shorter and Java-only — good to show Codemaps aren't just for the C++ engine. Prompt:

> *"Map how an ELF binary is loaded into a Program."*

```
ElfLoader.load                        ElfLoader.java:147
      | builds ElfHeader (:150-152)
      v
ElfProgramBuilder.loadElf             ElfProgramBuilder.java:108
      v
ElfProgramBuilder.load                ElfProgramBuilder.java:114
      | parse ELF (:118) -> begin transaction (:121) -> add properties (:124)
      v
   memory blocks, symbols & metadata populated on the Program
```

### What to do (live)
1. Open Codemaps (Activity Bar or `Ctrl+Shift+P` → "Focus on Codemaps View").
2. Create a new Codemap with the Flow A prompt above (or pick a suggested topic based on recent navigation).
3. When it generates, **click nodes** to jump straight to `ghidra_process.cc:293`, `action.cc:298`, `heritage.cc:2663`, etc. — emphasize node → code navigation.
4. Show **sharing**: generate a shareable link for a teammate (note: enterprise sharing requires opt-in since maps are stored server-side).
5. Show **Cascade integration**: `@`-mention the Codemap in a Cascade chat and ask *"where would I add a new rule in this pipeline?"*

### What the learner should see
A hierarchical, clickable map that turns a multi-file, cross-language flow into one navigable picture — plus the ability to share it and feed it to Cascade.

---

## Lesson 3 — Tab: write and navigate Ghidra code faster

### When to use it
Now the learner *writes*. Tab shines during active editing: finishing lines, making repetitive/structural edits before and after the cursor (**Supercomplete**), jumping to the next logical edit site (**Tab to Jump**), and auto-adding imports (**Tab to Import**). Reach for it constantly while coding; press `Esc` to dismiss anything unwanted.

### Where to demonstrate — a mission-relevant script
Use the analysis-script surface, which is where an analyst actually writes day-to-day code:

- **Java scripts:** `Ghidra/Features/Base/ghidra_scripts/` (e.g. `AntiDebugAntiVMDetector.java`, class at line 95, `run()` at line 187, import block lines 64–93)
- **Python (PyGhidra):** `Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py` (Python + Java + Ghidra imports at lines 20/25/32/61)

> Tip for a compelling IC demo: rather than editing an existing file in place, create a **new** script (e.g. `ghidra_scripts/DetectSuspiciousApiCalls.java`) and let Tab carry the boilerplate. Writing a fresh detection script lands better than trivial edits.

### 3a. Autocomplete / Supercomplete
1. In `ghidra_scripts/`, create `DetectSuspiciousApiCalls.java` and start a `GhidraScript` subclass: type `public class DetectSuspiciousApiCalls extends GhidraScript {` then a `protected void run() throws Exception {`.
2. Begin iterating the listing — type `for (Function f : currentProgram.getFunctionManager().` and let Supercomplete propose the rest.
3. Show it making a **multi-line** suggestion (a loop body that checks called function names against a watchlist). Accept with `Tab`, or accept word-by-word with `Ctrl+→`. Cancel with `Esc`.
4. Point out the model uses surrounding context — the class you're in, recent edits, terminal, and Cascade history.

### 3b. Tab to Jump
1. With the cursor mid-method, make a small change, then look for the **`Tab to Jump`** label appearing at the next logical edit line.
2. Press `Tab` to jump there instead of scrolling/clicking. Great for moving between the field declarations near the top and the `run()` body below.

### 3c. Tab to Import (the crowd-pleaser)
This is easiest to show against the existing, import-rich files:

- **Java:** open `AntiDebugAntiVMDetector.java`. In `run()`, reference a Ghidra type that is *not yet imported* — e.g. start using `SymbolTable` (or type a new type like `AddressSet`). When the import hint appears, press `Tab`: the `import ghidra....;` line is added to the block (lines 64–93) **and your cursor stays put**.
- **Python:** open `PyGhidraBasics.py`. Reference a new Java/Ghidra class in the body; press `Tab` when hinted to add the `from ... import ...` at the top (near lines 20–32) without moving your cursor.

### What the learner should see
Inline suggestions that complete real Ghidra-API code, a `Tab to Jump` label that moves the cursor to the next edit, and imports that appear automatically on `Tab` — all without breaking flow.

---

## Putting it together — a 10-minute end-to-end demo

Tell one story that chains all three (this is the recommended live sequence):

1. **DeepWiki** — "I've never seen this decompiler before." Hover `Funcdata` (`funcdata.hh:56`) and `Heritage` (`heritage.hh:207`); read the explanations; **Add to Cascade**.
2. **Codemaps** — "How does a decompile actually run?" Generate the Flow A map; click through `ghidra_process.cc:293` → `action.cc:298` → `heritage.cc:2663`; `@`-mention the map in Cascade.
3. **Tab** — "Now I'll write a detection script." Create `DetectSuspiciousApiCalls.java`, let Supercomplete draft the loop, use **Tab to Jump** between edit sites, and **Tab to Import** the Ghidra types.

Closing line for the facilitator: *DeepWiki reads, Codemaps maps, Tab writes — read → map → write is the whole onboarding loop for unfamiliar mission code.*

---

## Facilitator quick-reference (anchors)

```
DEEPWIKI (hover + Cmd+Shift+Click)
  funcdata.hh:56   Funcdata      varnode.hh:73    Varnode
  op.hh:63         PcodeOp       variable.hh:112  HighVariable
  heritage.hh:207  Heritage      sleigh.hh:162    Sleigh
  (all under Ghidra/Features/Decompiler/src/decompile/cpp/)

CODEMAPS (generate map, click nodes)
  Flow A decompile pipeline:
    DecompInterface.java:776 -> ghidra_process.cc:293 -> action.cc:298/877
      -> heritage.cc:2663 (2599 placeMultiequals, 2587 rename)
  Flow B ELF load:
    ElfLoader.java:147 -> ElfProgramBuilder.java:108 -> :114

TAB (while editing)
  Java scripts:   Ghidra/Features/Base/ghidra_scripts/
                  AntiDebugAntiVMDetector.java (imports 64-93, class 95, run 187)
  Python scripts: Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py
  Shortcuts: Tab accept | Esc cancel | Ctrl+-> word-by-word
```

---

<sub>Prepared by Cognition. Devin Desktop feature docs: Tab `docs.devin.ai/desktop/tab/overview` · Codemaps `docs.devin.ai/desktop/codemaps` · DeepWiki `docs.devin.ai/desktop/deepwiki`.</sub>
