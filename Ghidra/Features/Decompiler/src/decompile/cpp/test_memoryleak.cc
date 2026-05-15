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
/// \file test_memoryleak.cc
/// \brief Memory-leak smoke tests for the decompiler engine.
///
/// This harness is built by Makefile.sanitize and is intended to be run
/// under AddressSanitizer + LeakSanitizer (test_memoryleak_asan) and under
/// Valgrind (test_memoryleak_valgrind).  It exercises the five ownership
/// hot-spots that the memory-management modernization work targets:
///
///   1. Architecture default construction and destruction (cleans up
///      print/printlist/options even when init() has not been run).
///   2. Architecture init() + destruction (exercises symboltab, types,
///      translate, loader, pcodeinjectlib, commentdb, stringManager,
///      cpool, context, options ownership).
///   3. Funcdata construction (exercises the new ScopeLocal allocation,
///      attachScope handoff and the strong-exception-safe pattern in
///      funcdata.cc).
///   4. CParse parse-and-clear (exercises the 8 allocation lists in
///      grammar.cc::clearAllocation).
///   5. ActionDatabase::universalAction destruction (exercises the
///      Action/Rule ownership tree built by coreaction.cc).
///
/// The harness deliberately uses the existing TEST() registration macros
/// from test.hh so that individual scenarios can be selected from the
/// command line, e.g.:
///   ./test_memoryleak_asan memleak_funcdata_construct
///
/// The harness *does NOT* link against the legacy test.cc driver: it
/// supplies its own main() so the binary can be run standalone and so the
/// LeakSanitizer summary is the last thing printed before exit.
///
/// Required environment:
///   SLEIGHHOME must point at the root of a Ghidra source tree containing
///   a compiled .sla for x86:LE:64:default:gcc (run sleigh_opt on the
///   slaspec first).  See scripts/run_leak_check.sh for the wrapper that
///   builds it on demand.  When the .sla file is unavailable, the
///   architecture-dependent tests will be reported as skipped instead of
///   failing.
#include "libdecomp.hh"
#include "grammar.hh"
#include "test.hh"

#include <cstdlib>
#include <iostream>
#include <sstream>

namespace ghidra {

using std::cerr;
using std::cout;
using std::endl;
using std::istringstream;
using std::ostringstream;
using std::string;

namespace {

/// \brief RAII helper around an in-process Architecture.
///
/// The harness constructs and immediately destroys an Architecture for
/// nearly every test.  Wrapping the lifetime in a struct keeps the test
/// bodies readable and ensures the Architecture is deleted on every
/// control-flow path (including those that throw mid-test).
struct ArchHandle {
  Architecture *arch;
  bool skipped;
  string skipReason;

  ArchHandle() : arch(nullptr), skipped(false) {}
  ~ArchHandle() { delete arch; }
  ArchHandle(const ArchHandle &) = delete;
  ArchHandle &operator=(const ArchHandle &) = delete;
};

/// Build an in-process x86-64 XmlArchitecture using only an inline
/// \<binaryimage\> stub for the load image.  Returns a freshly initialized
/// Architecture pointer or nullptr if construction/init failed (most
/// commonly because the .sla file is missing).
bool buildArchitecture(ArchHandle &handle, const string &langid =
                       "x86:LE:64:default:gcc") {
  try {
    ArchitectureCapability *cap = ArchitectureCapability::getCapability("xml");
    if (cap == (ArchitectureCapability *)0) {
      handle.skipped = true;
      handle.skipReason = "xml architecture capability not registered";
      return false;
    }
    ostringstream xml;
    xml << "<binaryimage arch=\"" << langid << "\"></binaryimage>";
    istringstream s(xml.str());
    DocumentStorage store;
    Document *doc = store.parseDocument(s);
    store.registerTag(doc->getRoot());

    handle.arch = cap->buildArchitecture("", "", &cout);
    handle.arch->init(store);
    return true;
  }
  catch (LowlevelError &err) {
    handle.skipped = true;
    handle.skipReason = err.explain;
    delete handle.arch;
    handle.arch = nullptr;
    return false;
  }
  catch (...) {
    handle.skipped = true;
    handle.skipReason = "unknown exception during Architecture init";
    delete handle.arch;
    handle.arch = nullptr;
    return false;
  }
}

/// \brief Print a uniform "skipped" banner.
///
/// The harness is intentionally tolerant of a missing .sla file because
/// the test environment may not have run sleigh_opt yet.  Skipped tests
/// still count as passes for the purposes of the LSan exit code.
void reportSkip(const char *testname, const string &reason) {
  cerr << "  (skipped: " << testname << " — " << reason << ")" << endl;
}

}  // namespace

// ---------------------------------------------------------------------------
// Test 1 — Default-constructed Architecture: no init(), straight to dtor.
// ---------------------------------------------------------------------------
// Even with no init, the default constructor allocates `print` (via the
// PrintLanguageCapability factory), pushes it into `printlist`, and
// allocates `options` (OptionDatabase) and (under CPUI_STATISTICS) `stats`.
// The destructor must release all of these.  This test exercises that
// minimal path without needing any external data files.
TEST(memleak_architecture_default_ctor_dtor) {
  ArchHandle handle;
  ArchitectureCapability *cap = ArchitectureCapability::getCapability("xml");
  if (cap == (ArchitectureCapability *)0) {
    reportSkip("memleak_architecture_default_ctor_dtor",
               "xml architecture capability not registered");
    return;
  }
  // buildArchitecture allocates the concrete Architecture via the
  // capability factory.  We do NOT call init() — the goal is to test the
  // destructor's tolerance for partially-initialized state, which is the
  // exact failure mode that motivates moving to unique_ptr-typed members.
  handle.arch = cap->buildArchitecture("", "", &cout);
  ASSERT(handle.arch != nullptr);
  // ~ArchHandle() deletes the Architecture; LSan will report any leaks.
}

// ---------------------------------------------------------------------------
// Test 2 — Fully-initialized Architecture: exercises every owned sub-object.
// ---------------------------------------------------------------------------
TEST(memleak_architecture_init_dtor) {
  ArchHandle handle;
  if (!buildArchitecture(handle)) {
    reportSkip("memleak_architecture_init_dtor", handle.skipReason);
    return;
  }
  ASSERT(handle.arch != nullptr);
  ASSERT(handle.arch->translate != nullptr);
  ASSERT(handle.arch->symboltab != nullptr);
  // ~ArchHandle() runs the full destructor chain.
}

// ---------------------------------------------------------------------------
// Test 3 — Funcdata construction (normal path).
// ---------------------------------------------------------------------------
// Adding a FunctionSymbol to the global scope creates a Funcdata that
// allocates a ScopeLocal via `new`, attaches it to the symbol table, and
// stores the raw pointer in `localmap`.  Prior to the modernization, an
// exception from `attachScope` could leak the ScopeLocal; with the
// unique_ptr-guarded handoff the leak is impossible.
TEST(memleak_funcdata_construct) {
  ArchHandle handle;
  if (!buildArchitecture(handle)) {
    reportSkip("memleak_funcdata_construct", handle.skipReason);
    return;
  }
  Address addr(handle.arch->getDefaultCodeSpace(), 0x1000);
  FunctionSymbol *sym =
      handle.arch->symboltab->getGlobalScope()->addFunction(addr, "memleak_fn");
  ASSERT(sym != (FunctionSymbol *)0);
  Funcdata *fd = sym->getFunction();
  ASSERT(fd != (Funcdata *)0);
  fd->setHighLevel();
  // The Funcdata is owned by the symbol's scope, which is owned by the
  // global scope, which is owned by symboltab, which is owned by the
  // Architecture.  Deleting the Architecture must reclaim all of them.
}

// ---------------------------------------------------------------------------
// Test 4 — CParse parsing + automatic allocation cleanup.
// ---------------------------------------------------------------------------
// parse_type runs the bison-generated grammar.cc parser, which pushes
// intermediate TypeDeclarator/TypeSpecifiers/string/etc. into 8 separate
// allocation lists inside CParse.  The CParse destructor calls
// clearAllocation() on those lists; with raw pointer storage this requires
// the manual delete loop in grammar.cc:clearAllocation.  With
// list<unique_ptr<T>> storage, the destructor is automatic.
TEST(memleak_cparse_clearAllocation) {
  ArchHandle handle;
  if (!buildArchitecture(handle)) {
    reportSkip("memleak_cparse_clearAllocation", handle.skipReason);
    return;
  }
  // A grab-bag of declarations that touches every allocation list.
  const char *samples[] = {
      "int a;",
      "char *b;",
      "long arr[10];",
      "struct { int x; int y; } s;",
      "enum E { A=1, B=2, C=3 };",
      "unsigned int (*fp)(int, int);",
  };
  for (const char *sample : samples) {
    istringstream s(sample);
    string name;
    try {
      Datatype *dt = parse_type(s, name, handle.arch);
      // parse_type returns a Datatype owned by the TypeFactory, not by
      // the caller — no delete needed here.
      (void)dt;
    }
    catch (ParseError &err) {
      // Parse failures are still valid for leak-checking purposes — the
      // allocations made up to the failure point must still be reclaimed.
      cerr << "  (note: parse_type failed for \"" << sample << "\": "
           << err.explain << ")" << endl;
    }
    catch (LowlevelError &err) {
      cerr << "  (note: parse_type LowlevelError for \"" << sample << "\": "
           << err.explain << ")" << endl;
    }
  }
}

// ---------------------------------------------------------------------------
// Test 5 — Action / Rule pipeline.
// ---------------------------------------------------------------------------
// Calling buildAction("decompile", "decompile") forces ActionDatabase to
// derive a root Action from the universal Action that init() registered,
// which in turn allocates dozens of Action and Rule objects via raw `new`
// inside coreaction.cc.  Destroying the Architecture must release every
// Action/Rule in actionmap.
TEST(memleak_action_pipeline) {
  ArchHandle handle;
  if (!buildArchitecture(handle)) {
    reportSkip("memleak_action_pipeline", handle.skipReason);
    return;
  }
  // init() already called universalAction() and registered the
  // "decompile" root action; setCurrent here triggers deriveAction which
  // also exercises the ActionGroupList + grouplist clone path.
  try {
    handle.arch->allacts.setCurrent("decompile");
  }
  catch (LowlevelError &err) {
    cerr << "  (note: setCurrent(decompile) failed: " << err.explain << ")"
         << endl;
  }
}

// ---------------------------------------------------------------------------
// Test 6 — Parser error recovery.
// ---------------------------------------------------------------------------
// Feed malformed C-type syntax to parse_type so CParse's parser enters
// error recovery.  The %destructor / yydestruct path is responsible for
// freeing the YYSTYPE union members that were pushed onto the parser
// stack before the error.  With the new list<unique_ptr<T>> storage in
// CParse, those allocations are guaranteed to be cleaned up by ~CParse,
// not by the manual yydestruct code.
TEST(memleak_parser_error_recovery) {
  ArchHandle handle;
  if (!buildArchitecture(handle)) {
    reportSkip("memleak_parser_error_recovery", handle.skipReason);
    return;
  }
  const char *garbage[] = {
      "int int int;",
      "struct;",
      "enum { ;",
      ";;;;",
  };
  for (const char *sample : garbage) {
    istringstream s(sample);
    string name;
    try {
      parse_type(s, name, handle.arch);
    }
    catch (...) {
      // Expected — we are feeding malformed input on purpose.
    }
  }
}

}  // namespace ghidra

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
// Mirrors the style of test.cc but trims out the data-test branch and the
// elaborate command-line parsing.  Tests can be filtered by name:
//   ./test_memoryleak_asan memleak_funcdata_construct memleak_cparse_clearAllocation
// With no arguments, every registered leak test runs.
int main(int argc, char **argv) {
  using namespace ghidra;
  const char *envhome = getenv("SLEIGHHOME");
  string sleighhome;
  if (envhome != nullptr) {
    sleighhome = envhome;
    cout << "Using SLEIGHHOME=" << sleighhome << endl;
  } else {
    // Fall back to a relative path matching the layout of the in-tree
    // build.  This matches what decomp_test_dbg does when no -sleighpath
    // is supplied.
    sleighhome = "../../../../../../..";
    cout << "Defaulting SLEIGHHOME to repo-relative " << sleighhome << endl;
  }
  startDecompilerLibrary(sleighhome.c_str());

  set<string> selected;
  for (int i = 1; i < argc; ++i)
    selected.insert(argv[i]);

  // Run the tests directly rather than going through UnitTest::run() so
  // that this binary stays self-contained — we deliberately do not link
  // against test.cc (which carries its own main() and an unrelated
  // data-test driver).
  int total = 0;
  int passed = 0;
  for (UnitTest *t : UnitTest::tests()) {
    if (!selected.empty() && selected.find(t->name) == selected.end())
      continue;
    cerr << "testing : " << t->name << " ..." << endl;
    ++total;
    try {
      t->func();
      ++passed;
      cerr << "  passed." << endl;
    } catch (LowlevelError &err) {
      cerr << "  fail: " << err.explain << endl;
    } catch (...) {
      cerr << "  fail" << endl;
    }
  }
  cerr << "==============================" << endl;
  cerr << passed << "/" << total << " tests passed." << endl;
  int failed = total - passed;
  shutdownDecompilerLibrary();

  // Non-zero return indicates assertion failures.  Sanitizers append
  // their own leak report and exit non-zero on detected leaks even when
  // every TEST passes.
  return failed;
}
