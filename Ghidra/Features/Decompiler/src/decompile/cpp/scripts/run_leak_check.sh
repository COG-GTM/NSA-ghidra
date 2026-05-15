#!/usr/bin/env bash
# run_leak_check.sh — build the decompiler memory-leak test harness with
# both AddressSanitizer/LeakSanitizer and a plain debug build, run each
# against Valgrind / LSan, and dump timestamped reports under leak_reports/.
#
# Designed to be invoked twice — once on the base branch (PHASE=before)
# and once on the modernization branch (PHASE=after) — so the two
# directories can be diff'ed for an immediate before/after view.
#
# Usage:
#   ./scripts/run_leak_check.sh                  # PHASE defaults to "before"
#   ./scripts/run_leak_check.sh after            # PHASE=after
#   PHASE=baseline ./scripts/run_leak_check.sh   # explicit override
#   ./scripts/run_leak_check.sh after memleak_funcdata_construct
#       (any positional args beyond PHASE are forwarded to the harness,
#        useful for re-running a single test case)
#
# Required tooling:
#   * g++ with AddressSanitizer / LeakSanitizer support (g++ >= 5)
#   * valgrind (any reasonably recent build)
#   * bison, flex, libbfd-dev, libz-dev (only the first time, to bootstrap
#     the decompiler build).
#
# The script is intentionally conservative — it never `rm -rf`s the
# leak_reports/ directory and never overwrites an existing report — every
# run lands in its own timestamped subdirectory.

set -euo pipefail

# ----------------------------------------------------------------------------
# Argument handling
# ----------------------------------------------------------------------------
PHASE="${1:-before}"
shift || true
HARNESS_ARGS=("$@")

case "$PHASE" in
  before|after|baseline) ;;
  *)
    echo "warning: unrecognised PHASE '$PHASE'; valid choices are before / after / baseline" >&2
    ;;
esac

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CPP_DIR/../../../../../.." && pwd)"
SLEIGHHOME="${SLEIGHHOME:-$REPO_ROOT}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="$CPP_DIR/leak_reports/${PHASE}_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

# ----------------------------------------------------------------------------
# Step 1 — Ensure prerequisites are built.
# ----------------------------------------------------------------------------
# The harness loads an in-process x86:LE:64 architecture, so it needs the
# compiled .sla file.  Build it on demand if missing (cheap incremental
# rebuild if it already exists).
cd "$CPP_DIR"

X86_SLA="$REPO_ROOT/Ghidra/Processors/x86/data/languages/x86-64.sla"
X86_SLASPEC="$REPO_ROOT/Ghidra/Processors/x86/data/languages/x86-64.slaspec"

if [[ ! -f "$X86_SLA" ]]; then
  echo "==> Building sleigh_opt + x86-64.sla (one-time setup) ..."
  make sleigh_opt
  ./sleigh_opt "$X86_SLASPEC" || true
  if [[ ! -f "$X86_SLA" ]]; then
    echo "error: failed to compile $X86_SLA; tests requiring an" >&2
    echo "       Architecture will be skipped but the run will continue." >&2
  fi
fi

# ----------------------------------------------------------------------------
# Step 2 — Build the two harness flavours.
# ----------------------------------------------------------------------------
echo "==> Building test_memoryleak_asan (ASan + LSan) ..."
make -f Makefile.sanitize test_memoryleak_asan

echo "==> Building test_memoryleak_valgrind (debug, no instrumentation) ..."
make -f Makefile.sanitize test_memoryleak_valgrind

# ----------------------------------------------------------------------------
# Step 3 — Run under ASan + LSan.
# ----------------------------------------------------------------------------
echo "==> Running ASan/LSan harness ..."
# detect_leaks=1 turns on LSan; halt_on_error=0 lets ASan keep going and
# accumulate every failure rather than bailing on the first.  log_path
# directs the *sanitizer* output (not stdout/stderr of the harness) to a
# per-run log file; the .pid suffix is appended automatically.
ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:log_path=${REPORT_DIR}/asan" \
LSAN_OPTIONS="suppressions=${SCRIPT_DIR}/lsan.supp:print_suppressions=0" \
SLEIGHHOME="$SLEIGHHOME" \
  ./test_memoryleak_asan "${HARNESS_ARGS[@]}" \
    > "${REPORT_DIR}/asan_stdout.log" \
    2> "${REPORT_DIR}/asan_stderr.log" \
  || echo "(asan harness exited non-zero — leaks or assertion failures detected)" \
       | tee -a "${REPORT_DIR}/asan_stderr.log"

# ----------------------------------------------------------------------------
# Step 4 — Run under Valgrind.
# ----------------------------------------------------------------------------
echo "==> Running Valgrind harness (this is slow — a few minutes) ..."
SLEIGHHOME="$SLEIGHHOME" \
  valgrind --leak-check=full \
           --show-leak-kinds=all \
           --track-origins=yes \
           --error-exitcode=0 \
           --log-file="${REPORT_DIR}/valgrind.log" \
           ./test_memoryleak_valgrind "${HARNESS_ARGS[@]}" \
    > "${REPORT_DIR}/valgrind_stdout.log" \
    2> "${REPORT_DIR}/valgrind_stderr.log" \
  || true

# ----------------------------------------------------------------------------
# Step 5 — Produce a one-page summary that humans (and the AFTER diff)
# can read at a glance.
# ----------------------------------------------------------------------------
SUMMARY="${REPORT_DIR}/summary.txt"
{
  echo "Memory leak check summary — PHASE=$PHASE"
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Harness args: ${HARNESS_ARGS[*]:-<all tests>}"
  echo
  echo "================== VALGRIND =================="
  if [[ -f "${REPORT_DIR}/valgrind.log" ]]; then
    grep -E "in use at exit|total heap usage|definitely lost|indirectly lost|possibly lost|still reachable|ERROR SUMMARY" \
         "${REPORT_DIR}/valgrind.log" || true
  else
    echo "(no valgrind log produced)"
  fi
  echo
  echo "==================== ASAN ===================="
  shopt -s nullglob
  asan_logs=("${REPORT_DIR}"/asan.*)
  if (( ${#asan_logs[@]} == 0 )); then
    echo "(no ASan log emitted — no errors detected)"
  else
    for f in "${asan_logs[@]}"; do
      echo "--- $f ---"
      grep -E "ERROR: AddressSanitizer|ERROR: LeakSanitizer|SUMMARY: AddressSanitizer|detected memory leaks" "$f" || true
    done
  fi
  shopt -u nullglob
  echo
  echo "================== HARNESS ==================="
  if [[ -f "${REPORT_DIR}/asan_stderr.log" ]]; then
    grep -E "passed|fail|skipped|tests passed" "${REPORT_DIR}/asan_stderr.log" || true
  fi
} > "$SUMMARY"

cat "$SUMMARY"
echo
echo "Reports saved to $REPORT_DIR"
