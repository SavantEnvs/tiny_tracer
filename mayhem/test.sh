#!/usr/bin/env bash
#
# mayhem/test.sh — run the known-answer self-test of tiny_tracer's input parsers (built by build.sh
# from mayhem/tests/tt_selftest.cpp with normal flags). Upstream ships no test suite.
# Each expected check must print "PASS <name>"; a missing or FAIL line counts as a failure, so a
# no-op/exit(0) program fails every check.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXPECTED=(
  ini_filled ini_follow_shellcodes ini_hexdump_size ini_bool_yes_off ini_volume_id_hex ini_sleep_time
  ini_antidebug_clamped ini_flush_paren_negative ini_comment_ignored ini_shipped_defaults
  params_shipped_count params_shipped_first excluded_count excluded_dlls excluded_func
  watch_excluded_skipped watch_merge_param_count watch_syscall
  syscalls_count syscalls_lookup customdefs disasm_ranges_count disasm_ranges_lookup stop_offsets
  exports_count exports_names_addresses exports_reject_bad_magic
)

RUNNER="$SRC/mayhem/build/tt_selftest"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing — mayhem/build.sh should have built it" >&2
  emit_ctrf "tt_selftest" 0 "${#EXPECTED[@]}"
  exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/tt_selftest.XXXXXX")"
out="$("$RUNNER" "$SRC" "$scratch" 2>&1)"
rc=$?
rm -rf "$scratch"
echo "$out"

passed=0; failed=0
for t in "${EXPECTED[@]}"; do
  if grep -qx "PASS $t" <<<"$out"; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "missing/failed: $t" >&2; fi
done
[ "$rc" -eq 0 ] || { [ "$failed" -gt 0 ] || failed=1; echo "tt_selftest exited $rc" >&2; }
emit_ctrf "tt_selftest" "$passed" "$failed"
