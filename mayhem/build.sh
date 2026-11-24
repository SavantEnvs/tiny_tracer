#!/usr/bin/env bash
#
# mayhem/build.sh — build tiny_tracer's fuzz harnesses and its parser self-test.
#
# tiny_tracer is an Intel Pin tool; its real build (makefile + Pin's makefile.rules) needs the
# proprietary Pin kit and produces a Pintool that only runs inside Pin's JIT, which cannot host a
# sanitized in-process fuzzer. The code that reads untrusted data — the config/list loaders
# (Settings.cpp, FuncWatch.cpp, Util.cpp) and the PE export parser (ExportsInfo.cpp) — uses only a
# handful of Pin types and calls, so it is compiled here, unmodified, against mayhem/shim/pin.H.
#
# Runs in the commit image as `mayhem` in /mayhem; idempotent and offline (no fetches).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/build"            # gitignored (mayhem/.gitignore)
mkdir -p "$OUT/fuzz" "$OUT/test"

INC=(-include "$SRC/mayhem/shim/pin.H" -I"$SRC/mayhem/shim" -I"$SRC")
PARSERS=(Settings FuncWatch Util ExportsInfo)

# 1) The upstream parser sources, sanitized + SanCov-instrumented (fuzzer-no-link is unconditional, so
#    the no-sanitizer build still records coverage), DWARF 3.
FUZZ_CXXFLAGS=(-std=c++17 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${INC[@]}")
for f in "${PARSERS[@]}"; do
  $CXX "${FUZZ_CXXFLAGS[@]}" -c "$SRC/$f.cpp" -o "$OUT/fuzz/$f.o"
done
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/fuzz/standalone_main.o"

# 2) Each harness twice: libFuzzer binary + run-once standalone reproducer.
build_harness() {
  local name="$1"; shift
  $CXX "${FUZZ_CXXFLAGS[@]}" -c "$SRC/mayhem/harnesses/$name.cpp" -o "$OUT/fuzz/$name.o"
  local objs=("$OUT/fuzz/$name.o" "$OUT/fuzz/lsan_off.o")
  for f in "$@"; do objs+=("$OUT/fuzz/$f.o"); done
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/fuzz/standalone_main.o" "${objs[@]}" -o "$SRC/$name-standalone"
}
build_harness fuzz_settings Settings FuncWatch Util
build_harness fuzz_exports ExportsInfo

# 3) The known-answer self-test for the same parsers, with normal flags (no sanitizers) — test.sh runs it.
TEST_CXXFLAGS=(-std=c++17 -O1 $COVERAGE_FLAGS "${INC[@]}")
for f in "${PARSERS[@]}"; do
  $CXX "${TEST_CXXFLAGS[@]}" -c "$SRC/$f.cpp" -o "$OUT/test/$f.o"
done
$CXX "${TEST_CXXFLAGS[@]}" -c "$SRC/mayhem/tests/tt_selftest.cpp" -o "$OUT/test/tt_selftest.o"
TEST_OBJS=("$OUT/test/tt_selftest.o")
for f in "${PARSERS[@]}"; do TEST_OBJS+=("$OUT/test/$f.o"); done
$CXX $COVERAGE_FLAGS "${TEST_OBJS[@]}" -o "$OUT/tt_selftest"
