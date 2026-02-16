#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <pin> <taint_tracer.so> <test_objdir>" >&2
  exit 2
fi

PIN_BIN="$(echo "$1" | xargs)"
TOOL_SO="$2"
TEST_OBJDIR="$3"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ADDR2LINE_CMD=""
for candidate in "${ADDR2LINE:-}" llvm-addr2line-10 llvm-addr2line addr2line; do
  if [[ -n "$candidate" ]] && command -v "$candidate" >/dev/null 2>&1; then
    ADDR2LINE_CMD="$candidate"
    break
  fi
done

if [[ -z "$ADDR2LINE_CMD" ]]; then
  echo "❌ ERROR: addr2line not found (set ADDR2LINE or install llvm-addr2line)" >&2
  exit 1
fi

run_check() {
  local name="$1"
  local src_file="$SCRIPT_DIR/$2"
  local exe_file="$TEST_OBJDIR/$3"
  local trace_file="taint_trace.txt"
  local trace_out="taint_trace_${name}.txt"
  local addr_out="taint_trace_${name}.addr2line.txt"

  if [[ ! -f "$exe_file" ]]; then
    exe_file="${exe_file%.exe}"
  fi

  if [[ ! -f "$exe_file" ]]; then
    echo "❌ ERROR: missing test binary $exe_file" >&2
    exit 1
  fi


  rm -f "$trace_file" "$trace_out" "$addr_out"
  "$PIN_BIN" -t "$TOOL_SO" -- "$exe_file" 2>/dev/null >/dev/null

  if [[ ! -s "$trace_file" ]]; then
    echo "❌ ERROR: ${name} produced empty taint trace" >&2
    exit 1
  fi

  mv "$trace_file" "$trace_out"
  "$ADDR2LINE_CMD" -f -p -e "$exe_file" < "$trace_out" > "$addr_out"

  local src_base
  src_base="$(basename "$src_file")"

  while IFS=: read -r line marker; do
    if ! grep -q "${src_base}:${line}" "$addr_out"; then
      echo "❌ ERROR: missing trace for ${marker} (${src_base}:${line})" >&2
      exit 1
    fi
  done < <(grep -n "TRACE:" "$src_file" | sed -E 's/^([0-9]+):.*TRACE:[[:space:]]*([^[:space:]]+).*/\1:\2/')

  echo "✅ OK: ${name} markers found"
}

run_check "r2r" "taint_binop_r2r_smoke.c" "taint_binop_r2r_smoke.exe"
run_check "m2r" "taint_binop_m2r_smoke.c" "taint_binop_m2r_smoke.exe"
run_check "r2m" "taint_binop_r2m_smoke.c" "taint_binop_r2m_smoke.exe"

printf "All binop checks passed.\n"
