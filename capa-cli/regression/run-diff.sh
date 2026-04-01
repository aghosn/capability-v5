#!/usr/bin/env bash
# Differential testing: run .txt scripts through both Rust and Lean backends,
# diff outputs, report pass/fail.
#
# Usage:
#   ./run-diff.sh                   # run regression/ tests only
#   ./run-diff.sh --with-tutos      # run regression/ tests + tutos/
#   ./run-diff.sh path/to/test.txt  # run a single test
#
# Exit code: 0 if all match, 1 if any differ.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUST_BIN="$CLI_DIR/target/release/capability-cli"
LEAN_BIN="$RUST_BIN"  # same binary, different --backend flag
TMPDIR="${TMPDIR:-/tmp}/capa-diff-$$"

mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

# Collect test files
files=()
with_tutos=false

if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
        if [[ "$arg" == "--with-tutos" ]]; then
            with_tutos=true
        else
            files+=("$arg")
        fi
    done
fi

# If no explicit files given, collect from regression/
if [[ ${#files[@]} -eq 0 ]]; then
    for f in "$SCRIPT_DIR"/*.txt; do
        [[ -f "$f" ]] && files+=("$f")
    done
fi

# Optionally include tutos
if $with_tutos; then
    for f in "$CLI_DIR/tutos"/*.txt; do
        [[ "$(basename "$f")" == "index.txt" ]] && continue
        [[ -f "$f" ]] && files+=("$f")
    done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No test files found."
    exit 0
fi

# Check binaries exist
if [[ ! -x "$RUST_BIN" ]]; then
    echo "ERROR: CLI binary not found at $RUST_BIN"
    echo "Build with: cd capa-cli && cargo build --release --features lean-backend"
    exit 1
fi

pass=0
fail=0
skipped=0
failed_names=()

for f in "${files[@]}"; do
    name="$(basename "$f" .txt)"
    rust_out="$TMPDIR/${name}_rust.txt"
    lean_out="$TMPDIR/${name}_lean.txt"

    # Run both backends
    "$RUST_BIN" --backend rust < "$f" > "$rust_out" 2>&1 || true
    "$RUST_BIN" --backend lean < "$f" > "$lean_out" 2>&1 || true

    # Strip build header lines (backend indicator, version info)
    grep -v '^\[.*backend\]' "$rust_out" | grep -v '^Building\|^Compiling\|^Backend:' > "$TMPDIR/${name}_rust_clean.txt" || true
    grep -v '^\[.*backend\]' "$lean_out"  | grep -v '^Building\|^Compiling\|^Backend:' > "$TMPDIR/${name}_lean_clean.txt"  || true

    if diff -q "$TMPDIR/${name}_rust_clean.txt" "$TMPDIR/${name}_lean_clean.txt" > /dev/null 2>&1; then
        echo "  ✅ $name"
        pass=$((pass + 1))
    else
        echo "  ❌ $name"
        diff --unified=3 "$TMPDIR/${name}_rust_clean.txt" "$TMPDIR/${name}_lean_clean.txt" | head -30
        echo "  ..."
        fail=$((fail + 1))
        failed_names+=("$name")
    fi
done

echo ""
echo "━━━ Results ━━━"
echo "  Pass: $pass"
echo "  Fail: $fail"
if [[ ${#failed_names[@]} -gt 0 ]]; then
    echo "  Failed: ${failed_names[*]}"
fi
echo "  Total: $((pass + fail))"

[[ $fail -eq 0 ]]
