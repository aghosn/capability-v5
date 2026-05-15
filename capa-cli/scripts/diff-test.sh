#!/usr/bin/env bash
# Differential test: compare Rust and Lean backend outputs on all tutorials.
# Usage: ./capa-cli/scripts/diff-test.sh
set -euo pipefail

CLI_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TUTO_DIR="$CLI_DIR/tutos"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Building Rust backend..."
cargo build --release --manifest-path "$CLI_DIR/Cargo.toml" --quiet

echo "Building Lean backend..."
cargo build --release --manifest-path "$CLI_DIR/Cargo.toml" --features lean-backend --quiet

BIN="$CLI_DIR/../target/release/capability-cli"

passed=0
failed=0
errors=""

for tuto in "$TUTO_DIR"/*.txt; do
    name="$(basename "$tuto")"
    # Skip index.txt (meta-file that loads other tutorials)
    [ "$name" = "index.txt" ] && continue

    echo "load $tuto" | "$BIN" 2>/dev/null > "$TMPDIR/rust.txt" || true
    echo "load $tuto" | "$BIN" --backend lean 2>/dev/null > "$TMPDIR/lean.txt" || true

    # Strip the "Backend: ..." line since it will always differ
    grep -v '^Backend:' "$TMPDIR/rust.txt" > "$TMPDIR/rust_clean.txt" || true
    grep -v '^Backend:' "$TMPDIR/lean.txt" > "$TMPDIR/lean_clean.txt" || true

    if diff -u "$TMPDIR/rust_clean.txt" "$TMPDIR/lean_clean.txt" > "$TMPDIR/diff.txt" 2>&1; then
        echo "  ✓ $name"
        passed=$((passed + 1))
    else
        echo "  ✗ $name"
        errors="$errors\n=== $name ===\n$(cat "$TMPDIR/diff.txt")\n"
        failed=$((failed + 1))
    fi
done

echo ""
echo "Results: $passed passed, $failed failed"

if [ $failed -gt 0 ]; then
    echo -e "\nDifferences:$errors"
    exit 1
fi
