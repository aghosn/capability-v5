#!/usr/bin/env bash
# run-eunomia.sh — Boot an Eunomia workload under cloud-hypervisor from dom0.
#
# Usage (inside dom0):
#   sudo /opt/bins/eunomia/run-eunomia.sh                 # smoke (default)
#   sudo /opt/bins/eunomia/run-eunomia.sh timer            # named workload
#   sudo /opt/bins/eunomia/run-eunomia.sh /path/to/elf     # explicit ELF
#
# Environment:
#   CHV_CPUS      vCPU count (default: 1)
#   CHV_MEM       Memory   (default: 128M)
#
# Modes:
#   --kvm                  Force KVM backend
#   --themis               Force Themis backend (default: auto-detect)
#   --themis-config PATH   Pass --themis-config PATH to cloud-hypervisor
#   --policy-suite         Iterate every JSON in
#                          $SCRIPT_DIR/policies/<workload>/, running the
#                          named workload once per policy and aggregating
#                          results.  Exits non-zero if any scenario fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINS="/opt/bins"
CHV="$BINS/cloud-hypervisor/cloud-hypervisor"
THHV_KO="$BINS/thhv/thhv.ko"

CHV_CPUS="${CHV_CPUS:-1}"
CHV_MEM="${CHV_MEM:-128M}"
BACKEND_MODE="auto"
WORKLOAD=""
POLICY_SUITE=0
THEMIS_CONFIG=""

# ── Parse arguments ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kvm)     BACKEND_MODE="kvm";    shift ;;
        --themis)  BACKEND_MODE="themis"; shift ;;
        --policy-suite)
            POLICY_SUITE=1; shift ;;
        --themis-config)
            THEMIS_CONFIG="$2"; shift 2 ;;
        --help|-h)
            head -14 "$0" | tail -12
            exit 0
            ;;
        *)
            WORKLOAD="$1"; shift ;;
    esac
done

# ── Backend selection ─────────────────────────────────────────────────────
case "$BACKEND_MODE" in
    kvm)
        if [[ -c /dev/thhv ]]; then
            echo "→ Unloading thhv.ko to force KVM backend..."
            rmmod thhv 2>/dev/null || true
        fi
        echo "→ Backend: KVM"
        ;;
    themis)
        if [[ ! -c /dev/thhv ]]; then
            if [[ -f "$THHV_KO" ]]; then
                echo "→ Loading thhv.ko..."
                insmod "$THHV_KO"
            else
                echo "ERROR: thhv.ko not found" >&2
                exit 1
            fi
        fi
        echo "→ Backend: Themis (/dev/thhv)"
        ;;
    auto)
        if [[ ! -c /dev/thhv && -f "$THHV_KO" ]]; then
            echo "→ Loading thhv.ko..."
            insmod "$THHV_KO" || true
        fi
        if [[ -c /dev/thhv ]]; then
            echo "→ Backend: Themis (/dev/thhv)"
        else
            echo "→ Backend: KVM (/dev/kvm)"
        fi
        ;;
esac

# ── Kernel selection ──────────────────────────────────────────────────────
if [[ -z "$WORKLOAD" ]]; then
    WORKLOAD="smoke"
fi

# If it's a path to an existing file, use it directly
if [[ -f "$WORKLOAD" ]]; then
    KERNEL="$WORKLOAD"
else
    # Look up by workload name in the eunomia dir
    KERNEL="$SCRIPT_DIR/eunomia-${WORKLOAD}"
    if [[ ! -f "$KERNEL" ]]; then
        echo "ERROR: workload not found: $KERNEL" >&2
        echo "Available workloads:"
        ls "$SCRIPT_DIR"/eunomia-* 2>/dev/null | sed 's|.*/eunomia-|  |' || echo "  (none)"
        exit 1
    fi
fi

# ── Validation ────────────────────────────────────────────────────────────
if [[ ! -f "$CHV" ]]; then
    echo "ERROR: cloud-hypervisor not found at $CHV" >&2
    exit 1
fi

echo "╔═══════════════════════════════════════╗"
echo "║     Eunomia — dom1 boot (CHV/PVH)    ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "  kernel:  $KERNEL"
echo "  cpus:    $CHV_CPUS"
echo "  memory:  $CHV_MEM"
echo ""

# ── Build CHV command line ─────────────────────────────────────────────────
CHV_ARGS=(
    --kernel "$KERNEL"
    --cpus boot="$CHV_CPUS"
    --memory size="$CHV_MEM"
    --serial tty
    --console off
    --seccomp false
)

# CoCo workloads get the confidential platform flag.
WORKLOAD_NAME="$(basename "$KERNEL" | sed 's/^eunomia-//')"
case "$WORKLOAD_NAME" in
    coco*)
        CHV_ARGS+=(--platform "confidential=on")
        # Provision a capability-backed ivshmem device for doorbell/notification.
        # alias mode: dom0 keeps access, child discovers via CPUID 0x40000004.
        IVSHMEM_PATH="/tmp/eunomia-doorbell-$$"
        truncate -s 4096 "$IVSHMEM_PATH"
        CHV_ARGS+=(--ivshmem "path=${IVSHMEM_PATH},size=4096,mode=alias,count=1")
        echo "  mode:    confidential (CoCo)"
        echo "  ivshmem: ${IVSHMEM_PATH} (4K, alias, doorbell)"
        ;;
esac

# --themis-config PATH from CLI (single-run mode).
if [[ -n "$THEMIS_CONFIG" ]]; then
    CHV_ARGS+=(--themis-config "$THEMIS_CONFIG")
    echo "  policy:  $THEMIS_CONFIG"
fi

echo ""

# ── Policy-suite mode ────────────────────────────────────────────────────
# Iterate every policy JSON in $SCRIPT_DIR/policies/<workload>/, boot the
# workload once per policy, capture serial output, and tally pass/fail
# based on the "--- results: N passed, M failed ---" line that
# test_harness prints.
if (( POLICY_SUITE )); then
    POLICY_DIR="$SCRIPT_DIR/policies/$WORKLOAD_NAME"
    if [[ ! -d "$POLICY_DIR" ]]; then
        echo "ERROR: --policy-suite: no policy dir at $POLICY_DIR" >&2
        exit 1
    fi
    mapfile -t POLICIES < <(find "$POLICY_DIR" -maxdepth 1 -name '*.json' -print0 \
                            | xargs -0 -n1 echo | LC_ALL=C sort)
    if (( ${#POLICIES[@]} == 0 )); then
        echo "ERROR: --policy-suite: no policy JSONs under $POLICY_DIR" >&2
        exit 1
    fi
    echo "═══ Policy suite: $WORKLOAD_NAME (${#POLICIES[@]} scenarios) ═══"
    SUITE_PASS=0
    SUITE_FAIL=0
    SUITE_LOG_DIR="$(mktemp -d -t eunomia-suite.XXXXXX)"
    trap 'rm -rf "$SUITE_LOG_DIR"' EXIT
    for policy in "${POLICIES[@]}"; do
        policy_name="$(basename "$policy" .json)"
        log="$SUITE_LOG_DIR/${policy_name}.log"
        echo ""
        echo "── scenario: $policy_name ──"
        # Rebuild args so serial output goes to a file we can grep.
        SCENARIO_ARGS=()
        skip_next=0
        for a in "${CHV_ARGS[@]}"; do
            if (( skip_next )); then
                skip_next=0
                continue
            fi
            if [[ "$a" == "--serial" ]]; then
                SCENARIO_ARGS+=(--serial "file=$log")
                skip_next=1  # drop the following "tty" element
                continue
            fi
            SCENARIO_ARGS+=("$a")
        done
        SCENARIO_ARGS+=(--themis-config "$policy")
        set +e
        timeout 20s "$CHV" "${SCENARIO_ARGS[@]}" >"$log.chv" 2>&1
        rc=$?
        set -e
        # Serial log wins over chv stdout: test_harness writes results
        # over the serial file.  Fall back to combined file if serial
        # file wasn't created.
        [[ -s "$log" ]] || cp "$log.chv" "$log"
        # Look for "--- results: N passed, 0 failed ---"
        result_line="$(grep -E '^-{3}\s*results:' "$log" || true)"
        if [[ -z "$result_line" ]]; then
            echo "  FAIL: no results line (chv exit=$rc)"
            tail -20 "$log" | sed 's/^/    /'
            SUITE_FAIL=$((SUITE_FAIL + 1))
            continue
        fi
        # Parse "0 failed" from the results line.
        if grep -q ' 0 failed' <<<"$result_line"; then
            echo "  PASS: $result_line"
            SUITE_PASS=$((SUITE_PASS + 1))
        else
            echo "  FAIL: $result_line"
            grep -E 'FAILED:|MSR 0x' "$log" | sed 's/^/    /' || true
            SUITE_FAIL=$((SUITE_FAIL + 1))
        fi
    done
    echo ""
    echo "═══ Policy suite summary: $SUITE_PASS passed, $SUITE_FAIL failed ═══"
    if (( SUITE_FAIL > 0 )); then
        echo ""
        echo "Logs preserved at: $SUITE_LOG_DIR"
        # Keep logs on failure — override the EXIT trap.
        trap - EXIT
        exit 1
    fi
    exit 0
fi

# coco-illegal-access is a self-contained isolation test: boot dom1 in the
# background, give it time to come up and stamp its sentinel pages, then run
# the attacker against /dev/thhv.  The workload spins forever so a fixed
# sleep is fine.
if [[ "$WORKLOAD_NAME" == "coco-illegal-access" ]]; then
    ATTACKER_BIN="$BINS/thhv/tests/test_coco_attacker"
    if [[ ! -x "$ATTACKER_BIN" ]]; then
        echo "ERROR: $ATTACKER_BIN not found/executable" >&2
        exit 1
    fi

    DOM1_LOG="$(mktemp -t eunomia-dom1.XXXXXX.log)"
    echo "→ launching dom1 in background (log: $DOM1_LOG) ..."
    "$CHV" "${CHV_ARGS[@]}" >"$DOM1_LOG" 2>&1 &
    DOM1_PID=$!

    cleanup() {
        if kill -0 "$DOM1_PID" 2>/dev/null; then
            kill "$DOM1_PID" 2>/dev/null || true
            sleep 1
            kill -9 "$DOM1_PID" 2>/dev/null || true
        fi
    }
    trap cleanup EXIT INT TERM

    echo "→ sleeping 10s to let dom1 boot ..."
    sleep 10

    echo "→ running attacker ..."
    set +e
    "$ATTACKER_BIN" -v
    RC=$?
    set -e

    echo "→ attacker exit code: $RC"
    echo "── dom1 log tail ────────────────────────────────────────────"
    tail -40 "$DOM1_LOG" || true
    echo "─────────────────────────────────────────────────────────────"
    rm -f "$DOM1_LOG"
    exit "$RC"
fi

# `revoke` is the cross-core REVOKE_DOMAIN integration test. Boot a
# no-exit child on one physical core, then invoke the debug revoke ioctl
# from another. The capavisor's engine-side trace proves that the VP was
# Running{core} when revocation began and that the cross-core swap fired.
if [[ "$WORKLOAD_NAME" == "revoke" ]]; then
    DOM1_LOG="$(mktemp -t eunomia-revoke.XXXXXX.log)"
    # Auto-select the "no-exit" policy so the child never traps back to
    # dom0 during steady spin (guarantees child.vp0 stays Running{core}
    # long enough for the cross-core revoke to hit scenario 2).
    if [[ -z "$THEMIS_CONFIG" ]]; then
        REVOKE_POLICY=""
        for candidate in \
            "$SCRIPT_DIR/policies/revoke/no-exit.json" \
            "$SCRIPT_DIR/../../eunomia/policies/revoke/no-exit.json"; do
            if [[ -f "$candidate" ]]; then
                REVOKE_POLICY="$candidate"
                break
            fi
        done
        if [[ -n "$REVOKE_POLICY" ]]; then
            CHV_ARGS+=(--themis-config "$REVOKE_POLICY")
            echo "→ using revoke policy: $REVOKE_POLICY (trap=false)"
        else
            echo "WARN: revoke no-exit policy not found (child will trap on every VMEXIT)"
        fi
    fi
    # Serial to file so we can grep for heartbeats and traces.
    REVOKE_ARGS=()
    skip_next=0
    for a in "${CHV_ARGS[@]}"; do
        if (( skip_next )); then skip_next=0; continue; fi
        if [[ "$a" == "--serial" ]]; then
            REVOKE_ARGS+=(--serial "file=$DOM1_LOG")
            skip_next=1
            continue
        fi
        REVOKE_ARGS+=("$a")
    done

    echo "→ launching dom1 in background (log: $DOM1_LOG) ..."
    # Deterministic C3: pin CHV process (all threads) to physical core
    # THEMIS_CHV_CORE (default 0).  With CHV_CPUS=1, its single vCPU
    # thread lands on that core; when it enters VMCALL_SWITCH, the child
    # runs on that same physical core.  Combined with a no-VMEXIT child
    # workload, this guarantees the child is in guest mode on
    # THEMIS_CHV_CORE when the revoker fires from THEMIS_REVOKE_CORE.
    CHV_CORE="${THEMIS_CHV_CORE:-0}"
    REVOKE_CORE="${THEMIS_REVOKE_CORE:-1}"
    if [[ "$CHV_CORE" == "$REVOKE_CORE" ]]; then
        echo "FAIL: THEMIS_CHV_CORE ($CHV_CORE) must differ from THEMIS_REVOKE_CORE ($REVOKE_CORE)"
        exit 1
    fi
    if (( CHV_CPUS != 1 )); then
        echo "WARN: deterministic revoke test expects CHV_CPUS=1 (got $CHV_CPUS); scenario 2 not guaranteed"
    fi
    echo "→ pinning CHV to core $CHV_CORE, revoker to core $REVOKE_CORE"
    taskset -c "$CHV_CORE" "$CHV" "${REVOKE_ARGS[@]}" >"$DOM1_LOG.chv" 2>&1 &
    CHV_PID=$!

    cleanup() {
        if kill -0 "$CHV_PID" 2>/dev/null; then
            kill "$CHV_PID" 2>/dev/null || true
            sleep 1
            kill -9 "$CHV_PID" 2>/dev/null || true
        fi
    }
    trap cleanup EXIT INT TERM

    # Under the no-exit policy, serial PIO is consumed locally by the
    # capavisor and never forwarded to CHV, so workload heartbeats are
    # intentionally invisible here. Give the tiny PVH workload enough time
    # to boot and enter its permanent spin. The engine-side diagnostic at
    # revoke time is the authoritative readiness check: vp0 must report
    # Running{core:CHV_CORE}, immediately followed by the cross-core traces.
    echo "→ waiting for no-exit child to boot and enter steady spin ..."
    sleep 5

    # SIGKILL rather than SIGTERM: we want CHV to be terminated without
    # its graceful shutdown running.  On graceful shutdown CHV joins its
    # vCPU threads first, forcing the child to VMEXIT before the fd is
    # closed — which means REVOKE_DOMAIN fires with the child no longer
    # running in guest mode (scenario 1, same-core path).  SIGKILL skips
    # CHV cleanup; the kernel reaps threads and calls .release on the
    # thhv fd from an arbitrary dom0 core — often different from the one
    # that was hosting the child, exercising the cross-core swap path.
    #
    # Actually — SIGKILL still can't preempt a dom0 vCPU thread that is
    # mid-VMCALL-SWITCH, so we prefer the direct debug ioctl.  Ask thhv
    # to revoke every partition immediately.  Pin the tool to a specific
    # dom0 core so the REVOKE_DOMAIN VMCALL lands on a different core
    # than the one CHV's vCPU threads are typically busy on.
    REVOKE_TOOL="$BINS/thhv/tests/test_debug_revoke_all"
    if [[ -x "$REVOKE_TOOL" ]]; then
        echo "→ triggering THHV_DEBUG_REVOKE_ALL from core $REVOKE_CORE ..."
        taskset -c "$REVOKE_CORE" "$REVOKE_TOOL" || true
    else
        echo "→ REVOKE_TOOL not found; falling back to SIGKILL"
        kill -KILL "$CHV_PID" 2>/dev/null || true
    fi

    # Give the revoke path a few seconds to complete.  CHV will exit
    # with errors once its partition fd's underlying domain is gone.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$CHV_PID" 2>/dev/null; then break; fi
        sleep 1
    done
    if kill -0 "$CHV_PID" 2>/dev/null; then
        echo "→ CHV still alive after revoke; sending SIGKILL to clean up"
        kill -9 "$CHV_PID" 2>/dev/null || true
        sleep 1
    fi
    wait "$CHV_PID" 2>/dev/null || true

    echo "── dom1 log tail ────────────────────────────────────────────"
    tail -40 "$DOM1_LOG" | sed 's/^/    /' || true
    echo "─────────────────────────────────────────────────────────────"

    RC=0
    # Any panic in capavisor is a hard failure.  Note: capavisor's own
    # traces (e.g. [REVOKE-XCORE]) go to the *host* serial console, not
    # to CHV's virtual serial (which is what $DOM1_LOG captures).  We
    # can only detect panics that show up in dom0's own output.
    if grep -Ei 'panic|PANIC|BUG:|kernel BUG' "$DOM1_LOG" "$DOM1_LOG.chv" >/dev/null; then
        echo "FAIL: panic detected in dom0/CHV log"
        grep -Ei 'panic|PANIC|BUG:|kernel BUG' "$DOM1_LOG" "$DOM1_LOG.chv" | head -20 | sed 's/^/    /'
        RC=1
    fi

    if (( RC == 0 )); then
        echo "PASS: no-exit child revoked without panic"
        echo "      (check host serial console for [REVOKE-XCORE] traces)"
        rm -f "$DOM1_LOG" "$DOM1_LOG.chv"
    else
        echo "Logs preserved: $DOM1_LOG $DOM1_LOG.chv"
    fi
    trap - EXIT
    exit "$RC"
fi

exec "$CHV" "${CHV_ARGS[@]}"
