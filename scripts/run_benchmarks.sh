#!/usr/bin/env bash
#
# run_benchmarks.sh — Run all Piccard benchmarks and save results.
#
# Usage:
#   ./scripts/run_benchmarks.sh              # Full paper-grade run (STD128, 30/50 timing/accuracy trials)
#   ./scripts/run_benchmarks.sh --quick      # Quick smoke test   (TOY, 2 trials)
#
# Environment overrides:
#   BENCH_RESULTS_ROOT=<dir>  Override the results root (default: scripts/results).
#   DRY_RUN=1                 Print the resolved command plan (including the
#                              comparison-benchmark invocation and, in the
#                              paper-grade branch, the assert_methods.sh
#                              postcondition call) and the resolved results
#                              root, then exit 0 before touching the
#                              filesystem (no build check, mkdir, symlink,
#                              log, or metadata writes).
#
# Output:
#   results/YYYY-MM-DD_HHMMSS_TAG/
#     csv/
#       piccard_timing_STD128.csv
#       piccard_accuracy_STD128.csv
#       piccard_combined_STD128.csv
#       comparison_timing_STD128.csv
#       dynamic_timing_STD128.csv
#       dynamic_accuracy_STD128.csv
#       threshold_timing_STD128.csv
#       threshold_accuracy_STD128.csv
#     tables/
#       summary.txt
#       tables_latex.tex
#     system_info.txt
#     run_metadata.txt
#     run.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"

# ── Thread policy ────────────────────────────────────────────────────
# The measuring machine has 10 cores (`sysctl -n hw.ncpu` = 10) and the repo
# already uses `-j8` throughout its build tooling. Fixing OMP to 8 leaves 2
# cores for OS/background work, which reduces inter-trial variance, and
# `OMP_DYNAMIC=FALSE` stops the OpenMP runtime from shrinking the team mid-run
# so "fixed" is actually fixed. This matters because SJ16's encryption loop is
# OpenMP-parallel (src/baselines/sj16.cpp:175) and R2-W1 requires that the
# comparison against Piccard be measured under the same thread conditions.
BENCH_OMP_THREADS=8
export OMP_NUM_THREADS="$BENCH_OMP_THREADS"
export OMP_DYNAMIC=FALSE

# Prints a canonical, machine-readable line reporting the *exported*
# environment as seen by a child process (not the runner's own shell
# variables) — `env` only lists exported variables, so a missing `export`
# surfaces here as "unset" instead of silently reporting the right text.
print_env_line() {
    env | awk -F= '/^OMP_NUM_THREADS=/{t=$2} /^OMP_DYNAMIC=/{d=$2} \
         END{printf "ENV: OMP_NUM_THREADS=%s OMP_DYNAMIC=%s\n", (t?t:"unset"), (d?d:"unset")}'
}

# ── Defaults (paper-grade) ──────────────────────────────────────────
SECURITY_LEVELS=("STD128")
TIMING_TRIALS=30
ACCURACY_TRIALS=50
FPFN_TRIALS=2000        # boundary FP/FN trials per J-grid point
TAG="paper"
TRANSCRIPT_STAT_BITS=40
MAX_QUERIES=1048576
saw_transcript=0
saw_max_queries=0

validate_max_queries() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]] || return 1
    while [[ ${#value} -gt 1 && "$value" == 0* ]]; do
        value="${value#0}"
    done
    [[ "$value" != "0" ]] || return 1
    local maximum="9223372036854775808"
    [[ ${#value} -lt ${#maximum} ]] ||
        [[ ${#value} -eq ${#maximum} &&
           ( "$value" == "$maximum" || "$value" < "$maximum" ) ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            SECURITY_LEVELS=("TOY")
            TIMING_TRIALS=2
            ACCURACY_TRIALS=5
            FPFN_TRIALS=1
            TAG="quick"
            ;;
        --transcript_stat_bits=*)
            [[ $saw_transcript -eq 0 ]] ||
                { echo "Duplicate --transcript_stat_bits" >&2; exit 2; }
            saw_transcript=1
            TRANSCRIPT_STAT_BITS="${1#*=}"
            case "$TRANSCRIPT_STAT_BITS" in
                40|64|128) ;;
                *) echo "Invalid --transcript_stat_bits" >&2; exit 2 ;;
            esac
            ;;
        --max_queries=*)
            [[ $saw_max_queries -eq 0 ]] ||
                { echo "Duplicate --max_queries" >&2; exit 2; }
            saw_max_queries=1
            MAX_QUERIES="${1#*=}"
            validate_max_queries "$MAX_QUERIES" ||
                { echo "Invalid --max_queries" >&2; exit 2; }
            ;;
        *)
            echo "Unknown runner option: $1" >&2
            exit 2
            ;;
    esac
    shift
done
if [[ "$TAG" == "quick" ]]; then
    FPFN_PROFILE="readiness-toy-v1"
else
    FPFN_PROFILE="paper-v1"
fi
SANITIZER_FLAGS=(
    "--transcript_stat_bits=$TRANSCRIPT_STAT_BITS"
    "--max_queries=$MAX_QUERIES"
)

# ── Quick-mode extra flags for new benchmarks ─────────────────────
DYNAMIC_EXTRA_FLAGS=""
if [[ "$TAG" == "quick" ]]; then
    DYNAMIC_EXTRA_FLAGS="--depth=5"
fi

# ── Results root (overridable) ──────────────────────────────────────
BENCH_RESULTS_ROOT="${BENCH_RESULTS_ROOT:-$PROJECT_DIR/scripts/results}"

# Absolutize a caller-supplied relative root. Every path below (OUT_DIR, the
# `latest` symlink target, the OUTPUT_CSV:/ASSERT_CSV: contract lines) derives
# from this, and a CWD-relative value silently breaks them: `ln -s "$OUT_DIR"
# "$ROOT/latest"` resolves the target relative to the *symlink's* directory,
# so BENCH_RESULTS_ROOT=out yields out/latest -> out/out/<run> (dangling).
# Pure string manipulation — no stat, no mkdir — so it stays safe to run
# before the DRY_RUN early-exit below.
case "$BENCH_RESULTS_ROOT" in
    /*) ;;                                        # already absolute
    *)  BENCH_RESULTS_ROOT="$PWD/$BENCH_RESULTS_ROOT" ;;
esac

# ── Output directory (path computation only — no filesystem writes yet,
#    so this is safe to do before the DRY_RUN early-exit below) ────────
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
OUT_DIR="$BENCH_RESULTS_ROOT/${TIMESTAMP}_${TAG}"
CSV_DIR="$OUT_DIR/csv"
TABLE_DIR="$OUT_DIR/tables"

# ── Helper ──────────────────────────────────────────────────────────
run_bench() {
    local name="$1"
    local bin="$2"
    local outfile="$3"
    shift 3
    local args=("$@")

    echo "------------------------------------------------------------"
    echo "  Running: $name"
    echo "  Command: $(basename "$bin") ${args[*]}"
    echo "------------------------------------------------------------"

    local start_time
    start_time=$(date +%s)

    local logfile="${outfile%.csv}.log"
    "$bin" "${args[@]}" > "$outfile" 2> "$logfile"
    local rc=$?

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    # Show stderr progress in console
    cat "$logfile"

    if [[ $rc -eq 0 ]]; then
        echo "  Done in ${elapsed}s -> $(basename "$outfile")"
    else
        echo "  FAILED (exit $rc) after ${elapsed}s"
    fi
    echo ""
    return $rc
}

# ── Command plan: comparison timing + postcondition ─────────────────
# Builds the bench_comparison timing invocation for one security level and,
# in the paper-grade branch only, the assert_methods.sh postcondition check
# that must run immediately after it. Both the comparison call and the
# postcondition call are emitted from this single function so that a
# dry-run's line-adjacency reflects real control flow, not just textual
# proximity between two independently-generated log lines.
plan_comparison() {
    local security="$1"
    local csv="$CSV_DIR/comparison_timing_${security}.csv"

    local args=(--mode=timing --security="$security" --trials="$TIMING_TRIALS" \
                --set_size=1000 --accuracy_trials="$ACCURACY_TRIALS" \
                "${SANITIZER_FLAGS[@]}")
    if [[ "$TAG" != "quick" ]]; then
        # --sj16, paper-grade only. SJ16 at 3072-bit costs ~4.9 min/query at
        # 2^14 and ~19.5 min at 2^16, single-threaded (design doc
        # docs/.../2026-07-24-sj16-baseline-design.md:207); 30 trials =>
        # ~12.2h single-threaded, ~92min even at an ideal 8 threads (plan 13-3
        # tripled TIMING_TRIALS 10->30 on top of this; the 10-trial figures
        # were ~4.1h / ~31min). Acceptable for a long paper-grade run, not for
        # a --quick smoke test.
        args+=(--sj16)
    fi

    echo "OUTPUT_CSV: $csv"
    echo "ASSERT_CSV: $csv"
    echo "  bench_comparison ${args[*]}"
    if [[ "$TAG" != "quick" ]]; then
        echo "  scripts/assert_methods.sh $csv"
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        return 0
    fi

    run_bench "Comparison timing ($security)" "$BUILD_DIR/bench_comparison" "$csv" "${args[@]}"
    if [[ "$TAG" != "quick" ]]; then
        "$SCRIPT_DIR/assert_methods.sh" "$csv"
    fi
}

# ── DRY_RUN: print the command plan and exit before any side effects ──
if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "Command plan:"
    print_env_line
    for SECURITY in "${SECURITY_LEVELS[@]}"; do
        echo "  bench_piccard --mode=timing --security=$SECURITY --trials=$TIMING_TRIALS --set_size=1000 ${SANITIZER_FLAGS[*]}"
        echo "  bench_piccard --mode=accuracy --security=$SECURITY --trials=$ACCURACY_TRIALS --set_size=1000 ${SANITIZER_FLAGS[*]}"
        echo "  bench_piccard --mode=combined --security=$SECURITY --trials=$TIMING_TRIALS --accuracy_trials=$ACCURACY_TRIALS --overlap=0.3 --set_size=1000 ${SANITIZER_FLAGS[*]}"
        plan_comparison "$SECURITY"
        echo "  bench_dynamic --mode=timing --security=$SECURITY --trials=$TIMING_TRIALS --set_size=1000${DYNAMIC_EXTRA_FLAGS:+ $DYNAMIC_EXTRA_FLAGS} ${SANITIZER_FLAGS[*]}"
        echo "  bench_dynamic --mode=accuracy --security=$SECURITY --trials=$ACCURACY_TRIALS --set_size=1000${DYNAMIC_EXTRA_FLAGS:+ $DYNAMIC_EXTRA_FLAGS} ${SANITIZER_FLAGS[*]}"
        echo "  bench_threshold --mode=timing --security=$SECURITY --trials=$TIMING_TRIALS --set_size=1000"
        echo "  bench_threshold --mode=accuracy --security=$SECURITY --trials=$ACCURACY_TRIALS --set_size=1000"
        echo "  python3 $SCRIPT_DIR/run_threshold_fpfn_grid.py --binary $BUILD_DIR/bench_threshold --profile $FPFN_PROFILE --security $SECURITY --seed 20260729 --trials $FPFN_TRIALS --output $CSV_DIR/threshold_fpfn_${SECURITY}.csv"
        echo "  bench_threshold --mode=spec --security=$SECURITY"
    done
    echo "Resolved sanitizer profile: transcript_stat_bits=$TRANSCRIPT_STAT_BITS max_queries=$MAX_QUERIES"
    echo "Resolved results root: $BENCH_RESULTS_ROOT"
    exit 0
fi

# ── Verify binaries ─────────────────────────────────────────────────
if [[ ! -x "$BUILD_DIR/bench_piccard" ]] || [[ ! -x "$BUILD_DIR/bench_comparison" ]]; then
    echo "Building benchmarks..."
    NCPU="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
    cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" >/dev/null 2>&1
    cmake --build "$BUILD_DIR" -j"$NCPU" 2>&1
fi

mkdir -p "$CSV_DIR" "$TABLE_DIR"

# Stable pointer to the most recent run, so tooling and verification gates have
# a predictable path (results/latest/csv/...) independent of the timestamp.
# Lives under BENCH_RESULTS_ROOT so an overridden root stays fully isolated.
# Target is the bare run-directory name, not $OUT_DIR: a symlink target is
# resolved relative to the directory holding the link, and both live directly
# under BENCH_RESULTS_ROOT. This keeps the link valid even if the whole
# results tree is moved or mounted elsewhere.
ln -sfn "${TIMESTAMP}_${TAG}" "$BENCH_RESULTS_ROOT/latest"

LOG="$OUT_DIR/run.log"
exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo "  Piccard Benchmark Suite"
echo "  $(date)"
echo "  Security: ${SECURITY_LEVELS[*]}"
echo "  Timing trials:   $TIMING_TRIALS"
echo "  Accuracy trials: $ACCURACY_TRIALS"
echo "  Tag: $TAG"
echo "  Output: $OUT_DIR"
echo "  OMP threads: $BENCH_OMP_THREADS (OMP_DYNAMIC=FALSE)"
echo "============================================================"
echo ""

# ── System info ─────────────────────────────────────────────────────
{
    echo "Date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Hostname: $(hostname)"
    echo "OS:       $(uname -srm)"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "CPU:      $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
        echo "Cores:    $(sysctl -n hw.ncpu)"
        echo "RAM:      $(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
    else
        echo "CPU:      $(lscpu 2>/dev/null | grep 'Model name' | sed 's/.*: *//' || echo unknown)"
        echo "Cores:    $(nproc)"
        echo "RAM:      $(free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo unknown)"
    fi
    echo "Compiler: $(c++ --version 2>/dev/null | head -1 || echo unknown)"
    echo "OpenFHE:  $(grep 'Found OpenFHE' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null | head -1 || echo unknown)"
    echo "Build:    Release -O3"
    echo "Security: ${SECURITY_LEVELS[*]}"
    echo "Timing trials:   $TIMING_TRIALS"
    echo "Accuracy trials: $ACCURACY_TRIALS"
} > "$OUT_DIR/system_info.txt"

cat "$OUT_DIR/system_info.txt"
echo ""

# Thread-policy metadata, recorded by name so the paper can cite the
# conditions the comparison ran under (R2-W1: same-conditions comparison).
{
    echo "OMP_NUM_THREADS=$BENCH_OMP_THREADS"
    echo "OMP_DYNAMIC=FALSE"
    if [[ "$TAG" != "quick" ]]; then
        # Comparison-stage runtime re-estimate (plan 13-3): TIMING_TRIALS
        # tripled (10->30) on top of the --sj16 flag plan 10 added to the
        # paper-grade branch. ~24.4 min/trial (4.9 min @2^14 + 19.5 min @2^16,
        # single-threaded, design doc docs/.../2026-07-24-sj16-baseline-design.md:207).
        est_min=$(awk -v t="$TIMING_TRIALS" 'BEGIN{printf "%.0f", t*24.4}')
        est_hr=$(awk -v t="$TIMING_TRIALS" 'BEGIN{printf "%.1f", t*24.4/60}')
        est_8t_min=$(awk -v t="$TIMING_TRIALS" 'BEGIN{printf "%.0f", t*24.4/8}')
        echo "EstimatedComparisonRuntime: SJ16 sweep at TIMING_TRIALS=$TIMING_TRIALS => ~${est_hr}h single-threaded (~${est_min}min) / ~${est_8t_min}min at 8 threads (ideal)"
    fi
} > "$OUT_DIR/run_metadata.txt"

# ── Run benchmarks for each security level ─────────────────────────
for SECURITY in "${SECURITY_LEVELS[@]}"; do
    echo ""
    echo "============================================================"
    echo "  Security level: $SECURITY"
    echo "============================================================"
    echo ""

    # ── 1. bench_piccard: timing ────────────────────────────────────
    run_bench "Piccard timing ($SECURITY)" \
        "$BUILD_DIR/bench_piccard" \
        "$CSV_DIR/piccard_timing_${SECURITY}.csv" \
        --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000 \
        "${SANITIZER_FLAGS[@]}"

    # ── 2. bench_piccard: accuracy ──────────────────────────────────
    run_bench "Piccard accuracy ($SECURITY)" \
        "$BUILD_DIR/bench_piccard" \
        "$CSV_DIR/piccard_accuracy_${SECURITY}.csv" \
        --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" --set_size=1000 \
        "${SANITIZER_FLAGS[@]}"

    # ── 3. bench_piccard: combined ──────────────────────────────────
    run_bench "Piccard combined ($SECURITY)" \
        "$BUILD_DIR/bench_piccard" \
        "$CSV_DIR/piccard_combined_${SECURITY}.csv" \
        --mode=combined --security="$SECURITY" \
        --trials="$TIMING_TRIALS" --accuracy_trials="$ACCURACY_TRIALS" \
        --overlap=0.3 --set_size=1000 "${SANITIZER_FLAGS[@]}"

    # ── 4. bench_comparison: timing (+ SJ16 postcondition, paper-grade only)
    plan_comparison "$SECURITY"

    # ── 5. bench_dynamic: timing (optional) ─────────────────────────
    if [[ -x "$BUILD_DIR/bench_dynamic" ]]; then
        run_bench "Dynamic timing ($SECURITY)" \
            "$BUILD_DIR/bench_dynamic" \
            "$CSV_DIR/dynamic_timing_${SECURITY}.csv" \
            --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000 \
            $DYNAMIC_EXTRA_FLAGS "${SANITIZER_FLAGS[@]}"

        # ── 6. bench_dynamic: accuracy ──────────────────────────────
        run_bench "Dynamic accuracy ($SECURITY)" \
            "$BUILD_DIR/bench_dynamic" \
            "$CSV_DIR/dynamic_accuracy_${SECURITY}.csv" \
            --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" --set_size=1000 \
            $DYNAMIC_EXTRA_FLAGS "${SANITIZER_FLAGS[@]}"
    else
        echo "  (bench_dynamic not built, skipping)"
    fi

    # ── 7. bench_threshold: timing (optional) ───────────────────────
    if [[ -x "$BUILD_DIR/bench_threshold" ]]; then
        run_bench "Threshold timing ($SECURITY)" \
            "$BUILD_DIR/bench_threshold" \
            "$CSV_DIR/threshold_timing_${SECURITY}.csv" \
            --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000

        # ── 8. bench_threshold: accuracy ────────────────────────────
        run_bench "Threshold accuracy ($SECURITY)" \
            "$BUILD_DIR/bench_threshold" \
            "$CSV_DIR/threshold_accuracy_${SECURITY}.csv" \
            --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" --set_size=1000

        # ── 8b. bench_threshold: boundary FP/FN (true-Jaccard, R3-4) ─
        # The point producer is plaintext-only; this runner invokes the
        # fixed 84-point orchestrator with an explicit profile and root seed.
        run_bench "Threshold boundary FP/FN ($SECURITY)" \
            "$(command -v python3)" \
            "$CSV_DIR/threshold_fpfn_${SECURITY}.csv" \
            "$SCRIPT_DIR/run_threshold_fpfn_grid.py" \
            --binary "$BUILD_DIR/bench_threshold" \
            --profile "$FPFN_PROFILE" \
            --security "$SECURITY" \
            --seed 20260729 \
            --trials "$FPFN_TRIALS" \
            --output "$CSV_DIR/threshold_fpfn_${SECURITY}.csv"

        # ── 8c. bench_threshold: u_tau spec dump (paper table, R3-4) ─
        run_bench "Threshold u_tau spec ($SECURITY)" \
            "$BUILD_DIR/bench_threshold" \
            "$CSV_DIR/threshold_spec_${SECURITY}.csv" \
            --mode=spec --security="$SECURITY"
    else
        echo "  (bench_threshold not built, skipping)"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────
echo "============================================================"
echo "  All benchmarks complete."
echo "  Results: $OUT_DIR"
echo ""
echo "  CSV files:"
for f in "$CSV_DIR"/*.csv; do
    lines=$(wc -l < "$f")
    echo "    $(basename "$f")  ($lines lines)"
done
echo ""
echo "  System info: $OUT_DIR/system_info.txt"
echo "  Full log:    $OUT_DIR/run.log"
echo "============================================================"

# ── Summarize results ─────────────────────────────────────────────
SUMMARIZE="$SCRIPT_DIR/summarize_results.py"
if [[ -f "$SUMMARIZE" ]]; then
    echo ""
    echo "============================================================"
    echo "  Generating summary tables..."
    echo "============================================================"
    echo ""
    python3 "$SUMMARIZE" "$CSV_DIR" --save-dir "$TABLE_DIR" --ci | tee "$TABLE_DIR/summary.txt"
    echo ""
    echo "  Summary saved: $TABLE_DIR/summary.txt"

    echo ""
    echo "------------------------------------------------------------"
    echo "  Generating LaTeX tables..."
    echo "------------------------------------------------------------"
    python3 "$SUMMARIZE" "$CSV_DIR" --latex --ci > "$TABLE_DIR/tables_latex.tex"
    echo "  LaTeX saved: $TABLE_DIR/tables_latex.tex"
else
    echo ""
    echo "  (summarize_results.py not found, skipping summary)"
fi
