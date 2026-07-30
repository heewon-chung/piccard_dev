#!/usr/bin/env bash
#
# run_core_benchmarks.sh — Run core Piccard benchmarks only (no Dynamic/Threshold).
#
# Usage:
#   ./scripts/run_core_benchmarks.sh              # Full paper-grade run (STD128, 10/50 timing/accuracy trials)
#   ./scripts/run_core_benchmarks.sh --quick      # Quick smoke test   (TOY, 2 trials)
#
# Output:
#   results/YYYY-MM-DD_HHMMSS_TAG/
#     csv/
#       piccard_timing_STD128.csv
#       piccard_accuracy_STD128.csv
#       piccard_combined_STD128.csv
#       comparison_timing_STD128.csv
#     tables/
#       summary.txt
#       tables_latex.tex
#     system_info.txt
#     run.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"

# ── Defaults (paper-grade) ──────────────────────────────────────────
SECURITY_LEVELS=("STD128")
TIMING_TRIALS=10
ACCURACY_TRIALS=50
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
SANITIZER_FLAGS=(
    "--transcript_stat_bits=$TRANSCRIPT_STAT_BITS"
    "--max_queries=$MAX_QUERIES"
)

BENCH_RESULTS_ROOT="${BENCH_RESULTS_ROOT:-$PROJECT_DIR/scripts/results}"
case "$BENCH_RESULTS_ROOT" in
    /*) ;;
    *) BENCH_RESULTS_ROOT="$PWD/$BENCH_RESULTS_ROOT" ;;
esac

if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "Command plan:"
    for SECURITY in "${SECURITY_LEVELS[@]}"; do
        echo "  bench_piccard --mode=timing --security=$SECURITY --trials=$TIMING_TRIALS --set_size=1000 ${SANITIZER_FLAGS[*]}"
        echo "  bench_piccard --mode=accuracy --security=$SECURITY --trials=$ACCURACY_TRIALS --set_size=1000 ${SANITIZER_FLAGS[*]}"
        echo "  bench_piccard --mode=combined --security=$SECURITY --trials=$TIMING_TRIALS --accuracy_trials=$ACCURACY_TRIALS --overlap=0.3 --set_size=1000 ${SANITIZER_FLAGS[*]}"
        echo "  bench_comparison --mode=timing --security=$SECURITY --trials=$TIMING_TRIALS --set_size=1000 ${SANITIZER_FLAGS[*]}"
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

# ── Output directory ────────────────────────────────────────────────
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
OUT_DIR="$BENCH_RESULTS_ROOT/${TIMESTAMP}_${TAG}"
CSV_DIR="$OUT_DIR/csv"
TABLE_DIR="$OUT_DIR/tables"
mkdir -p "$CSV_DIR" "$TABLE_DIR"

LOG="$OUT_DIR/run.log"
exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo "  Piccard Core Benchmark Suite"
echo "  $(date)"
echo "  Security: ${SECURITY_LEVELS[*]}"
echo "  Timing trials:   $TIMING_TRIALS"
echo "  Accuracy trials: $ACCURACY_TRIALS"
echo "  Tag: $TAG"
echo "  Output: $OUT_DIR"
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

# ── Run core benchmarks for each security level ─────────────────────
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

    # ── 4. bench_comparison: timing ─────────────────────────────────
    run_bench "Comparison timing ($SECURITY)" \
        "$BUILD_DIR/bench_comparison" \
        "$CSV_DIR/comparison_timing_${SECURITY}.csv" \
        --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000 \
        "${SANITIZER_FLAGS[@]}"
done

# ── Summary ─────────────────────────────────────────────────────────
echo "============================================================"
echo "  All core benchmarks complete."
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
    python3 "$SUMMARIZE" "$CSV_DIR" --save-dir "$TABLE_DIR" | tee "$TABLE_DIR/summary.txt"
    echo ""
    echo "  Summary saved: $TABLE_DIR/summary.txt"

    echo ""
    echo "------------------------------------------------------------"
    echo "  Generating LaTeX tables..."
    echo "------------------------------------------------------------"
    python3 "$SUMMARIZE" "$CSV_DIR" --latex > "$TABLE_DIR/tables_latex.tex"
    echo "  LaTeX saved: $TABLE_DIR/tables_latex.tex"
else
    echo ""
    echo "  (summarize_results.py not found, skipping summary)"
fi
