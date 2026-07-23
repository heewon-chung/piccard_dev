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

if [[ "${1:-}" == "--quick" ]]; then
    SECURITY_LEVELS=("TOY")
    TIMING_TRIALS=2
    ACCURACY_TRIALS=5
    TAG="quick"
    shift
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
OUT_DIR="$PROJECT_DIR/scripts/results/${TIMESTAMP}_${TAG}"
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
        --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000

    # ── 2. bench_piccard: accuracy ──────────────────────────────────
    run_bench "Piccard accuracy ($SECURITY)" \
        "$BUILD_DIR/bench_piccard" \
        "$CSV_DIR/piccard_accuracy_${SECURITY}.csv" \
        --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" --set_size=1000

    # ── 3. bench_piccard: combined ──────────────────────────────────
    run_bench "Piccard combined ($SECURITY)" \
        "$BUILD_DIR/bench_piccard" \
        "$CSV_DIR/piccard_combined_${SECURITY}.csv" \
        --mode=combined --security="$SECURITY" \
        --trials="$TIMING_TRIALS" --accuracy_trials="$ACCURACY_TRIALS" \
        --overlap=0.3 --set_size=1000

    # ── 4. bench_comparison: timing ─────────────────────────────────
    run_bench "Comparison timing ($SECURITY)" \
        "$BUILD_DIR/bench_comparison" \
        "$CSV_DIR/comparison_timing_${SECURITY}.csv" \
        --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" --set_size=1000
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
