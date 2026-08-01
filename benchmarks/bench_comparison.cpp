#include "benchmark_utils.h"
#include "baseline_engine.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <set>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

using namespace piccard;
using namespace piccard::benchmark;
using namespace piccard::baseline;

// NOTE (task 10-2, FHE-IND relabel): the std::cerr progress lines below print
// the lowercase method key "baseline" as shorthand for the FHE-IND comparator
// (baseline_engine.h) — this is developer-facing stderr progress output, not
// a reporting surface (verify_reporting_gaps.py does not capture it), so it
// is intentionally left unchanged. CSV/table/CLI-help text uses the FHE-IND
// relabel exclusively; see FHE_IND_DISCLOSURE in scripts/summarize_results.py
// and PrintUsage() below.

// ============================================================================
// Shared helpers
// ============================================================================

static double ExactJaccard(const std::vector<uint64_t>& a,
                           const std::vector<uint64_t>& b) {
    std::set<uint64_t> sa(a.begin(), a.end());
    std::set<uint64_t> sb(b.begin(), b.end());
    size_t inter = 0;
    for (auto x : sa) {
        if (sb.count(x)) inter++;
    }
    size_t uni = sa.size() + sb.size() - inter;
    if (uni == 0) return 1.0;
    return static_cast<double>(inter) / static_cast<double>(uni);
}

/// Generate two sets with elements in [0, universe_size) and given overlap.
static std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSetsWithOverlap(size_t set_size, double overlap_fraction,
                    uint64_t universe_size) {
    size_t overlap = static_cast<size_t>(overlap_fraction * set_size);

    // Ensure we don't exceed universe bounds:
    // Need overlap shared + (set_size - overlap) unique_a + (set_size - overlap) unique_b
    // = 2*set_size - overlap distinct elements
    if (2 * set_size - overlap > universe_size) {
        throw std::runtime_error(
            "Universe too small: need " +
            std::to_string(2 * set_size - overlap) +
            " distinct elements but universe_size=" +
            std::to_string(universe_size));
    }

    std::vector<uint64_t> a, b;
    a.reserve(set_size);
    b.reserve(set_size);

    // Shared elements: [0, overlap)
    for (uint64_t i = 0; i < overlap; i++) {
        a.push_back(i);
        b.push_back(i);
    }
    // Unique to A: [overlap, overlap + (set_size - overlap))
    for (uint64_t i = overlap; i < set_size; i++) {
        a.push_back(i);
    }
    // Unique to B: [set_size, set_size + (set_size - overlap))
    for (uint64_t i = 0; i < set_size - overlap; i++) {
        b.push_back(set_size + i);
    }

    return {a, b};
}

struct ReviewerWorkload {
    std::vector<uint64_t> set_a;
    std::vector<uint64_t> set_b;
    double target_jaccard = 0.0;
    size_t intersection = 0;
    size_t union_size = 0;
    double realized_jaccard = 0.0;
};

/** Build equal-size sets whose exact rational Jaccard is nearest the target. */
static ReviewerWorkload MakeReviewerWorkload(size_t set_size,
                                             double target_jaccard,
                                             uint64_t universe_size) {
    const long double target = static_cast<long double>(target_jaccard);
    const long double ideal_intersection =
        (2.0L * static_cast<long double>(set_size) * target) /
        (1.0L + target);
    const size_t intersection = static_cast<size_t>(
        std::llround(ideal_intersection));
    const size_t union_size = 2 * set_size - intersection;
    if (union_size > universe_size) {
        throw std::invalid_argument(
            "reviewer comparison universe is too small for target Jaccard");
    }

    ReviewerWorkload workload;
    workload.target_jaccard = target_jaccard;
    workload.intersection = intersection;
    workload.union_size = union_size;
    workload.realized_jaccard = union_size == 0
        ? 1.0
        : static_cast<double>(intersection) /
              static_cast<double>(union_size);
    workload.set_a.reserve(set_size);
    workload.set_b.reserve(set_size);
    for (uint64_t value = 0; value < intersection; ++value) {
        workload.set_a.push_back(value);
        workload.set_b.push_back(value);
    }
    for (uint64_t value = intersection; value < set_size; ++value) {
        workload.set_a.push_back(value);
    }
    for (uint64_t offset = 0; offset < set_size - intersection; ++offset) {
        workload.set_b.push_back(set_size + offset);
    }
    return workload;
}

// SJ16 adapter (Phase 4) — owns the SJ16 per-trial timing + aggregation. Kept
// out of this shared file; included here because it maps onto ComparisonResult
// above. Compiled out entirely when GMP/piccard_baselines is absent.
#ifdef HAVE_SJ16
#include "sj16_adapter.h"
#endif

// ============================================================================
// CSV output for ComparisonResult
// ============================================================================

// Measurement thread count at the moment this row is written (task 13-4).
// Not a per-row-construction field: OMP_NUM_THREADS/omp_set_num_threads is
// fixed for the process lifetime, so querying it here (synchronously, right
// before the row is serialized) is equivalent to capturing it wherever the
// row was built, without touching every Run*/FinalizeSJ16* call site.
static uint32_t CurrentOmpThreads() {
#ifdef _OPENMP
    return static_cast<uint32_t>(omp_get_max_threads());
#else
    return 1;
#endif
}

class ComparisonCSVWriter {
public:
    ComparisonCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << SerializeComparisonHeader();
    }

    void WriteRow(const ComparisonResult& r) {
        *out_ << SerializeComparisonRow(r, CurrentOmpThreads());
    }

private:
    std::ostream* out_;
};

static void ClearAccuracyFields(ComparisonResult& row) {
    row.jaccard_computed = 0.0;
    row.jaccard_expected = 0.0;
    row.jaccard_error = 0.0;
    row.jaccard_rel_error = 0.0;
    row.rel_error_eligible_n = 0;
    row.accuracy_trials = 0;
}

static void BindReviewerRow(
    const BenchmarkConfig& config,
    const ReviewerWorkload& workload,
    BenchmarkMeasurementKind measurement_kind,
    ComparisonResult& row) {
    row.target_jaccard = workload.target_jaccard;
    row.realized_intersection = workload.intersection;
    row.realized_union = workload.union_size;
    row.realized_jaccard = workload.realized_jaccard;

    // FHE-IND is a diagnostic comparator, not a Piccard-family evidence row.
    // Leave its default legacy profile metadata intact instead of applying the
    // primary Piccard profile to the common comparison writer.
    if (row.method != "baseline") {
        ApplyBenchmarkProfile(config, row, measurement_kind);
    }
}

// ============================================================================
// Timed protocol: Piccard
// ============================================================================

static ComparisonResult RunPiccardTimed(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size)
{
    Timer timer;
    ComparisonResult cr;
    cr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    cr.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    cr.scenario = scenario;
    cr.method = "piccard";
    cr.universe_size = universe_size;
    cr.set_size = set_x.size();
    cr.k = engine.GetParams().k;
    cr.m = engine.GetParams().m;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = 1;  // Piccard always uses 1 ciphertext per party
    cr.mult_depth = 1;

    // Phase 1: Encode (minhash + onehot)
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    // Measure ciphertext size and communication cost
    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);
    // Communication: 2 parties upload 1 ct each + 1 result ct download
    cr.comm_bytes = 3 * cr.ct_size_bytes;

    // Phase 3: Compute (multiply + rotate-and-sum)
    const auto& bfv = engine.GetBFVContext();
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    auto result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 3.5: Noise flooding (cloud) — mirrors Piccard::Evaluate exit (piccard.cpp:77)
    timer.Start();
    result = bfv.Flood(result);
    cr.phase_flood_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + bias correction
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    double k = static_cast<double>(engine.GetParams().k);
    double m = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_flood_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j_hat;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j_hat - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Timed protocol: Baseline (binary vector)
// ============================================================================

static ComparisonResult RunBaselineTimed(
    const BaselineEngine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario)
{
    Timer timer;
    ComparisonResult cr;
    cr.estimator_model = EstimatorModel::NotApplicable;
    cr.sanitizer = NotApplicableSanitizerMetadata();
    cr.scenario = scenario;
    cr.method = "baseline";
    cr.universe_size = engine.GetParams().universe_size;
    cr.set_size = set_x.size();
    cr.k = 0;
    cr.m = 0;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = engine.GetParams().num_ciphertexts;

    // Phase 1: Encode (binary vector construction)
    timer.Start();
    auto chunks_x = engine.EncodeBinaryVectors(set_x);
    auto chunks_y = engine.EncodeBinaryVectors(set_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt (all chunks)
    timer.Start();
    auto ct_x = engine.EncryptChunks(chunks_x);
    auto ct_y = engine.EncryptChunks(chunks_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    // Measure ciphertext size and communication cost
    size_t per_ct_bytes = CiphertextSizer::GetSerializedSize(ct_x[0]);
    cr.ct_size_bytes = per_ct_bytes * ct_x.size();  // total per party
    // Communication: 2 parties upload num_cts each + 1 result ct download
    cr.comm_bytes = 2 * cr.ct_size_bytes + per_ct_bytes;

    // Phase 3: Compute (multiply + rotate-and-sum for each chunk, aggregate)
    timer.Start();
    auto ct_result = engine.ComputeInnerProduct(ct_x, ct_y);
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + Jaccard formula
    timer.Start();
    double j = engine.ComputeJaccardFromInnerProduct(
        ct_result, set_x.size(), set_y.size());
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Multi-trial aggregation using ComputeDispersion (replaces local Median)
// ============================================================================

static ComparisonResult RunMultiTrialPiccard(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size,
    size_t num_trials)
{
    RunPiccardTimed(engine, set_x, set_y, j_true, "warmup", universe_size);

    std::vector<double> v_encode, v_encrypt, v_compute, v_flood, v_decrypt, v_total;
    double sum_j_hat = 0.0, sum_j_err = 0.0;
    size_t rel_eligible = 0;
    double sum_rel_err = 0.0;
    size_t ct_size = 0; size_t comm_b = 0;

    for (size_t t = 0; t < num_trials; t++) {
        auto cr = RunPiccardTimed(engine, set_x, set_y, j_true, scenario, universe_size);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_flood.push_back(cr.phase_flood_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        sum_j_hat += cr.jaccard_computed;
        sum_j_err += cr.jaccard_error;
        if (j_true > 0.0) { sum_rel_err += cr.jaccard_error / j_true; rel_eligible++; }
        ct_size = cr.ct_size_bytes; comm_b = cr.comm_bytes;
    }

    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_cmp = ComputeDispersion(v_compute);
    auto d_flo = ComputeDispersion(v_flood);
    auto d_dec = ComputeDispersion(v_decrypt);
    auto d_tot = ComputeDispersion(v_total);
    double n = static_cast<double>(num_trials);

    ComparisonResult r;
    r.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    r.scenario = scenario; r.method = "piccard";
    r.universe_size = universe_size; r.set_size = set_x.size();
    r.k = engine.GetParams().k; r.m = engine.GetParams().m;
    r.ring_dim = engine.GetParams().ring_dim;
    r.num_cts = 1; r.mult_depth = 1;
    r.trials = num_trials;
    r.phase_encode_ms = d_enc.mean;  r.phase_encode_ms_sd = d_enc.sd;  r.phase_encode_ms_median = d_enc.median;
    r.phase_encrypt_ms = d_cry.mean; r.phase_encrypt_ms_sd = d_cry.sd; r.phase_encrypt_ms_median = d_cry.median;
    r.phase_compute_ms = d_cmp.mean; r.phase_compute_ms_sd = d_cmp.sd; r.phase_compute_ms_median = d_cmp.median;
    r.phase_flood_ms = d_flo.mean;   r.phase_flood_ms_sd = d_flo.sd;   r.phase_flood_ms_median = d_flo.median;
    r.phase_decrypt_ms = d_dec.mean; r.phase_decrypt_ms_sd = d_dec.sd; r.phase_decrypt_ms_median = d_dec.median;
    r.total_ms = d_tot.mean;         r.total_ms_sd = d_tot.sd;         r.total_ms_median = d_tot.median;
    r.memory_bytes = MemoryTracker::GetPeakRSS();
    r.ct_size_bytes = ct_size; r.comm_bytes = comm_b;
    r.jaccard_computed = sum_j_hat / n;
    r.jaccard_expected = j_true;
    r.jaccard_error = sum_j_err / n;
    r.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
    r.rel_error_eligible_n = rel_eligible;
    r.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    r.scaling_mod_size = engine.GetParams().scaling_mod_size;
    // Provenance (task 9-1a): this sweep never reseeds — every trial reuses
    // the engine's construction-time CRS — so hash_seed and hash_root_seed
    // both hold that same value (never config.seed, which the engine's hash
    // family is not derived from here).
    r.hash_randomness = "fixed";
    r.hash_seed = engine.GetParams().hash_seed;
    r.hash_root_seed = engine.GetParams().hash_seed;
    r.accuracy_trials = num_trials;
    return r;
}

static ComparisonResult RunMultiTrialBaseline(
    const BaselineEngine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    size_t num_trials)
{
    RunBaselineTimed(engine, set_x, set_y, j_true, "warmup");

    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt, v_total;
    double sum_j_hat = 0.0, sum_j_err = 0.0;
    size_t rel_eligible = 0;
    double sum_rel_err = 0.0;
    size_t ct_size = 0; size_t comm_b = 0; uint32_t ring_d = 0; uint32_t ncts = 0;

    for (size_t t = 0; t < num_trials; t++) {
        auto cr = RunBaselineTimed(engine, set_x, set_y, j_true, scenario);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        sum_j_hat += cr.jaccard_computed;
        sum_j_err += cr.jaccard_error;
        if (j_true > 0.0) { sum_rel_err += cr.jaccard_error / j_true; rel_eligible++; }
        ct_size = cr.ct_size_bytes; comm_b = cr.comm_bytes;
        ring_d = cr.ring_dim; ncts = cr.num_cts;
    }

    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_cmp = ComputeDispersion(v_compute);
    auto d_dec = ComputeDispersion(v_decrypt);
    auto d_tot = ComputeDispersion(v_total);
    double n = static_cast<double>(num_trials);

    ComparisonResult r;
    r.estimator_model = EstimatorModel::NotApplicable;
    r.sanitizer = NotApplicableSanitizerMetadata();
    r.scenario = scenario; r.method = "baseline";
    r.universe_size = engine.GetParams().universe_size;
    r.set_size = set_x.size(); r.k = 0; r.m = 0;
    r.ring_dim = ring_d; r.num_cts = ncts;
    r.trials = num_trials;
    r.phase_encode_ms = d_enc.mean;  r.phase_encode_ms_sd = d_enc.sd;  r.phase_encode_ms_median = d_enc.median;
    r.phase_encrypt_ms = d_cry.mean; r.phase_encrypt_ms_sd = d_cry.sd; r.phase_encrypt_ms_median = d_cry.median;
    r.phase_compute_ms = d_cmp.mean; r.phase_compute_ms_sd = d_cmp.sd; r.phase_compute_ms_median = d_cmp.median;
    r.phase_decrypt_ms = d_dec.mean; r.phase_decrypt_ms_sd = d_dec.sd; r.phase_decrypt_ms_median = d_dec.median;
    r.total_ms = d_tot.mean;         r.total_ms_sd = d_tot.sd;         r.total_ms_median = d_tot.median;
    r.memory_bytes = MemoryTracker::GetPeakRSS();
    r.ct_size_bytes = ct_size; r.comm_bytes = comm_b;
    r.jaccard_computed = sum_j_hat / n;
    r.jaccard_expected = j_true;
    r.jaccard_error = sum_j_err / n;
    r.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
    r.rel_error_eligible_n = rel_eligible;
    // Baseline uses no hash family (task 9-1a): hash_randomness/hash_seed/
    // hash_root_seed stay blank/0. accuracy_trials reflects the real sample
    // count — baseline has no separate accuracy loop.
    r.accuracy_trials = num_trials;
    return r;
}

// ============================================================================
// Multi-trial: BCG12 (fixed-set scenario — mirrors RunMultiTrialPiccard)
// ============================================================================

#ifdef HAVE_PICCARD_BASELINES
#include "baselines/bcg12.h"
#include "util/params.h"   // PiccardParams (CRS parity source)
static ComparisonResult RunBCG12MultiTrial(
    piccard::baselines::BCG12& eng, const std::vector<uint64_t>& x,
    const std::vector<uint64_t>& y, double j_true, const std::string& scenario,
    uint32_t universe, const char* method, uint32_t k, size_t trials) {
    eng.RunQuery(x,y);                                  // warmup (excluded)
    std::vector<double> enc,encr,comp,dec,tot;
    double sum_j_hat=0.0, sum_j_err=0.0, sum_rel=0.0; size_t rel_elig=0;
    piccard::baselines::QueryCost last{};
    for(size_t t=0;t<trials;t++){ auto q=eng.RunQuery(x,y);
        enc.push_back(q.phase_encode_ms); encr.push_back(q.phase_encrypt_ms);
        comp.push_back(q.phase_compute_ms); dec.push_back(q.phase_decrypt_ms);
        tot.push_back(q.total_ms);
        double e=std::abs(q.jaccard_estimate-j_true);
        sum_j_hat+=q.jaccard_estimate; sum_j_err+=e;
        if(j_true>0.0){ sum_rel+=e/j_true; rel_elig++; }
        last=q; }
    using piccard::benchmark::ComputeDispersion;
    auto de=ComputeDispersion(enc), dr=ComputeDispersion(encr), dc=ComputeDispersion(comp),
         dd=ComputeDispersion(dec), dt=ComputeDispersion(tot);
    double n=static_cast<double>(trials);
    ComparisonResult cr;
    cr.estimator_model = EstimatorModel::NotApplicable;
    cr.sanitizer = NotApplicableSanitizerMetadata();
    cr.scenario=scenario; cr.method=method; cr.universe_size=universe;
    cr.set_size=x.size(); cr.k=k; cr.m=0; cr.ring_dim=0; cr.num_cts=0; cr.mult_depth=0;
    cr.trials=trials;
    cr.phase_encode_ms=de.mean;  cr.phase_encode_ms_sd=de.sd;  cr.phase_encode_ms_median=de.median;
    cr.phase_encrypt_ms=dr.mean; cr.phase_encrypt_ms_sd=dr.sd; cr.phase_encrypt_ms_median=dr.median;
    cr.phase_compute_ms=dc.mean; cr.phase_compute_ms_sd=dc.sd; cr.phase_compute_ms_median=dc.median;
    cr.phase_decrypt_ms=dd.mean; cr.phase_decrypt_ms_sd=dd.sd; cr.phase_decrypt_ms_median=dd.median;
    cr.total_ms=dt.mean;         cr.total_ms_sd=dt.sd;         cr.total_ms_median=dt.median;
    cr.ct_size_bytes=last.ct_size_bytes; cr.comm_bytes=last.comm_bytes;
    cr.jaccard_computed=sum_j_hat/n; cr.jaccard_expected=j_true; cr.jaccard_error=sum_j_err/n;
    cr.jaccard_rel_error=(rel_elig>0)?(sum_rel/static_cast<double>(rel_elig)):-1.0;
    cr.rel_error_eligible_n=rel_elig;
    // BCG12-exact ignores the MinHash CRS entirely (task 9-1a): hash_* stay
    // blank/0. accuracy_trials reflects the real sample count (this function
    // is exact-mode-only in this file — see run_exact in BenchVarySetSize).
    cr.accuracy_trials=trials;
    cr.memory_bytes=MemoryTracker::GetPeakRSS(); return cr;
}
#endif

// ============================================================================
// Helper: check if m is valid for sqrt encoding
// ============================================================================

static bool IsSqrtValid(uint32_t m) {
    if (m < 4 || (m & (m - 1)) != 0) return false;
    uint32_t log2m = 0;
    { uint32_t tmp = m; while (tmp > 1) { log2m++; tmp >>= 1; } }
    return (log2m % 2 == 0);
}

// ============================================================================
// Timed protocol: SqrtPiccard
// Mirrors SqrtPiccard::Evaluate (sqrt_piccard.cpp lines 42-86)
// ============================================================================

static ComparisonResult RunSqrtPiccardTimed(
    const SqrtPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size)
{
    Timer timer;
    ComparisonResult cr;
    cr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    cr.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    cr.scenario = scenario;
    cr.method = "piccard_sqrt";
    cr.universe_size = universe_size;
    cr.set_size = set_x.size();
    cr.k = engine.GetParams().k;
    cr.m = engine.GetParams().m;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = 1;
    cr.mult_depth = 3;

    // Phase 1: Encode (minhash + sqrt encoding)
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);
    cr.comm_bytes = 3 * cr.ct_size_bytes;

    // Phase 3: Compute (4 sub-phases of sqrt evaluate)
    const auto& bfv = engine.GetBFVContext();
    uint32_t b = engine.GetParams().sqrt_base;
    uint32_t block = 2 * b;

    timer.Start();
    // 3a: Component-wise multiply (depth 1)
    auto product = bfv.Multiply(ct_x, ct_y);
    // 3b: Intra-digit rotate-and-sum
    auto digit_sums = product;
    for (uint32_t step = 1; step < b; step *= 2) {
        auto rotated = bfv.Rotate(digit_sums, static_cast<int>(step));
        digit_sums = bfv.Add(digit_sums, rotated);
    }
    // 3c: Digit AND multiply (depth 2)
    auto shifted = bfv.Rotate(digit_sums, static_cast<int>(b));
    auto anded = bfv.Multiply(digit_sums, shifted);
    // 3d: Cross-k sum
    auto result = anded;
    for (uint32_t step = block; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 3.5: Noise flooding (cloud) — mirrors SqrtPiccard::Evaluate exit (sqrt_piccard.cpp:101)
    timer.Start();
    result = bfv.Flood(result);
    cr.phase_flood_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + bias correction
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    double kd = static_cast<double>(engine.GetParams().k);
    double md = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / kd;
    double j_hat = (raw_ratio - 1.0 / md) / (1.0 - 1.0 / md);
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_flood_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j_hat;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j_hat - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Multi-trial: SqrtPiccard
// ============================================================================

static ComparisonResult RunMultiTrialSqrtPiccard(
    const SqrtPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size,
    size_t num_trials)
{
    RunSqrtPiccardTimed(engine, set_x, set_y, j_true, "warmup", universe_size);

    std::vector<double> v_encode, v_encrypt, v_compute, v_flood, v_decrypt, v_total;
    double sum_j_hat = 0.0, sum_j_err = 0.0;
    size_t rel_eligible = 0;
    double sum_rel_err = 0.0;
    size_t ct_size = 0; size_t comm_b = 0;

    for (size_t t = 0; t < num_trials; t++) {
        auto cr = RunSqrtPiccardTimed(engine, set_x, set_y, j_true, scenario, universe_size);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_flood.push_back(cr.phase_flood_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        sum_j_hat += cr.jaccard_computed;
        sum_j_err += cr.jaccard_error;
        if (j_true > 0.0) { sum_rel_err += cr.jaccard_error / j_true; rel_eligible++; }
        ct_size = cr.ct_size_bytes; comm_b = cr.comm_bytes;
    }

    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_cmp = ComputeDispersion(v_compute);
    auto d_flo = ComputeDispersion(v_flood);
    auto d_dec = ComputeDispersion(v_decrypt);
    auto d_tot = ComputeDispersion(v_total);
    double n = static_cast<double>(num_trials);

    ComparisonResult r;
    r.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    r.scenario = scenario; r.method = "piccard_sqrt";
    r.universe_size = universe_size; r.set_size = set_x.size();
    r.k = engine.GetParams().k; r.m = engine.GetParams().m;
    r.ring_dim = engine.GetParams().ring_dim;
    r.num_cts = 1; r.mult_depth = 3;
    r.trials = num_trials;
    r.phase_encode_ms = d_enc.mean;  r.phase_encode_ms_sd = d_enc.sd;  r.phase_encode_ms_median = d_enc.median;
    r.phase_encrypt_ms = d_cry.mean; r.phase_encrypt_ms_sd = d_cry.sd; r.phase_encrypt_ms_median = d_cry.median;
    r.phase_compute_ms = d_cmp.mean; r.phase_compute_ms_sd = d_cmp.sd; r.phase_compute_ms_median = d_cmp.median;
    r.phase_flood_ms = d_flo.mean;   r.phase_flood_ms_sd = d_flo.sd;   r.phase_flood_ms_median = d_flo.median;
    r.phase_decrypt_ms = d_dec.mean; r.phase_decrypt_ms_sd = d_dec.sd; r.phase_decrypt_ms_median = d_dec.median;
    r.total_ms = d_tot.mean;         r.total_ms_sd = d_tot.sd;         r.total_ms_median = d_tot.median;
    r.memory_bytes = MemoryTracker::GetPeakRSS();
    r.ct_size_bytes = ct_size; r.comm_bytes = comm_b;
    r.jaccard_computed = sum_j_hat / n;
    r.jaccard_expected = j_true;
    r.jaccard_error = sum_j_err / n;
    r.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
    r.rel_error_eligible_n = rel_eligible;
    r.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    r.scaling_mod_size = engine.GetParams().scaling_mod_size;
    // Provenance (task 9-1a): this sweep never reseeds, same rationale as
    // RunMultiTrialPiccard above.
    r.hash_randomness = "fixed";
    r.hash_seed = engine.GetParams().hash_seed;
    r.hash_root_seed = engine.GetParams().hash_seed;
    r.accuracy_trials = num_trials;
    return r;
}

// ============================================================================
// CLI config (extends BenchmarkConfig with universe_size)
// Placed before scenarios so they can reference it.
// ============================================================================

struct ComparisonConfig {
    BenchmarkConfig base;
    uint32_t universe_size = 65536;  // Default: 2^16

    // SJ16 baseline (Phase 4), opt-in. Runs only in BenchVaryUniverse.
    bool sj16 = false;                   // --sj16
    uint32_t sj16_key_bits = 3072;       // --sj16_key_bits=K (1024/2048/3072)
    uint32_t sj16_max_universe = 65536;  // --sj16_max_universe=N (measure boundary)
    bool sj16_precompute = false;        // --sj16_precompute (D5 sensitivity row)

    static ComparisonConfig ParseArgs(int argc, char** argv) {
        ComparisonConfig config;
        config.base = BenchmarkConfig::ParseArgs(argc, argv);

        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            if (arg.find("--universe=") == 0) {
                config.universe_size =
                    static_cast<uint32_t>(std::stoul(arg.substr(11)));
            } else if (arg == "--sj16") {
                config.sj16 = true;
            } else if (arg.find("--sj16_key_bits=") == 0) {
                config.sj16_key_bits =
                    static_cast<uint32_t>(std::stoul(arg.substr(16)));
            } else if (arg.find("--sj16_max_universe=") == 0) {
                config.sj16_max_universe =
                    static_cast<uint32_t>(std::stoul(arg.substr(20)));
            } else if (arg == "--sj16_precompute") {
                config.sj16_precompute = true;
            }
        }
        return config;
    }

    void Print() const {
        base.Print();
        std::cerr << "  Universe: " << universe_size << "\n";
    }
};

static void SetReviewerAccuracyFields(
    ComparisonResult& row,
    const ReviewerWorkload& workload,
    size_t accuracy_trials,
    double estimate_sum,
    double error_sum) {
    const double trials = static_cast<double>(accuracy_trials);
    row.accuracy_trials = accuracy_trials;
    row.jaccard_computed = estimate_sum / trials;
    row.jaccard_expected = workload.realized_jaccard;
    row.jaccard_error = error_sum / trials;
    row.jaccard_rel_error = workload.realized_jaccard > 0.0
        ? row.jaccard_error / workload.realized_jaccard
        : -1.0;
    row.rel_error_eligible_n = workload.realized_jaccard > 0.0
        ? accuracy_trials
        : 0;
}

template <typename Engine>
static ComparisonResult RunReviewerHashedAccuracy(
    Engine& engine,
    const BenchmarkConfig& config,
    const ReviewerWorkload& workload,
    uint32_t universe_size,
    const std::string& scenario,
    const char* method,
    uint32_t mult_depth) {
    ComparisonResult row;
    row.scenario = scenario;
    row.method = method;
    row.universe_size = universe_size;
    row.set_size = workload.set_a.size();
    row.k = engine.GetParams().k;
    row.m = engine.GetParams().m;
    row.ring_dim = engine.GetParams().ring_dim;
    row.num_cts = 1;
    row.mult_depth = mult_depth;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    row.scaling_mod_size = engine.GetParams().scaling_mod_size;
    row.hash_randomness = HashRandomnessName(config.hash_randomness);
    row.hash_seed = engine.GetParams().hash_seed;
    row.hash_root_seed = config.hash_randomness == HashRandomness::Resampled
        ? config.seed
        : engine.GetParams().hash_seed;

    double estimate_sum = 0.0;
    double error_sum = 0.0;
    for (size_t trial = 0; trial < config.accuracy_trials; ++trial) {
        const uint64_t hash_seed =
            config.hash_randomness == HashRandomness::Resampled
            ? benchmark::HashTrialSeed(
                  config.seed, trial, workload.target_jaccard)
            : row.hash_seed;
        engine.SetHashSeed(hash_seed);
        const auto result = engine.Run(workload.set_a, workload.set_b);
        estimate_sum += result.jaccard_estimate;
        error_sum += std::abs(
            result.jaccard_estimate - workload.realized_jaccard);
    }
    SetReviewerAccuracyFields(
        row, workload, config.accuracy_trials, estimate_sum, error_sum);
    return row;
}

static ComparisonResult RunReviewerBaselineAccuracy(
    const BaselineEngine& engine,
    const BenchmarkConfig& config,
    const ReviewerWorkload& workload,
    const std::string& scenario) {
    ComparisonResult row;
    row.scenario = scenario;
    row.method = "baseline";
    row.universe_size = engine.GetParams().universe_size;
    row.set_size = workload.set_a.size();
    row.ring_dim = engine.GetParams().ring_dim;
    row.num_cts = engine.GetParams().num_ciphertexts;
    row.estimator_model = EstimatorModel::NotApplicable;
    row.sanitizer = NotApplicableSanitizerMetadata();

    double estimate_sum = 0.0;
    double error_sum = 0.0;
    for (size_t trial = 0; trial < config.accuracy_trials; ++trial) {
        (void)trial;
        const double estimate = engine.ComputeJaccard(
            workload.set_a, workload.set_b);
        estimate_sum += estimate;
        error_sum += std::abs(estimate - workload.realized_jaccard);
    }

    SetReviewerAccuracyFields(
        row, workload, config.accuracy_trials, estimate_sum, error_sum);
    return row;
}

static void WriteReviewerRowsForPoint(
    const ComparisonConfig& cfg,
    const BenchmarkGridPoint& point,
    ComparisonCSVWriter& csv) {
    BenchmarkConfig config = cfg.base;
    config.k = point.k;
    config.m = point.m;
    config.set_size = point.set_size;

    const ReviewerWorkload workload = MakeReviewerWorkload(
        config.set_size, point.target_jaccard, point.universe_size);
    const auto measurement_kinds = MeasurementKindsForMode(
        ParseBenchmarkMode(config.mode));

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    ApplyBenchmarkProfile(config, params);
    params.Validate();
    Piccard piccard(params);
    piccard.KeyGen();

    PiccardParams sqrt_params = params;
    sqrt_params.ValidateSqrt();
    SqrtPiccard sqrt_piccard(sqrt_params);
    sqrt_piccard.KeyGen();

    BaselineParams baseline_params;
    baseline_params.universe_size = point.universe_size;
    baseline_params.security = config.security_level;
    baseline_params.Validate();
    BaselineEngine baseline(baseline_params);
    baseline.Initialize();

    const std::string scenario =
        "vary_universe_" + std::to_string(point.universe_size);
    for (BenchmarkMeasurementKind kind : measurement_kinds) {
        if (kind == BenchmarkMeasurementKind::FheTiming) {
            auto piccard_row = RunMultiTrialPiccard(
                piccard, workload.set_a, workload.set_b,
                workload.realized_jaccard, scenario, point.universe_size,
                config.trials);
            ClearAccuracyFields(piccard_row);
            BindReviewerRow(config, workload, kind, piccard_row);
            csv.WriteRow(piccard_row);

            auto sqrt_row = RunMultiTrialSqrtPiccard(
                sqrt_piccard, workload.set_a, workload.set_b,
                workload.realized_jaccard, scenario, point.universe_size,
                config.trials);
            ClearAccuracyFields(sqrt_row);
            BindReviewerRow(config, workload, kind, sqrt_row);
            csv.WriteRow(sqrt_row);

            auto baseline_row = RunMultiTrialBaseline(
                baseline, workload.set_a, workload.set_b,
                workload.realized_jaccard, scenario, config.trials);
            ClearAccuracyFields(baseline_row);
            BindReviewerRow(config, workload, kind, baseline_row);
            csv.WriteRow(baseline_row);
        } else {
            auto piccard_row = RunReviewerHashedAccuracy(
                piccard, config, workload, point.universe_size, scenario,
                "piccard", 1);
            BindReviewerRow(config, workload, kind, piccard_row);
            csv.WriteRow(piccard_row);

            auto sqrt_row = RunReviewerHashedAccuracy(
                sqrt_piccard, config, workload, point.universe_size, scenario,
                "piccard_sqrt", 3);
            BindReviewerRow(config, workload, kind, sqrt_row);
            csv.WriteRow(sqrt_row);

            auto baseline_row = RunReviewerBaselineAccuracy(
                baseline, config, workload, scenario);
            BindReviewerRow(config, workload, kind, baseline_row);
            csv.WriteRow(baseline_row);
        }
    }
}

static void BenchReviewerComparison(const ComparisonConfig& cfg,
                                    ComparisonCSVWriter& csv) {
    const auto mode = ParseBenchmarkMode(cfg.base.mode);
    if ((mode == BenchmarkMode::Timing || mode == BenchmarkMode::Combined) &&
        cfg.base.trials == 0) {
        throw std::invalid_argument("reviewer timing trials must be positive");
    }
    if ((mode == BenchmarkMode::Accuracy || mode == BenchmarkMode::Combined) &&
        cfg.base.accuracy_trials == 0) {
        throw std::invalid_argument("reviewer accuracy trials must be positive");
    }

    BenchmarkGridPoint supplied;
    supplied.axis = "U";
    supplied.k = cfg.base.k;
    supplied.m = cfg.base.m;
    supplied.set_size = cfg.base.set_size;
    supplied.universe_size = cfg.universe_size;
    supplied.target_jaccard = cfg.base.target_jaccard;
    auto points = ResolveBenchmarkGrid(
        cfg.base.profile, BenchmarkProducer::Comparison, mode,
        cfg.base.evidence_point, supplied);
    for (auto& point : points) {
        // The CLI Jaccard target is the workload contract. The native resolver
        // supplies the two fixed reviewer universes and never substitutes the
        // legacy intersection/set-size overlap interpretation.
        point.target_jaccard = cfg.base.target_jaccard;
        WriteReviewerRowsForPoint(cfg, point, csv);
    }
}

// ============================================================================
// Scenario 1: Vary k (Piccard ring_dim changes; baseline constant)
// ============================================================================

static void BenchVaryK(const ComparisonConfig& cfg,
                       ComparisonCSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, cfg.base.security_level);
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5, u);
    double j_true = ExactJaccard(set_a, set_b);

    // Baseline: independent of k — run once and reuse
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                    "vary_k_baseline", config.trials);

    for (uint32_t k : k_values) {
        std::string scenario = "vary_k_" + std::to_string(k);

        // Piccard (one-hot)
        PiccardParams pp;
        pp.k = k;
        pp.m = config.m;
        pp.security = config.security_level;
        ApplyBenchmarkProfile(config, pp);
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        // SqrtPiccard (default m=64 is sqrt-valid)
        if (IsSqrtValid(config.m)) {
            PiccardParams sp;
            sp.k = k;
            sp.m = config.m;
            sp.security = config.security_level;
            ApplyBenchmarkProfile(config, sp);
            sp.ValidateSqrt();

            SqrtPiccard sqrt_eng(sp);
            sqrt_eng.KeyGen();

            auto sr = RunMultiTrialSqrtPiccard(sqrt_eng, set_a, set_b, j_true,
                                               scenario, u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  k=" << k
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms";
        } else {
            std::cerr << "  k=" << k
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: SKIPPED (m=" << config.m << " not sqrt-valid)";
        }

        // Baseline
        auto br_copy = br;
        br_copy.scenario = scenario;
        csv.WriteRow(br_copy);

        std::cerr << " | baseline: N=" << br_copy.ring_dim
                  << " total=" << br_copy.total_ms << "ms\n";
    }
}

// ============================================================================
// Scenario 2: Vary m (Piccard ring_dim changes; baseline constant)
// ============================================================================

static void BenchVaryM(const ComparisonConfig& cfg,
                       ComparisonCSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, cfg.base.security_level);
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5, u);
    double j_true = ExactJaccard(set_a, set_b);

    // Baseline: independent of m — run once and reuse
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                    "vary_m_baseline", config.trials);

    for (uint32_t m : m_values) {
        std::string scenario = "vary_m_" + std::to_string(m);

        // Piccard (one-hot) — runs for all m
        PiccardParams pp;
        pp.k = config.k;
        pp.m = m;
        pp.security = config.security_level;
        ApplyBenchmarkProfile(config, pp);
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        // SqrtPiccard — only for sqrt-valid m
        if (IsSqrtValid(m)) {
            PiccardParams sp;
            sp.k = config.k;
            sp.m = m;
            sp.security = config.security_level;
            ApplyBenchmarkProfile(config, sp);
            sp.ValidateSqrt();

            SqrtPiccard sqrt_eng(sp);
            sqrt_eng.KeyGen();

            auto sr = RunMultiTrialSqrtPiccard(sqrt_eng, set_a, set_b, j_true,
                                               scenario, u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  m=" << m
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms";
        } else {
            std::cerr << "  m=" << m
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: SKIPPED (not sqrt-valid)";
        }

        // Baseline — runs for all m
        auto br_copy = br;
        br_copy.scenario = scenario;
        csv.WriteRow(br_copy);

        std::cerr << " | baseline: N=" << br_copy.ring_dim
                  << " total=" << br_copy.total_ms << "ms\n";
    }
}

// ============================================================================
// Scenario 3: Vary universe size |U| (main comparison — Table in paper)
//
// Piccard ring_dim is constant (determined by k*m and security), while
// baseline ring_dim grows with U_set. This is THE key result.
// ============================================================================

static void BenchVaryUniverse(const ComparisonConfig& cfg,
                              ComparisonCSVWriter& csv) {
    // Universe sizes chosen to span: within Piccard ring_dim, at boundary,
    // and well beyond (forcing larger BFV parameters for baseline).
    std::vector<uint32_t> u_values =
        cfg.base.profile.run_class == BenchmarkRunClass::Legacy
        ? QuickSweep<uint32_t>({16384, 65536, 262144, 1048576},
                               cfg.base.security_level)
        : std::vector<uint32_t>{16384, 65536};
    const auto& config = cfg.base;

#ifdef HAVE_SJ16
    // SJ16 engine is caller-owned: constructed + Setup() ONCE per key size,
    // outside the universe loop (keygen is per-K, not per-trial/universe).
    std::unique_ptr<piccard::baselines::SJ16> sj16_eng;
    if (cfg.sj16) {
        sj16_eng = std::make_unique<piccard::baselines::SJ16>(
            cfg.sj16_key_bits, cfg.sj16_precompute);
        sj16_eng->Setup();
    }
#endif

    for (uint32_t u : u_values) {
        std::string scenario = "vary_universe_" + std::to_string(u);

#ifdef HAVE_SJ16
        // SJ16 measures up to sj16_max_universe; beyond it the row is left for
        // the Phase-3 fitted model. Instead of a symbolic T(m)=alpha*m+beta, the
        // adapter loads the matching PASS fit from the calibration artifact and
        // prints NUMERIC alpha/beta, the predicted T(u), the held-out residual,
        // and provenance so the extrapolated row is reproducible.
        std::vector<piccard::baselines::SJ16Trial> sj16_trials;
        const bool sj16_active = cfg.sj16 && (u <= cfg.sj16_max_universe);
        if (cfg.sj16 && !sj16_active) {
            std::cerr << "  U=" << u
                      << " sj16: SKIPPED (u > sj16_max_universe="
                      << cfg.sj16_max_universe << ")\n";
            PrintSJ16ExtrapolationNote(u, cfg.sj16_key_bits);
            // Task 13-2: publish the extrapolation as a CSV row too — the
            // stderr note above is operational logging, not a reporting
            // surface, so without this the row silently vanished from every
            // table. Gate is unchanged: only an authorized (PASS-fit) load
            // produces a row; an unauthorized one writes nothing.
            SJ16Extrapolation sj16_extrap =
                LoadSJ16Extrapolation(u, cfg.sj16_key_bits);
            if (sj16_extrap.authorized) {
                auto er = FinalizeSJ16Extrapolated(sj16_extrap, u, scenario,
                                                    config.set_size);
                er.estimator_model = EstimatorModel::NotApplicable;
                er.sanitizer = NotApplicableSanitizerMetadata();
                csv.WriteRow(er);
            }
        }
        if (sj16_active) sj16_eng->SetUniverse(u);
#endif

        // --- Piccard (constant ring_dim) ---
        PiccardParams pp;
        pp.k = config.k;
        pp.m = config.m;
        pp.security = config.security_level;
        ApplyBenchmarkProfile(config, pp);
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        // --- SqrtPiccard (constant ring_dim, smaller than Piccard) ---
        // Created once outside loop since params don't depend on universe
        bool has_sqrt = IsSqrtValid(config.m);
        std::unique_ptr<SqrtPiccard> sqrt_eng;
        if (has_sqrt) {
            PiccardParams sp;
            sp.k = config.k;
            sp.m = config.m;
            sp.security = config.security_level;
            ApplyBenchmarkProfile(config, sp);
            sp.ValidateSqrt();
            sqrt_eng = std::make_unique<SqrtPiccard>(sp);
            sqrt_eng->KeyGen();
        }

        // --- Baseline (ring_dim grows with U) ---
        BaselineParams bp;
        bp.universe_size = u;
        bp.security = config.security_level;
        bp.Validate();

        BaselineEngine baseline(bp);
        baseline.Initialize();

        // Use randomized sets per trial so timing varies across trials. The
        // Piccard/Sqrt/BCG12-MinHash accuracy fields are NOT accumulated here
        // any more (task 9-1): this loop is the --mode=timing path and the
        // shared contract (benchmark_utils.h:101/193) requires timing to
        // always run under one fixed CRS. Accuracy for those three engines is
        // computed by a separate untimed, per-trial-reseeded loop below.
        // Baseline has no hash family, so its accuracy stays sourced here.
        std::vector<double> p_encode, p_encrypt, p_compute, p_flood, p_decrypt, p_total;
        std::vector<double> s_encode, s_encrypt, s_compute, s_flood, s_decrypt, s_total;
        std::vector<double> b_encode, b_encrypt, b_compute, b_decrypt, b_total;
        ComparisonResult p_last, s_last, b_last;
        double total_b_err = 0.0;
        double sum_b_jhat = 0.0;

        // Warmup with deterministic sets
        {
            auto [wa, wb] = MakeSetsWithOverlap(config.set_size, 0.5, u);
            double wj = ExactJaccard(wa, wb);
            RunPiccardTimed(piccard, wa, wb, wj, "warmup", u);
            if (has_sqrt)
                RunSqrtPiccardTimed(*sqrt_eng, wa, wb, wj, "warmup", u);
            RunBaselineTimed(baseline, wa, wb, wj, "warmup");
        }

        // BCG12: MinHash cost is universe-independent, so build engines once
        // per universe row (before the trial loop) and accumulate per-trial,
        // mirroring the Piccard/SqrtPiccard/Baseline accumulation above.
#ifdef HAVE_PICCARD_BASELINES
        using piccard::baselines::BCG12; using piccard::baselines::Bcg12Params;
        using piccard::baselines::Bcg12Mode; using piccard::baselines::Bcg12Backend;
        Bcg12Params bp_ff; bp_ff.mode=Bcg12Mode::MinHash; bp_ff.backend=Bcg12Backend::FF;
        bp_ff.k=config.k; bp_ff.minhash_seed=PiccardParams{}.hash_seed;   // CRS parity
        Bcg12Params bp_ec=bp_ff; bp_ec.backend=Bcg12Backend::EC;
        BCG12 bcg12_ff(bp_ff); bcg12_ff.Setup();
        BCG12 bcg12_ec(bp_ec); bcg12_ec.Setup();
        // Timing-only vectors (task 9-1): accuracy accumulators for these two
        // engines moved to the untimed accuracy loop below, same as Piccard/Sqrt.
        std::vector<double> f_enc,f_encr,f_comp,f_dec,f_tot; piccard::baselines::QueryCost f_last{};
        std::vector<double> e_enc,e_encr,e_comp,e_dec,e_tot; piccard::baselines::QueryCost e_last{};
        // Warm-up (excluded) so the first measured trial has no cold-start bias, matching
        // every other engine's warm-up. Uses deterministic sets, like the existing warm-up block.
        { auto [wa,wb]=MakeSetsWithOverlap(config.set_size,0.5,u);
          bcg12_ff.RunQuery(wa,wb); bcg12_ec.RunQuery(wa,wb); }
#endif

        for (size_t t = 0; t < config.trials; t++) {
            std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = benchmark::MakeRandomSetsWithOverlap(
                config.set_size, 0.5, u, rng);
            double j_true = ExactJaccard(set_a, set_b);

            auto pr = RunPiccardTimed(piccard, set_a, set_b, j_true, scenario, u);
            p_encode.push_back(pr.phase_encode_ms);
            p_encrypt.push_back(pr.phase_encrypt_ms);
            p_compute.push_back(pr.phase_compute_ms);
            p_flood.push_back(pr.phase_flood_ms);
            p_decrypt.push_back(pr.phase_decrypt_ms);
            p_total.push_back(pr.total_ms);
            p_last = pr;

            if (has_sqrt) {
                auto sr = RunSqrtPiccardTimed(*sqrt_eng, set_a, set_b, j_true, scenario, u);
                s_encode.push_back(sr.phase_encode_ms);
                s_encrypt.push_back(sr.phase_encrypt_ms);
                s_compute.push_back(sr.phase_compute_ms);
                s_flood.push_back(sr.phase_flood_ms);
                s_decrypt.push_back(sr.phase_decrypt_ms);
                s_total.push_back(sr.total_ms);
                s_last = sr;
            }

            auto br = RunBaselineTimed(baseline, set_a, set_b, j_true, scenario);
            b_encode.push_back(br.phase_encode_ms);
            b_encrypt.push_back(br.phase_encrypt_ms);
            b_compute.push_back(br.phase_compute_ms);
            b_decrypt.push_back(br.phase_decrypt_ms);
            b_total.push_back(br.total_ms);
            total_b_err += br.jaccard_error;
            sum_b_jhat += br.jaccard_computed;
            b_last = br;

            // BCG12: per-trial TIMING accumulation only (task 9-1) — this loop
            // never reseeds, so its accuracy is not representative of the
            // resampled-CRS accuracy figure; that comes from the untimed loop
            // below. set_a/set_b are still used here for a realistic timing
            // measurement (payload-size-dependent PSI-CA cost).
#ifdef HAVE_PICCARD_BASELINES
            { auto q=bcg12_ff.RunQuery(set_a,set_b);
              f_enc.push_back(q.phase_encode_ms); f_encr.push_back(q.phase_encrypt_ms);
              f_comp.push_back(q.phase_compute_ms); f_dec.push_back(q.phase_decrypt_ms);
              f_tot.push_back(q.total_ms); f_last=q; }
            { auto q=bcg12_ec.RunQuery(set_a,set_b);
              e_enc.push_back(q.phase_encode_ms); e_encr.push_back(q.phase_encrypt_ms);
              e_comp.push_back(q.phase_compute_ms); e_dec.push_back(q.phase_decrypt_ms);
              e_tot.push_back(q.total_ms); e_last=q; }
#endif
#ifdef HAVE_SJ16
            // SJ16 reuses THIS trial's (set_a, set_b) — no independent draw.
            if (sj16_active) {
                sj16_trials.push_back(RunSJ16OnTrial(
                    *sj16_eng, set_a, set_b, j_true, u, cfg.sj16_precompute,
                    cfg.sj16_key_bits));
            }
#endif
        }

        // ── Untimed accuracy loop (task 9-1) ───────────────────────────
        // The timed loop above never reseeds (timing is always fixed-CRS —
        // benchmark_utils.h:101/193). This separate, untimed loop resamples
        // the MinHash CRS per trial and recomputes accuracy for the three
        // MinHash-using engines: Piccard, SqrtPiccard, BCG12-MinHash.
        // Baseline and SJ16 don't use a hash family, so their accuracy stays
        // sourced from the timed loop above (unchanged).
        //
        // Capture the timing CRS BEFORE any reseeding: SetHashSeed mutates
        // the engine, so this is the last point at which GetParams() reflects
        // what the timed loop above actually measured. Piccard, SqrtPiccard,
        // and BCG12 all default-construct to PiccardParams{}.hash_seed and
        // nothing reseeds them before this point, so one captured value is
        // valid for all three (CRS parity holds by construction).
        const uint64_t timing_crs = piccard.GetParams().hash_seed;

        double acc_sum_p_jhat = 0.0, acc_sum_p_err = 0.0;
        double acc_p_jtrue_last = 0.0;
        double acc_sum_s_jhat = 0.0, acc_sum_s_err = 0.0;
        double acc_s_jtrue_last = 0.0;
#ifdef HAVE_PICCARD_BASELINES
        double acc_sum_f_jhat = 0.0, acc_sum_f_err = 0.0;
        double acc_f_jtrue_last = 0.0;
        double acc_sum_e_jhat = 0.0, acc_sum_e_err = 0.0;
        double acc_e_jtrue_last = 0.0;
#endif

        for (size_t t = 0; t < config.accuracy_trials; t++) {
            std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = benchmark::MakeRandomSetsWithOverlap(
                config.set_size, 0.5, u, rng);
            double j_true = ExactJaccard(set_a, set_b);

            const uint64_t trial_hash_seed =
                (config.hash_randomness == HashRandomness::Resampled)
                    ? benchmark::HashTrialSeed(config.seed, t, 0.5)
                    : timing_crs;

            // engine.Run() is the protocol path (bucket matching + bias
            // correction + clamping), not the plaintext MinHasher shortcut —
            // the plaintext estimator is not protocol-equivalent.
            piccard.SetHashSeed(trial_hash_seed);
            auto p_res = piccard.Run(set_a, set_b);
            acc_sum_p_jhat += p_res.jaccard_estimate;
            acc_sum_p_err += std::abs(p_res.jaccard_estimate - j_true);
            acc_p_jtrue_last = j_true;

            if (has_sqrt) {
                sqrt_eng->SetHashSeed(trial_hash_seed);
                auto s_res = sqrt_eng->Run(set_a, set_b);
                acc_sum_s_jhat += s_res.jaccard_estimate;
                acc_sum_s_err += std::abs(s_res.jaccard_estimate - j_true);
                acc_s_jtrue_last = j_true;
            }

#ifdef HAVE_PICCARD_BASELINES
            // Same trial_hash_seed as Piccard/Sqrt above: preserves CRS
            // parity within a trial so the BCG12-MinHash accuracy comparison
            // stays paired with Piccard/Sqrt, not just internally consistent.
            bcg12_ff.SetHashSeed(trial_hash_seed);
            auto f_res = bcg12_ff.RunQuery(set_a, set_b);
            acc_sum_f_jhat += f_res.jaccard_estimate;
            acc_sum_f_err += std::abs(f_res.jaccard_estimate - j_true);
            acc_f_jtrue_last = j_true;

            bcg12_ec.SetHashSeed(trial_hash_seed);
            auto e_res = bcg12_ec.RunQuery(set_a, set_b);
            acc_sum_e_jhat += e_res.jaccard_estimate;
            acc_sum_e_err += std::abs(e_res.jaccard_estimate - j_true);
            acc_e_jtrue_last = j_true;
#endif
        }

        // Aggregate Piccard — explicit field assignment, no last-trial copy
        {
            auto d_enc = ComputeDispersion(p_encode);
            auto d_cry = ComputeDispersion(p_encrypt);
            auto d_cmp = ComputeDispersion(p_compute);
            auto d_flo = ComputeDispersion(p_flood);
            auto d_dec = ComputeDispersion(p_decrypt);
            auto d_tot = ComputeDispersion(p_total);

            ComparisonResult pr;
            pr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
            pr.scenario = scenario; pr.method = "piccard";
            pr.universe_size = u; pr.set_size = config.set_size;
            pr.k = piccard.GetParams().k; pr.m = piccard.GetParams().m;
            pr.ring_dim = piccard.GetParams().ring_dim;
            pr.num_cts = 1; pr.mult_depth = 1;
            pr.trials = config.trials;
            pr.phase_encode_ms = d_enc.mean;  pr.phase_encode_ms_sd = d_enc.sd;  pr.phase_encode_ms_median = d_enc.median;
            pr.phase_encrypt_ms = d_cry.mean; pr.phase_encrypt_ms_sd = d_cry.sd; pr.phase_encrypt_ms_median = d_cry.median;
            pr.phase_compute_ms = d_cmp.mean; pr.phase_compute_ms_sd = d_cmp.sd; pr.phase_compute_ms_median = d_cmp.median;
            pr.phase_flood_ms = d_flo.mean;   pr.phase_flood_ms_sd = d_flo.sd;   pr.phase_flood_ms_median = d_flo.median;
            pr.phase_decrypt_ms = d_dec.mean; pr.phase_decrypt_ms_sd = d_dec.sd; pr.phase_decrypt_ms_median = d_dec.median;
            pr.total_ms = d_tot.mean;         pr.total_ms_sd = d_tot.sd;         pr.total_ms_median = d_tot.median;
            pr.memory_bytes = MemoryTracker::GetPeakRSS();
            pr.ct_size_bytes = p_last.ct_size_bytes; pr.comm_bytes = p_last.comm_bytes;
            // Accuracy fields (task 9-1): recomputed entirely from the untimed,
            // per-trial-reseeded accuracy loop above — NOT from the timed loop's
            // (fixed-CRS) trials, so a fixed timing value and a resampled
            // accuracy value never end up mixed in the same row.
            double acc_n = static_cast<double>(config.accuracy_trials);
            pr.jaccard_computed = acc_sum_p_jhat / acc_n;
            pr.jaccard_expected = acc_p_jtrue_last;
            pr.jaccard_error = acc_sum_p_err / acc_n;
            size_t p_rel = (acc_p_jtrue_last > 0.0) ? config.accuracy_trials : 0;
            pr.jaccard_rel_error = (p_rel > 0) ? (pr.jaccard_error / pr.jaccard_expected) : -1.0;
            pr.rel_error_eligible_n = p_rel;
            pr.sanitizer = MakeSanitizerMetadata(piccard.GetParams());
            pr.scaling_mod_size = piccard.GetParams().scaling_mod_size;
            pr.hash_randomness = HashRandomnessName(config.hash_randomness);
            pr.hash_seed = timing_crs;
            pr.hash_root_seed = (config.hash_randomness == HashRandomness::Resampled)
                                     ? config.seed : timing_crs;
            pr.accuracy_trials = config.accuracy_trials;
            csv.WriteRow(pr);

            std::cerr << "  U=" << u
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " comm=" << (pr.comm_bytes / 1024) << "KB"
                      << " err=" << pr.jaccard_error << "\n";
        }

        // Aggregate SqrtPiccard — explicit field assignment
        if (has_sqrt) {
            auto d_enc = ComputeDispersion(s_encode);
            auto d_cry = ComputeDispersion(s_encrypt);
            auto d_cmp = ComputeDispersion(s_compute);
            auto d_flo = ComputeDispersion(s_flood);
            auto d_dec = ComputeDispersion(s_decrypt);
            auto d_tot = ComputeDispersion(s_total);

            ComparisonResult sr;
            sr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
            sr.scenario = scenario; sr.method = "piccard_sqrt";
            sr.universe_size = u; sr.set_size = config.set_size;
            sr.k = s_last.k; sr.m = s_last.m;
            sr.ring_dim = s_last.ring_dim;
            sr.num_cts = 1; sr.mult_depth = 3;
            sr.trials = config.trials;
            sr.phase_encode_ms = d_enc.mean;  sr.phase_encode_ms_sd = d_enc.sd;  sr.phase_encode_ms_median = d_enc.median;
            sr.phase_encrypt_ms = d_cry.mean; sr.phase_encrypt_ms_sd = d_cry.sd; sr.phase_encrypt_ms_median = d_cry.median;
            sr.phase_compute_ms = d_cmp.mean; sr.phase_compute_ms_sd = d_cmp.sd; sr.phase_compute_ms_median = d_cmp.median;
            sr.phase_flood_ms = d_flo.mean;   sr.phase_flood_ms_sd = d_flo.sd;   sr.phase_flood_ms_median = d_flo.median;
            sr.phase_decrypt_ms = d_dec.mean; sr.phase_decrypt_ms_sd = d_dec.sd; sr.phase_decrypt_ms_median = d_dec.median;
            sr.total_ms = d_tot.mean;         sr.total_ms_sd = d_tot.sd;         sr.total_ms_median = d_tot.median;
            sr.memory_bytes = MemoryTracker::GetPeakRSS();
            sr.ct_size_bytes = s_last.ct_size_bytes; sr.comm_bytes = s_last.comm_bytes;
            // Accuracy fields (task 9-1): recomputed from the untimed accuracy
            // loop above, same rationale as the Piccard block.
            {
                double acc_n = static_cast<double>(config.accuracy_trials);
                sr.jaccard_computed = acc_sum_s_jhat / acc_n;
                sr.jaccard_expected = acc_s_jtrue_last;
                sr.jaccard_error = acc_sum_s_err / acc_n;
                size_t s_rel = (acc_s_jtrue_last > 0.0) ? config.accuracy_trials : 0;
                sr.jaccard_rel_error = (s_rel > 0) ? (sr.jaccard_error / sr.jaccard_expected) : -1.0;
                sr.rel_error_eligible_n = s_rel;
            }
            sr.sanitizer =
                MakeSanitizerMetadata(sqrt_eng->GetParams());
            sr.scaling_mod_size = sqrt_eng->GetParams().scaling_mod_size;
            sr.hash_randomness = HashRandomnessName(config.hash_randomness);
            sr.hash_seed = timing_crs;
            sr.hash_root_seed = (config.hash_randomness == HashRandomness::Resampled)
                                     ? config.seed : timing_crs;
            sr.accuracy_trials = config.accuracy_trials;
            csv.WriteRow(sr);

            std::cerr << "  U=" << u
                      << " sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms"
                      << " comm=" << (sr.comm_bytes / 1024) << "KB"
                      << " err=" << sr.jaccard_error << "\n";
        }

        // Aggregate Baseline — explicit field assignment
        {
            auto d_enc = ComputeDispersion(b_encode);
            auto d_cry = ComputeDispersion(b_encrypt);
            auto d_cmp = ComputeDispersion(b_compute);
            auto d_dec = ComputeDispersion(b_decrypt);
            auto d_tot = ComputeDispersion(b_total);
            double n = static_cast<double>(config.trials);

            ComparisonResult br;
            br.estimator_model = EstimatorModel::NotApplicable;
            br.sanitizer = NotApplicableSanitizerMetadata();
            br.scenario = scenario; br.method = "baseline";
            br.universe_size = u; br.set_size = config.set_size;
            br.k = 0; br.m = 0;
            br.ring_dim = b_last.ring_dim; br.num_cts = b_last.num_cts;
            br.trials = config.trials;
            br.phase_encode_ms = d_enc.mean;  br.phase_encode_ms_sd = d_enc.sd;  br.phase_encode_ms_median = d_enc.median;
            br.phase_encrypt_ms = d_cry.mean; br.phase_encrypt_ms_sd = d_cry.sd; br.phase_encrypt_ms_median = d_cry.median;
            br.phase_compute_ms = d_cmp.mean; br.phase_compute_ms_sd = d_cmp.sd; br.phase_compute_ms_median = d_cmp.median;
            br.phase_decrypt_ms = d_dec.mean; br.phase_decrypt_ms_sd = d_dec.sd; br.phase_decrypt_ms_median = d_dec.median;
            br.total_ms = d_tot.mean;         br.total_ms_sd = d_tot.sd;         br.total_ms_median = d_tot.median;
            br.memory_bytes = MemoryTracker::GetPeakRSS();
            br.ct_size_bytes = b_last.ct_size_bytes; br.comm_bytes = b_last.comm_bytes;
            br.jaccard_computed = sum_b_jhat / n;
            br.jaccard_expected = b_last.jaccard_expected;
            br.jaccard_error = total_b_err / n;
            size_t b_rel = (b_last.jaccard_expected > 0.0) ? config.trials : 0;
            br.jaccard_rel_error = (b_rel > 0) ? (br.jaccard_error / br.jaccard_expected) : -1.0;
            br.rel_error_eligible_n = b_rel;
            // Baseline uses no hash family (task 9-1a): hash_randomness/
            // hash_seed/hash_root_seed stay at their blank/0 defaults.
            // accuracy_trials still reflects the real sample count — baseline
            // has no separate accuracy loop, its accuracy is the timed loop.
            br.accuracy_trials = config.trials;
            csv.WriteRow(br);

            std::cerr << "  U=" << u
                      << " baseline: N=" << br.ring_dim
                      << " cts=" << br.num_cts
                      << " total=" << br.total_ms << "ms"
                      << " comm=" << (br.comm_bytes / 1024) << "KB"
                      << " err=" << br.jaccard_error << "\n";
        }   // closes baseline block

        // BCG12: aggregate + emit per-variant rows (mirrors the Piccard aggregate block).
#ifdef HAVE_PICCARD_BASELINES
        auto emit_bcg12=[&](const char* method, std::vector<double>& ve,std::vector<double>& vr,
                            std::vector<double>& vc,std::vector<double>& vd,std::vector<double>& vt,
                            double acc_err, double acc_jhat, double acc_jtrue_last,
                            const piccard::baselines::QueryCost& last){
            using piccard::benchmark::ComputeDispersion;
            auto de=ComputeDispersion(ve),dr=ComputeDispersion(vr),dc=ComputeDispersion(vc),
                 dd=ComputeDispersion(vd),dt=ComputeDispersion(vt);
            ComparisonResult r;
            r.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
            r.sanitizer = NotApplicableSanitizerMetadata();
            r.scenario=scenario; r.method=method; r.universe_size=u;
            r.set_size=config.set_size; r.k=config.k; r.m=0; r.ring_dim=0; r.num_cts=0; r.mult_depth=0;
            r.trials=config.trials;
            r.phase_encode_ms=de.mean;  r.phase_encode_ms_sd=de.sd;  r.phase_encode_ms_median=de.median;
            r.phase_encrypt_ms=dr.mean; r.phase_encrypt_ms_sd=dr.sd; r.phase_encrypt_ms_median=dr.median;
            r.phase_compute_ms=dc.mean; r.phase_compute_ms_sd=dc.sd; r.phase_compute_ms_median=dc.median;
            r.phase_decrypt_ms=dd.mean; r.phase_decrypt_ms_sd=dd.sd; r.phase_decrypt_ms_median=dd.median;
            r.total_ms=dt.mean;         r.total_ms_sd=dt.sd;         r.total_ms_median=dt.median;
            r.memory_bytes=MemoryTracker::GetPeakRSS();
            r.ct_size_bytes=last.ct_size_bytes; r.comm_bytes=last.comm_bytes;
            // Accuracy fields (task 9-1): sourced from the untimed, per-trial-
            // reseeded accuracy loop above (acc_* args), not the timed loop's
            // fixed-CRS trials — same rationale as the Piccard/Sqrt blocks.
            double acc_n=static_cast<double>(config.accuracy_trials);
            r.jaccard_computed=acc_jhat/acc_n;       // MEAN estimate across accuracy trials
            r.jaccard_expected=acc_jtrue_last; r.jaccard_error=acc_err/acc_n;
            size_t rel=(acc_jtrue_last>0.0)?config.accuracy_trials:0;
            r.jaccard_rel_error=(rel>0)?(r.jaccard_error/acc_jtrue_last):-1.0; r.rel_error_eligible_n=rel;
            r.hash_randomness = HashRandomnessName(config.hash_randomness);
            r.hash_seed = timing_crs;
            r.hash_root_seed = (config.hash_randomness == HashRandomness::Resampled)
                                    ? config.seed : timing_crs;
            r.accuracy_trials = config.accuracy_trials;
            csv.WriteRow(r);
            std::cerr << "  U=" << u << " " << method << ": total=" << r.total_ms
                      << "ms comm=" << (r.comm_bytes/1024) << "KB err=" << r.jaccard_error << "\n"; };
        emit_bcg12("bcg12_mh_ff", f_enc,f_encr,f_comp,f_dec,f_tot, acc_sum_f_err, acc_sum_f_jhat, acc_f_jtrue_last, f_last);
        emit_bcg12("bcg12_mh_ec", e_enc,e_encr,e_comp,e_dec,e_tot, acc_sum_e_err, acc_sum_e_jhat, acc_e_jtrue_last, e_last);
#endif
#ifdef HAVE_SJ16
        // Aggregate SJ16 trials into one published row (median timing + mean
        // error). Labeled a LOWER BOUND: shares only, secure division excluded.
        if (sj16_active && !sj16_trials.empty()) {
            auto sr = FinalizeSJ16(sj16_trials, u, scenario, config.set_size);
            sr.estimator_model = EstimatorModel::NotApplicable;
            sr.sanitizer = NotApplicableSanitizerMetadata();
            csv.WriteRow(sr);

            std::cerr << "  U=" << u
                      << " sj16: total=" << sr.total_ms << "ms"
                      << " comm=" << (sr.comm_bytes / 1024) << "KB"
                      << " err=" << sr.jaccard_error
                      << " (shares only; secure division excluded)\n";
        }
#endif
    }   // closes for (uint32_t u : u_values)
}

// ============================================================================
// Scenario 4: Vary set size n (fixed universe)
// ============================================================================

static void BenchVarySetSize(const ComparisonConfig& cfg,
                             ComparisonCSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, cfg.base.security_level);
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    // Piccard engine (reuse across sizes — parameters don't change)
    PiccardParams pp;
    pp.k = config.k;
    pp.m = config.m;
    pp.security = config.security_level;
    ApplyBenchmarkProfile(config, pp);
    pp.Validate();

    Piccard piccard(pp);
    piccard.KeyGen();

    // SqrtPiccard engine (reuse across sizes)
    bool has_sqrt = IsSqrtValid(config.m);
    std::unique_ptr<SqrtPiccard> sqrt_eng;
    if (has_sqrt) {
        PiccardParams sp;
        sp.k = config.k;
        sp.m = config.m;
        sp.security = config.security_level;
        ApplyBenchmarkProfile(config, sp);
        sp.ValidateSqrt();
        sqrt_eng = std::make_unique<SqrtPiccard>(sp);
        sqrt_eng->KeyGen();
    }

    for (size_t sz : sizes) {
        // Scale universe to accommodate large set sizes
        uint32_t eff_u = std::max(u, static_cast<uint32_t>(2 * sz));
        std::string scenario = "vary_size_" + std::to_string(sz);

        // Baseline engine (recreated per size when universe changes)
        BaselineParams bp;
        bp.universe_size = eff_u;
        bp.security = config.security_level;
        bp.Validate();

        BaselineEngine baseline(bp);
        baseline.Initialize();

        auto [set_a, set_b] = MakeSetsWithOverlap(sz, 0.5, eff_u);
        double j_true = ExactJaccard(set_a, set_b);

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, eff_u, config.trials);
        csv.WriteRow(pr);

        std::cerr << "  size=" << sz
                  << " piccard: total=" << pr.total_ms << "ms"
                  << " comm=" << (pr.comm_bytes / 1024) << "KB"
                  << " err=" << pr.jaccard_error << "\n";

        if (has_sqrt) {
            auto sr = RunMultiTrialSqrtPiccard(*sqrt_eng, set_a, set_b, j_true,
                                               scenario, eff_u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  size=" << sz
                      << " sqrt: total=" << sr.total_ms << "ms"
                      << " comm=" << (sr.comm_bytes / 1024) << "KB"
                      << " err=" << sr.jaccard_error << "\n";
        }

        auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                        scenario, config.trials);
        csv.WriteRow(br);

        std::cerr << "  size=" << sz
                  << " baseline: total=" << br.total_ms << "ms"
                  << " comm=" << (br.comm_bytes / 1024) << "KB"
                  << " err=" << br.jaccard_error << "\n";

        // BCG12: exact mode (Fig. 2), fixed-set multi-trial, with cost-model caps
        // (single source of truth: EC ~0.037 ms/op, FF ~0.55 ms/op, exact = 4n ops).
#ifdef HAVE_PICCARD_BASELINES
        {
            using namespace piccard::baselines;
            // BCG12: capture named aliases, not the structured bindings themselves —
            // capturing structured bindings in a lambda is a C++20 extension.
            const std::vector<uint64_t>& bcg12_sa = set_a;
            const std::vector<uint64_t>& bcg12_sb = set_b;
            auto run_exact=[&](Bcg12Backend be,const char* m,size_t tr){
                Bcg12Params bp; bp.mode=Bcg12Mode::Exact; bp.backend=be;   // exact mode ignores CRS
                BCG12 eng(bp); eng.Setup();
                csv.WriteRow(RunBCG12MultiTrial(eng,bcg12_sa,bcg12_sb,j_true,scenario,eff_u,m,0,tr));
                std::cerr << "  size=" << sz << " " << m << ": ran trials=" << tr << "\n"; };
            // EC exact
            if (sz <= 10000) run_exact(Bcg12Backend::EC,"bcg12_exact_ec",config.trials);
            else if (sz <= 100000){ run_exact(Bcg12Backend::EC,"bcg12_exact_ec",std::min<size_t>(config.trials,1));
                std::cerr << "  CAP: bcg12_exact_ec size=" << sz << " ~"
                          << (4.0*sz*0.037/1000.0) << "s/query -> trials=1\n"; }
            else std::cerr << "  SKIP: bcg12_exact_ec size=" << sz << " exceeds budget\n";
            // FF exact (faithful cost, expensive)
            if (sz <= 1000) run_exact(Bcg12Backend::FF,"bcg12_exact_ff",config.trials);
            else std::cerr << "  SKIP: bcg12_exact_ff size=" << sz << " ~"
                           << (4.0*sz*0.55/1000.0) << "s/query > budget\n";
        }
#endif
    }
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cerr
        << "Usage: bench_comparison [options]\n"
        << "\n"
        << "Comparator suite: Piccard vs SqrtPiccard vs the FHE-IND indicator-vector\n"
        << "comparator (universe-sized BFV protocol; not a faithful [11]\n"
        << "reimplementation). Reports compute time, end-to-end time, and\n"
        << "communication cost.\n"
        << "\n"
        << "Timing scenarios (--mode=timing):\n"
        << "  1. Vary k       — Piccard ring_dim changes; comparator constant\n"
        << "  2. Vary m       — Piccard ring_dim changes; comparator constant\n"
        << "  3. Vary |U|     — Comparator ring_dim grows; Piccard constant\n"
        << "  4. Vary n       — Set size (affects encode/minhash phases)\n"
        << "\n"
        << "Options:\n"
        << "  --mode=MODE        'timing' or 'accuracy' (default: timing)\n"
        << "  --k=N              Piccard MinHash functions (default: 128)\n"
        << "  --m=N              Piccard one-hot bucket size (default: 64)\n"
        << "  --set_size=N       Size of each party's set (default: 1000)\n"
        << "  --trials=N         Number of trials (default: 10)\n"
        << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256' (default: STD128)\n"
        << "  --universe=N       Comparator universe size (default: 65536)\n"
        << "  --sj16             Also run the SJ16 AHE comparator in Vary |U| (opt-in; lower bound: shares only, secure division excluded)\n"
        << "  --sj16_key_bits=K  SJ16 Paillier key size 1024/2048/3072 (default: 3072)\n"
        << "  --sj16_max_universe=N  Skip SJ16 above this |U|; left for the Phase-3 fitted model (default: 65536)\n"
        << "  --sj16_precompute  Use the offline rho^N randomiser pool (D5 sensitivity row)\n"
        << "  --help, -h         Print this help message\n"
        << "\n"
        << "Examples:\n"
        << "  bench_comparison --security=TOY --trials=3\n"
        << "  bench_comparison --mode=accuracy --security=TOY --trials=5\n"
        << "  bench_comparison --security=STD128 --trials=5   # paper-grade numbers\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        }
    }

    auto config = ComparisonConfig::ParseArgs(argc, argv);
    RejectUnknownBenchmarkOptions(
        argc, argv,
        {"--universe=", "--sj16", "--sj16_key_bits=",
         "--sj16_max_universe=", "--sj16_precompute"});
    config.Print();

    ComparisonCSVWriter csv;
    csv.WriteHeader();

    if (config.base.profile.run_class != BenchmarkRunClass::Legacy) {
        const bool reviewer_primary =
            config.base.profile.id == "std128-t40-primary";
        const bool focused_toy =
            config.base.profile.id == "toy-smoke" &&
            config.base.evidence_point;
        if (!reviewer_primary && !focused_toy) {
            throw std::invalid_argument(
                "bench_comparison named evidence supports only "
                "std128-t40-primary reviewer comparison or a toy-smoke "
                "evidence point");
        }
        BenchReviewerComparison(config, csv);
        return 0;
    }

    if (config.base.mode == "timing") {
        std::cerr << "\n=== Vary k (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryK(config, csv);

        std::cerr << "\n=== Vary m (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryM(config, csv);

        std::cerr << "\n=== Vary universe size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryUniverse(config, csv);

        std::cerr << "\n=== Vary set size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVarySetSize(config, csv);
    }

    return 0;
}
