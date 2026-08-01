#include "baseline_profile.h"
#include "benchmark_profile.h"
#include "benchmark_provenance.h"
#include "comparison_workload.h"
#include "baselines/bcg12.h"
#include "baselines/pjs_baseline.h"
#include "baselines/sj16.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"
#include "util/params.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace {

using piccard::Piccard;
using piccard::PiccardParams;
using piccard::SecurityLevel;
using piccard::SqrtPiccard;
using piccard::benchmark::AggregateIdentity;
using piccard::benchmark::AssuranceScopeName;
using piccard::benchmark::BaselineCapability;
using piccard::benchmark::BaselineEvidenceKind;
using piccard::benchmark::BaselineMethod;
using piccard::benchmark::BaselineSecurityPolicy;
using piccard::benchmark::BenchmarkMeasurementKindName;
using piccard::benchmark::BenchmarkProfile;
using piccard::benchmark::BenchmarkProvenance;
using piccard::benchmark::BenchmarkRunClassName;
using piccard::benchmark::ComparisonScopeName;
using piccard::benchmark::ComparisonTrial;
using piccard::benchmark::ComparisonWorkload;
using piccard::benchmark::CostScopeName;
using piccard::benchmark::ExactRational;
using piccard::benchmark::ExecutionTrace;
using piccard::benchmark::OutputSemanticsName;
using piccard::benchmark::PrecomputationModeName;
using piccard::benchmark::PrimitiveName;
using piccard::benchmark::ProtocolModelName;
using piccard::benchmark::ResolveBaselineCapability;
using piccard::benchmark::ReviewMeasurementKind;
using piccard::benchmark::ReviewNumericCell;
using piccard::benchmark::ResolveReviewMethodRowPolicy;
using piccard::benchmark::SecurityBasisName;
using piccard::benchmark::TrialKind;
using piccard::benchmark::ValidateAggregateMembership;
using piccard::benchmark::WorkloadSpec;
using piccard::baselines::BCG12;
using piccard::baselines::Bcg12Backend;
using piccard::baselines::Bcg12Mode;
using piccard::baselines::Bcg12Params;
using piccard::baselines::QueryCost;
using piccard::baselines::SJ16;

using Clock = std::chrono::steady_clock;

struct Options {
    std::string suite;
    std::string profile;
    SecurityLevel security = SecurityLevel::STD128;
    bool saw_security = false;
    uint64_t k = 0;
    uint64_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    std::string target_jaccard_text;
    uint32_t trials = 0;
    uint32_t accuracy_trials = 0;
    uint64_t seed = 0;
    std::vector<std::string> methods;
    unsigned sj16_key_bits = 0;
    enum class SecurityPolicy { Unset, Strict, Diagnostic } policy =
        SecurityPolicy::Unset;
    std::filesystem::path manifest_out;
    std::filesystem::path execution_trace_out;
};

uint64_t ParseU64(const std::string& text, const std::string& flag) {
    if (text.empty() || text[0] == '-') {
        throw std::invalid_argument(flag + " requires a non-negative integer");
    }
    size_t consumed = 0;
    const unsigned long long value = std::stoull(text, &consumed);
    if (consumed != text.size()) throw std::invalid_argument("invalid " + flag);
    return static_cast<uint64_t>(value);
}

uint32_t ParseU32(const std::string& text, const std::string& flag) {
    const uint64_t value = ParseU64(text, flag);
    if (value > UINT32_MAX) throw std::invalid_argument(flag + " exceeds BE32");
    return static_cast<uint32_t>(value);
}

std::vector<std::string> SplitMethods(const std::string& text) {
    std::vector<std::string> methods;
    size_t begin = 0;
    while (true) {
        const size_t comma = text.find(',', begin);
        methods.push_back(text.substr(begin, comma - begin));
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    return methods;
}

Options ParseOptions(int argc, char** argv) {
    Options options;
    std::map<std::string, bool> seen;
    auto set_once = [&](const std::string& key) {
        if (seen[key]) throw std::invalid_argument("duplicate --" + key);
        seen[key] = true;
    };
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        const size_t equals = arg.find('=');
        const std::string key = equals == std::string::npos
            ? arg : arg.substr(0, equals);
        const std::string value = equals == std::string::npos
            ? "" : arg.substr(equals + 1);
        if (key == "--suite") { set_once("suite"); options.suite = value; }
        else if (key == "--profile") { set_once("profile"); options.profile = value; }
        else if (key == "--security") {
            set_once("security");
            options.saw_security = true;
            if (value == "TOY") options.security = SecurityLevel::TOY;
            else if (value == "STD128") options.security = SecurityLevel::STD128;
            else if (value == "STD192") options.security = SecurityLevel::STD192;
            else if (value == "STD256") options.security = SecurityLevel::STD256;
            else throw std::invalid_argument("invalid --security");
        } else if (key == "--k") { set_once("k"); options.k = ParseU64(value, "--k"); }
        else if (key == "--m") { set_once("m"); options.m = ParseU64(value, "--m"); }
        else if (key == "--set-size") { set_once("set-size"); options.set_size = ParseU64(value, "--set-size"); }
        else if (key == "--universe") { set_once("universe"); options.universe = ParseU64(value, "--universe"); }
        else if (key == "--target-jaccard") { set_once("target-jaccard"); options.target_jaccard_text = value; }
        else if (key == "--trials") { set_once("trials"); options.trials = ParseU32(value, "--trials"); }
        else if (key == "--accuracy-trials") { set_once("accuracy-trials"); options.accuracy_trials = ParseU32(value, "--accuracy-trials"); }
        else if (key == "--seed") { set_once("seed"); options.seed = ParseU64(value, "--seed"); }
        else if (key == "--methods") { set_once("methods"); options.methods = SplitMethods(value); }
        else if (key == "--sj16-key-bits") { set_once("sj16-key-bits"); options.sj16_key_bits = ParseU32(value, "--sj16-key-bits"); }
        else if (key == "--manifest-out") { set_once("manifest-out"); options.manifest_out = value; }
        else if (key == "--execution-trace-out") { set_once("execution-trace-out"); options.execution_trace_out = value; }
        else if (arg == "--strict-security") {
            set_once("security-policy"); options.policy = Options::SecurityPolicy::Strict;
        } else if (arg == "--diagnostic-security" ||
                   arg == "--allow-unmatched-security") {
            set_once("security-policy"); options.policy = Options::SecurityPolicy::Diagnostic;
        } else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: bench_review_comparison --suite=SUITE --profile=ID "
                   "--security=LEVEL (optional with --profile) --k=N --m=N "
                   "--set-size=N --universe=N "
                   "--target-jaccard=DECIMAL --trials=N --accuracy-trials=N "
                   "--seed=N --methods=CSV --sj16-key-bits=N "
                   "--manifest-out=PATH.bin --execution-trace-out=PATH.bin "
                   "(--strict-security|--diagnostic-security|"
                   "--allow-unmatched-security)\n"
                   "Profile supplies security when --security is omitted.\n";
            std::exit(0);
        } else if (key == "--overlap") {
            throw std::invalid_argument(
                "reviewer evidence rejects --overlap; use --target-jaccard");
        } else {
            throw std::invalid_argument("unknown option: " + arg);
        }
    }
    const char* required[] = {"suite", "profile", "k", "m",
                              "set-size", "universe", "target-jaccard",
                              "trials", "accuracy-trials", "seed", "methods",
                              "sj16-key-bits", "manifest-out",
                              "execution-trace-out", "security-policy"};
    for (const char* key : required) {
        if (!seen[key]) throw std::invalid_argument("missing --" + std::string(key));
    }
    if (options.k == 0 || options.m == 0 || options.universe == 0 ||
        options.methods.empty()) {
        throw std::invalid_argument("k, m, universe, and methods must be nonzero");
    }
    if (options.universe > UINT32_MAX || options.k > UINT32_MAX ||
        options.m > UINT32_MAX || options.set_size > SIZE_MAX) {
        throw std::invalid_argument("CLI value exceeds implementation range");
    }
    if (options.sj16_key_bits != 1024 && options.sj16_key_bits != 2048 &&
        options.sj16_key_bits != 3072) {
        throw std::invalid_argument("--sj16-key-bits must be 1024, 2048, or 3072");
    }
    if (options.manifest_out.extension() != ".bin" ||
        options.execution_trace_out.extension() != ".bin") {
        throw std::invalid_argument("manifest and execution trace require .bin paths");
    }
    if (std::filesystem::exists(options.manifest_out) ||
        std::filesystem::exists(options.execution_trace_out)) {
        throw std::invalid_argument("review artifacts must use new output paths");
    }
    if (options.manifest_out == options.execution_trace_out) {
        throw std::invalid_argument(
            "--manifest-out and --execution-trace-out must differ");
    }
    return options;
}

uint32_t SecurityBits(SecurityLevel security) {
    switch (security) {
        case SecurityLevel::TOY: return 0;
        case SecurityLevel::STD128: return 128;
        case SecurityLevel::STD192: return 192;
        case SecurityLevel::STD256: return 256;
    }
    throw std::logic_error("unknown security level");
}

BaselineMethod MethodEnum(const std::string& method, unsigned sj16_key_bits) {
    if (method == "piccard") return BaselineMethod::Piccard;
    if (method == "piccard_sqrt") return BaselineMethod::PiccardSqrt;
    if (method == "bcg12_mh_ff") return BaselineMethod::Bcg12MinHashFf;
    if (method == "bcg12_mh_ec") return BaselineMethod::Bcg12MinHashEc;
    if (method == "bcg12_exact_ff") return BaselineMethod::Bcg12ExactFf;
    if (method == "bcg12_exact_ec") return BaselineMethod::Bcg12ExactEc;
    if (method == "sj16" || method == "sj16_precomputed") {
        if (sj16_key_bits == 1024) return BaselineMethod::Sj16Paillier1024;
        if (sj16_key_bits == 2048) return BaselineMethod::Sj16Paillier2048;
        return BaselineMethod::Sj16Paillier3072;
    }
    throw std::invalid_argument("unknown method: " + method);
}

double RationalDouble(const ExactRational& value) {
    return static_cast<double>(value.numerator) /
           static_cast<double>(value.denominator);
}

struct Observation {
    QueryCost cost;
    double expected = 0.0;
};

class Adapter {
public:
    Adapter(std::string name, BaselineCapability capability)
        : name_(std::move(name)), capability_(std::move(capability)) {}
    virtual ~Adapter() = default;
    const std::string& Name() const { return name_; }
    const BaselineCapability& Capability() const { return capability_; }
    virtual Observation Run(const ComparisonTrial& trial) = 0;
    virtual BenchmarkProvenance Provenance() const = 0;
    virtual const PiccardParams* Params() const { return nullptr; }

private:
    std::string name_;
    BaselineCapability capability_;
};

class PiccardAdapter final : public Adapter {
public:
    PiccardAdapter(const WorkloadSpec& spec, SecurityLevel security,
                   const BenchmarkProfile& profile, BaselineCapability capability)
        : Adapter("piccard", std::move(capability)) {
        PiccardParams params;
        params.k = static_cast<uint32_t>(spec.k);
        params.m = static_cast<uint32_t>(spec.m);
        params.security = security;
        params.hash_seed = spec.root_seed;
        params.transcript_stat_bits = profile.transcript_stat_bits;
        params.max_queries = profile.max_queries;
        params.Validate();
        engine_ = std::make_unique<Piccard>(params);
        engine_->KeyGen();
    }

    Observation Run(const ComparisonTrial& trial) override {
        engine_->SetHashSeed(trial.hash_seed);
        const auto start = Clock::now();
        const auto result = engine_->Run(trial.set_a, trial.set_b);
        const auto stop = Clock::now();
        Observation out;
        out.cost.total_ms =
            std::chrono::duration<double, std::milli>(stop - start).count();
        out.cost.jaccard_estimate = result.jaccard_estimate;
        out.expected = RationalDouble(trial.exact_jaccard);
        return out;
    }

    BenchmarkProvenance Provenance() const override {
        return piccard::benchmark::MakePiccardBenchmarkProvenance(
            engine_->GetBFVContext());
    }
    const PiccardParams* Params() const override { return &engine_->GetParams(); }

private:
    std::unique_ptr<Piccard> engine_;
};

class SqrtAdapter final : public Adapter {
public:
    SqrtAdapter(const WorkloadSpec& spec, SecurityLevel security,
                const BenchmarkProfile& profile, BaselineCapability capability)
        : Adapter("piccard_sqrt", std::move(capability)) {
        PiccardParams params;
        params.k = static_cast<uint32_t>(spec.k);
        params.m = static_cast<uint32_t>(spec.m);
        params.security = security;
        params.hash_seed = spec.root_seed;
        params.transcript_stat_bits = profile.transcript_stat_bits;
        params.max_queries = profile.max_queries;
        params.ValidateSqrt();
        engine_ = std::make_unique<SqrtPiccard>(params);
        engine_->KeyGen();
    }

    Observation Run(const ComparisonTrial& trial) override {
        engine_->SetHashSeed(trial.hash_seed);
        const auto start = Clock::now();
        const auto result = engine_->Run(trial.set_a, trial.set_b);
        const auto stop = Clock::now();
        Observation out;
        out.cost.total_ms =
            std::chrono::duration<double, std::milli>(stop - start).count();
        out.cost.jaccard_estimate = result.jaccard_estimate;
        out.expected = RationalDouble(trial.exact_jaccard);
        return out;
    }

    BenchmarkProvenance Provenance() const override {
        return piccard::benchmark::MakePiccardBenchmarkProvenance(
            engine_->GetBFVContext());
    }
    const PiccardParams* Params() const override { return &engine_->GetParams(); }

private:
    std::unique_ptr<SqrtPiccard> engine_;
};

class Bcg12Adapter final : public Adapter {
public:
    Bcg12Adapter(std::string method, const WorkloadSpec& spec,
                 BaselineCapability capability)
        : Adapter(method, std::move(capability)) {
        Bcg12Params params;
        params.mode = method.find("_mh_") != std::string::npos
            ? Bcg12Mode::MinHash : Bcg12Mode::Exact;
        params.backend = method.size() >= 3 &&
                         method.substr(method.size() - 3) == "_ff"
            ? Bcg12Backend::FF : Bcg12Backend::EC;
        params.k = static_cast<uint32_t>(spec.k);
        params.minhash_seed = spec.root_seed;
        engine_ = std::make_unique<BCG12>(params);
        engine_->Setup();
    }

    Observation Run(const ComparisonTrial& trial) override {
        engine_->SetHashSeed(trial.hash_seed);
        Observation out;
        out.cost = engine_->RunQuery(trial.set_a, trial.set_b);
        out.expected = RationalDouble(trial.exact_jaccard);
        return out;
    }

    BenchmarkProvenance Provenance() const override {
        return piccard::benchmark::MakeAheBenchmarkProvenance();
    }

private:
    std::unique_ptr<BCG12> engine_;
};

class Sj16Adapter final : public Adapter {
public:
    Sj16Adapter(std::string method, unsigned key_bits, uint32_t universe,
                BaselineCapability capability)
        : Adapter(method, std::move(capability)),
          precomputed_(method == "sj16_precomputed"),
          universe_(universe),
          engine_(std::make_unique<SJ16>(key_bits, precomputed_)) {
        engine_->Setup();
        engine_->SetUniverse(universe);
    }

    Observation Run(const ComparisonTrial& trial) override {
        if (precomputed_) {
            engine_->PrepareRandomizerPool(static_cast<size_t>(universe_) + 1);
        }
        Observation out;
        out.cost = engine_->RunQuery(trial.set_a, trial.set_b);
        out.expected = RationalDouble(trial.exact_jaccard);
        return out;
    }

    BenchmarkProvenance Provenance() const override {
        return piccard::benchmark::MakeAheBenchmarkProvenance();
    }

private:
    bool precomputed_;
    uint32_t universe_;
    std::unique_ptr<SJ16> engine_;
};

struct Stats {
    double mean = 0.0;
    double median = 0.0;
    double sd = -1.0;
};

Stats Summarize(std::vector<double> values) {
    if (values.empty()) throw std::logic_error("cannot summarize no samples");
    Stats out;
    out.mean = std::accumulate(values.begin(), values.end(), 0.0) /
               static_cast<double>(values.size());
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    out.median = values.size() % 2 == 0
        ? (values[mid - 1] + values[mid]) / 2.0 : values[mid];
    if (values.size() > 1) {
        double squares = 0.0;
        for (double value : values) squares += (value - out.mean) * (value - out.mean);
        out.sd = std::sqrt(squares / static_cast<double>(values.size() - 1));
    }
    return out;
}

struct Aggregate {
    Adapter* adapter = nullptr;
    TrialKind kind = TrialKind::Timing;
    std::vector<Observation> observations;
};

std::string OptionalU32(const std::optional<uint32_t>& value) {
    return value ? std::to_string(*value) : "";
}
std::string OptionalU64(const std::optional<uint64_t>& value) {
    return value ? std::to_string(*value) : "";
}
std::string OptionalDouble(const std::optional<double>& value) {
    if (!value) return "";
    std::ostringstream out;
    out << std::fixed << std::setprecision(6) << *value;
    return out.str();
}

std::string CsvHeader() {
    return "suite,scenario,method,profile_id,run_class,target_security_bits,"
           "cryptographic_profile,nominal_security_bits,security_match,"
           "comparison_eligible,comparison_scope,primitive,protocol_model,"
           "output_semantics,assurance_scope,security_basis,cost_scope,"
           "precomputation_mode,secure_division_included,measurement_kind,"
           "evidence_arm,workload_id,workload_manifest_sha256,"
           "execution_trace_sha256,root_seed,omp_threads,omp_dynamic,k,m,"
           "set_size,universe_size,target_semantics,target_jaccard_numerator,"
           "target_jaccard_denominator,target_jaccard,realized_intersection,"
           "realized_union,realized_jaccard,timing_trials,accuracy_trials,"
           "trials,hash_randomness,hash_seed,estimator_model,sanitizer_model,"
           "sanitizer_assurance,transcript_stat_bits,max_queries,query_stat_bits,"
           "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
           "flood_noise_bits,scaling_mod_size,actual_ring_dim,log_q_bits,"
           "plaintext_modulus,num_limbs,openfhe_version,total_ms,total_ms_sd,"
           "total_ms_median,jaccard_computed,jaccard_expected,jaccard_error,"
           "measurement_status\n";
}

std::string SerializeAggregate(const Options& options,
                               const BenchmarkProfile& profile,
                               const ComparisonWorkload& workload,
                               const std::string& trace_sha,
                               const Aggregate& aggregate) {
    const BaselineSecurityPolicy security_policy =
        options.policy == Options::SecurityPolicy::Strict
            ? BaselineSecurityPolicy::RequireMatch
            : BaselineSecurityPolicy::AllowDiagnostic;
    const BaselineCapability cap = ResolveBaselineCapability(
        MethodEnum(aggregate.adapter->Name(), options.sj16_key_bits),
        profile.target_security_bits,
        aggregate.kind == TrialKind::Timing
            ? BaselineEvidenceKind::Timing : BaselineEvidenceKind::Accuracy,
        security_policy,
        aggregate.adapter->Name() == "sj16_precomputed");
    const BenchmarkProvenance provenance = aggregate.adapter->Provenance();
    const PiccardParams* params = aggregate.adapter->Params();
    std::vector<double> times;
    times.reserve(aggregate.observations.size());
    double estimate = 0.0;
    double expected = 0.0;
    double error = 0.0;
    for (const auto& observation : aggregate.observations) {
        times.push_back(observation.cost.total_ms);
        estimate += observation.cost.jaccard_estimate;
        expected += observation.expected;
        error += std::abs(observation.cost.jaccard_estimate - observation.expected);
    }
    const double n = static_cast<double>(aggregate.observations.size());
    estimate /= n;
    expected /= n;
    error /= n;
    const bool exact = aggregate.adapter->Name().find("bcg12_exact_") == 0 ||
                       aggregate.adapter->Name() == "sj16" ||
                       aggregate.adapter->Name() == "sj16_precomputed";
    if (exact) {
        if (error > 1e-12) {
            throw std::runtime_error("exact adapter produced nonzero estimator error");
        }
        error = 0.0;
    }
    const Stats stats = Summarize(times);
    const auto& realized = workload.Records().front();
    const bool suite_diagnostic = options.suite != "primary-review";
    const bool eligible = !suite_diagnostic && cap.comparison_eligible;
    const std::string arm = aggregate.kind == TrialKind::Timing
        ? "timing" : "accuracy";
    const auto row_policy = ResolveReviewMethodRowPolicy(
        aggregate.adapter->Name(), aggregate.kind, options.k, options.m,
        workload.Records()[1].hash_seed);

    std::ostringstream out;
    out << options.suite << ",review-" << options.universe << ","
        << aggregate.adapter->Name() << "," << profile.id << ","
        << BenchmarkRunClassName(profile.run_class) << ","
        << profile.target_security_bits << "," << cap.cryptographic_profile << ","
        << OptionalU32(cap.nominal_security_bits) << ","
        << (cap.security_match ? "true" : "false") << ","
        << (eligible ? "true" : "false") << ","
        << ComparisonScopeName(cap.comparison_scope) << ","
        << PrimitiveName(cap.primitive) << "," << ProtocolModelName(cap.protocol_model)
        << "," << OutputSemanticsName(cap.output_semantics) << ","
        << AssuranceScopeName(cap.assurance_scope) << ","
        << SecurityBasisName(cap.security_basis) << ","
        << CostScopeName(cap.cost_scope) << ","
        << PrecomputationModeName(cap.precomputation_mode) << ","
        << (cap.secure_division_included ? "true" : "false") << ","
        << ReviewMeasurementKind(aggregate.adapter->Name(), aggregate.kind) << ","
        << arm << "," << workload.WorkloadId() << ","
        << workload.ManifestSha256Hex() << "," << trace_sha << ","
        << options.seed << ","
#ifdef _OPENMP
        << omp_get_max_threads() << "," << (omp_get_dynamic() ? "true" : "false")
#else
        << 1 << ",false"
#endif
        << "," << OptionalU64(row_policy.k) << ","
        << OptionalU64(row_policy.m) << "," << options.set_size
        << "," << options.universe << ",jaccard,"
        << workload.Spec().target_jaccard.numerator << ","
        << workload.Spec().target_jaccard.denominator << ","
        << std::fixed << std::setprecision(12)
        << RationalDouble(workload.Spec().target_jaccard) << ","
        << realized.exact_intersection << "," << realized.exact_union << ","
        << RationalDouble(realized.exact_jaccard) << ","
        << options.trials << "," << options.accuracy_trials << ","
        << aggregate.observations.size() << "," << row_policy.hash_randomness << ","
        << OptionalU64(row_policy.hash_seed) << ","
        << (exact ? "not-applicable" : "sha256-random-ranking-poc-v1") << ","
        << (params ? "phase-smudging-enc0-poc-v1" : "not-applicable") << ","
        << (params ? "empirical-phase-statistical+ciphertext-computational"
                   : "not-applicable") << ","
        << (params ? std::to_string(params->transcript_stat_bits) : "") << ","
        << (params ? std::to_string(params->max_queries) : "") << ","
        << (params ? std::to_string(params->QueryStatBits()) : "") << ","
        << (params ? std::to_string(params->CoefficientStatBits()) : "") << ","
        << (params ? std::to_string(params->flood_margin_bits) : "") << ","
        << (params ? std::to_string(params->eval_noise_bits) : "") << ","
        << (params ? std::to_string(params->FloodNoiseBits()) : "") << ","
        << (params ? std::to_string(params->scaling_mod_size) : "") << ","
        << OptionalU32(provenance.actual_ring_dim) << ","
        << OptionalDouble(provenance.log_q_bits) << ","
        << OptionalU64(provenance.plaintext_modulus) << ","
        << OptionalU32(provenance.num_limbs) << "," << provenance.openfhe_version
        << "," << std::fixed << std::setprecision(6) << stats.mean << ","
        << ReviewNumericCell(stats.sd) << "," << stats.median << "," << estimate << ","
        << expected << "," << error << ",measured\n";
    return out.str();
}

std::vector<std::unique_ptr<Adapter>> SetupAdapters(
    const Options& options,
    const BenchmarkProfile& profile,
    const ComparisonWorkload& workload) {
    const BaselineSecurityPolicy policy =
        options.policy == Options::SecurityPolicy::Strict
            ? BaselineSecurityPolicy::RequireMatch
            : BaselineSecurityPolicy::AllowDiagnostic;
    std::vector<std::unique_ptr<Adapter>> adapters;
    for (const auto& method : workload.Spec().methods) {
        const bool precomputed = method == "sj16_precomputed";
        BaselineCapability capability = ResolveBaselineCapability(
            MethodEnum(method, options.sj16_key_bits),
            profile.target_security_bits, BaselineEvidenceKind::Timing,
            policy, precomputed);
        if (method == "piccard") {
            adapters.push_back(std::make_unique<PiccardAdapter>(
                workload.Spec(), options.security, profile, std::move(capability)));
        } else if (method == "piccard_sqrt") {
            adapters.push_back(std::make_unique<SqrtAdapter>(
                workload.Spec(), options.security, profile, std::move(capability)));
        } else if (method.rfind("bcg12_", 0) == 0) {
            adapters.push_back(std::make_unique<Bcg12Adapter>(
                method, workload.Spec(), std::move(capability)));
        } else {
            adapters.push_back(std::make_unique<Sj16Adapter>(
                method, options.sj16_key_bits,
                static_cast<uint32_t>(options.universe), std::move(capability)));
        }
    }
    return adapters;
}

int Run(int argc, char** argv) {
    Options options = ParseOptions(argc, argv);
    const BenchmarkProfile& profile =
        piccard::benchmark::ResolveBenchmarkProfile(options.profile);
    if (!options.saw_security) {
        options.security = profile.security;
    } else if (profile.security != options.security) {
        throw std::invalid_argument("--security conflicts with --profile");
    }
    if ((options.suite == "primary-review" &&
         options.policy != Options::SecurityPolicy::Strict) ||
        (options.suite != "primary-review" &&
         options.policy != Options::SecurityPolicy::Diagnostic)) {
        throw std::invalid_argument("security policy does not match frozen suite");
    }
    if ((options.suite == "toy-smoke" && options.sj16_key_bits != 1024) ||
        (options.suite != "toy-smoke" && options.sj16_key_bits != 3072)) {
        throw std::invalid_argument("SJ16 key size does not match frozen suite");
    }
#ifdef _OPENMP
    if (omp_get_dynamic()) {
        throw std::invalid_argument("reviewer comparison requires OMP_DYNAMIC=FALSE");
    }
#endif

    WorkloadSpec spec;
    spec.suite = options.suite;
    spec.profile_id = options.profile;
    spec.root_seed = options.seed;
    spec.k = options.k;
    spec.m = options.m;
    spec.set_size = options.set_size;
    spec.universe = options.universe;
    spec.target_jaccard =
        piccard::benchmark::ParseExactDecimal(options.target_jaccard_text);
    spec.methods = options.methods;
    spec.timing_trials = options.trials;
    spec.accuracy_trials = options.accuracy_trials;

    // Contract boundary: every set/seed is generated and persisted before any
    // adapter construction, group setup, Paillier keygen, or FHE keygen.
    const ComparisonWorkload workload = ComparisonWorkload::Generate(spec);
    workload.WriteNew(options.manifest_out);

    std::vector<std::unique_ptr<Adapter>> adapters =
        SetupAdapters(options, profile, workload);
    std::map<std::string, Adapter*> by_name;
    for (const auto& adapter : adapters) by_name.emplace(adapter->Name(), adapter.get());

    std::map<std::pair<std::string, TrialKind>, Aggregate> aggregates;
    for (const auto& adapter : adapters) {
        aggregates[{adapter->Name(), TrialKind::Timing}] =
            Aggregate{adapter.get(), TrialKind::Timing, {}};
        if (options.accuracy_trials != 0) {
            aggregates[{adapter->Name(), TrialKind::Accuracy}] =
                Aggregate{adapter.get(), TrialKind::Accuracy, {}};
        }
    }

    ExecutionTrace trace(workload);
    try {
        for (const auto& trial : workload.Records()) {
            trace.BeginRecord(trial);
            for (const auto& method : workload.ExecutionOrder(trial)) {
                trace.AppendDispatch(method);  // must precede adapter invocation
                Observation observation = by_name.at(method)->Run(trial);
                if (trial.kind != TrialKind::Warmup) {
                    aggregates.at({method, trial.kind}).observations.push_back(
                        std::move(observation));
                }
            }
            trace.CompleteRecord();
        }
    } catch (...) {
        trace.FailRecord();
        const std::string partial_sha = trace.WriteNew(options.execution_trace_out);
        std::cerr << "comparison group invalidated; partial execution trace sha256="
                  << partial_sha << "\n";
        throw;
    }

    const std::string trace_sha = trace.WriteNew(options.execution_trace_out);
    std::vector<AggregateIdentity> identities;
    std::vector<std::string> rows;
    for (const auto& method : workload.Spec().methods) {
        for (TrialKind kind : {TrialKind::Timing, TrialKind::Accuracy}) {
            if (kind == TrialKind::Accuracy && options.accuracy_trials == 0) continue;
            const Aggregate& aggregate = aggregates.at({method, kind});
            if (aggregate.observations.empty()) {
                throw std::runtime_error("missing measured trials for aggregate");
            }
            AggregateIdentity identity;
            identity.method = method;
            identity.measurement_kind = ReviewMeasurementKind(method, kind);
            identity.evidence_arm = kind == TrialKind::Timing ? "timing" : "accuracy";
            identity.workload_id = workload.WorkloadId();
            identity.workload_manifest_sha256 = workload.ManifestSha256Hex();
            identity.k = options.k;
            identity.m = options.m;
            identity.set_size = options.set_size;
            identity.universe = options.universe;
            identity.timing_trials = options.trials;
            identity.accuracy_trials = options.accuracy_trials;
            identity.aggregate_trials = static_cast<uint32_t>(aggregate.observations.size());
            identity.precomputation_mode = PrecomputationModeName(
                aggregate.adapter->Capability().precomputation_mode);
            identity.exact_estimator = method.find("bcg12_exact_") == 0 ||
                                       method == "sj16" ||
                                       method == "sj16_precomputed";
            double error = 0.0;
            for (const auto& observation : aggregate.observations) {
                error += std::abs(observation.cost.jaccard_estimate -
                                  observation.expected);
            }
            identity.estimator_error = error / aggregate.observations.size();
            if (identity.exact_estimator && identity.estimator_error < 1e-12) {
                identity.estimator_error = 0.0;
            }
            identities.push_back(identity);
            rows.push_back(SerializeAggregate(options, profile, workload,
                                              trace_sha, aggregate));
        }
    }
    ValidateAggregateMembership(workload, identities);

    // Aggregate CSV is emitted only after the complete trace is durably bound.
    std::cout << CsvHeader();
    for (const auto& row : rows) std::cout << row;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (piccard::benchmark::PrintBuildProvenanceIfRequested(argc, argv)) {
            return 0;
        }
        return Run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "bench_review_comparison: " << error.what() << "\n";
        return 2;
    }
}
