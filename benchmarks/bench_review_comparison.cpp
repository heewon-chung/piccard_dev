#include "baseline_engine.h"
#include "baseline_profile.h"
#include "benchmark_profile.h"
#include "benchmark_provenance.h"
#include "comparison_workload.h"
#include "encoding_work_unit.h"
#include "raw_timing_schema.h"
#include "review_revision_adapter.h"
#include "baselines/bcg12.h"
#include "baselines/pjs_baseline.h"
#include "baselines/sj16.h"
#include "core/minhash.h"
#include "core/onehot_encoder.h"
#include "core/sqrt_encoder.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"
#include "util/params.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <limits>
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
using piccard::MinHasher;
using piccard::OneHotEncoder;
using piccard::SecurityLevel;
using piccard::SqrtEncoder;
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
using piccard::benchmark::RevisionSuiteForFamily;
using piccard::benchmark::ExpectedTimingTrials;
using piccard::benchmark::ExpectedWarmupPolicy;
using piccard::benchmark::RawTimingArtifact;
using piccard::benchmark::RawTimingSample;
using piccard::benchmark::SampleKind;
using piccard::benchmark::WarmupPolicy;
using piccard::benchmark::WriteRawTimingArtifactsV1;
using piccard::benchmark::kPaperTimingProfileVersion;
using piccard::benchmark::kReadinessTimingProfileVersion;
using piccard::benchmark::ComputeTimingAggregateV1;
using piccard::benchmark::SecurityBasisName;
using piccard::benchmark::TrialKind;
using piccard::benchmark::ValidateAggregateMembership;
using piccard::benchmark::WorkloadSpec;
using piccard::benchmark::EncodingWorkUnit;
using piccard::benchmark::EncodeEndpointWorkUnit;
using piccard::benchmark::ResolveEncodingWorkUnit;
using piccard::benchmark::LoadAndValidateRevisionMatrix;
using piccard::benchmark::ParseReviewRevisionArgs;
using piccard::benchmark::PlanReviewRevisionExecution;
using piccard::benchmark::ReviewRevisionExecutionPlan;
using piccard::benchmark::ReviewRevisionRequest;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::MakeConcreteReviewArgs;
using piccard::benchmark::SerializeReviewEncodingTerminalRowsV1;
using piccard::baseline::BaselineEngine;
using piccard::baseline::BaselineParams;
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
    enum class SecurityPolicy { Unset, Strict, Diagnostic, AllowUnmatched } policy =
        SecurityPolicy::Unset;
    std::filesystem::path manifest_out;
    std::filesystem::path execution_trace_out;
    // Optional v1 raw timing sidecars.  Empty preserves the frozen Work 5
    // stdout, manifest, and execution-trace behavior byte-for-byte.
    std::filesystem::path raw_timing_out;
    // Non-empty only on the strict Phase-9 successor path. Legacy invocations
    // keep this field empty and retain their historical artifact identity.
    std::string revision_cell;
};

struct ReviewSuccessorOptions {
    bool enabled = false;
    std::vector<std::string> planner_argv;
    RevisionRunMode mode = RevisionRunMode::Paper;
    ReviewRevisionExecutionPlan execution;
    // Concrete values are captured before planner placeholders are restored.
    // They are used only at the producer boundary; the pure planner argv
    // remains canonical and byte-identical to the matrix contract.
    std::string concrete_seed;
    std::filesystem::path concrete_output;
};

struct ConcreteReviewRuntimeArgs {
    std::string seed;
    std::filesystem::path output;
};

ConcreteReviewRuntimeArgs ParseConcreteReviewRuntimeArgs(
    const std::vector<std::string>& argv) {
    ConcreteReviewRuntimeArgs runtime;
    bool seed_seen = false;
    bool output_seen = false;
    for (const std::string& arg : argv) {
        if (arg.rfind("--seed=", 0) == 0) {
            if (seed_seen) {
                throw std::invalid_argument("duplicate concrete review --seed");
            }
            seed_seen = true;
            const std::string value = arg.substr(7);
            if (value.empty() || value == "{seed}" || value.front() == '+' ||
                value.front() == '-') {
                throw std::invalid_argument(
                    "concrete review --seed must be a positive integer");
            }
            uint64_t parsed = 0;
            const auto result = std::from_chars(
                value.data(), value.data() + value.size(), parsed);
            if (result.ec != std::errc{} ||
                result.ptr != value.data() + value.size() || parsed == 0 ||
                std::to_string(parsed) != value) {
                throw std::invalid_argument(
                    "concrete review --seed must be a canonical unsigned integer");
            }
            runtime.seed = value;
        } else if (arg.rfind("--output=", 0) == 0) {
            if (output_seen) {
                throw std::invalid_argument("duplicate concrete review --output");
            }
            output_seen = true;
            const std::string value = arg.substr(9);
            if (value.empty() || value.find('{') != std::string::npos ||
                value.find('}') != std::string::npos) {
                throw std::invalid_argument(
                    "concrete review --output must be a concrete CSV path");
            }
            const std::filesystem::path output(value);
            const std::string filename = output.filename().string();
            if (filename != "encoding.csv" && filename != "comparison.csv") {
                throw std::invalid_argument(
                    "concrete review --output must end in encoding.csv or comparison.csv");
            }
            runtime.output = output;
        }
    }
    if (!seed_seen) {
        throw std::invalid_argument("missing concrete review --seed");
    }
    if (!output_seen) {
        throw std::invalid_argument("missing concrete review --output");
    }
    return runtime;
}

std::vector<std::string> CanonicalizeReviewPlannerArgv(
    const std::vector<std::string>& argv) {
    std::vector<std::string> canonical;
    canonical.reserve(argv.size());
    for (const std::string& arg : argv) {
        if (arg.rfind("--seed=", 0) == 0 && arg != "--seed={seed}") {
            canonical.push_back("--seed={seed}");
        } else if (arg.rfind("--output=", 0) == 0) {
            const std::string value = arg.substr(9);
            const std::string filename =
                std::filesystem::path(value).filename().string();
            if (filename == "encoding.csv") {
                canonical.push_back("--output={output}/encoding.csv");
            } else if (filename == "comparison.csv") {
                canonical.push_back("--output={output}/comparison.csv");
            } else {
                throw std::invalid_argument(
                    "concrete review --output must end in encoding.csv or comparison.csv");
            }
        } else if (arg.rfind("--raw-timing-out=", 0) == 0 ||
                   arg.rfind("--raw_timing_dir=", 0) == 0) {
            canonical.push_back("--raw_timing_dir={output}/raw");
        } else {
            canonical.push_back(arg);
        }
    }
    return canonical;
}

ReviewSuccessorOptions ParseReviewSuccessorOptions(int argc, char** argv) {
    ReviewSuccessorOptions successor;
    for (int index = 1; index < argc; ++index) {
        const std::string arg(argv[index]);
        if (arg.rfind("--revision-cell=", 0) == 0) successor.enabled = true;
        successor.planner_argv.push_back(arg);
    }
    if (!successor.enabled) {
        successor.planner_argv.clear();
        return successor;
    }
#ifdef PICCARD_REVISION_MATRIX_PATH
    const ConcreteReviewRuntimeArgs runtime =
        ParseConcreteReviewRuntimeArgs(successor.planner_argv);
    successor.concrete_seed = runtime.seed;
    successor.concrete_output = runtime.output;
    successor.planner_argv = CanonicalizeReviewPlannerArgv(
        successor.planner_argv);
    const ReviewRevisionRequest request = ParseReviewRevisionArgs(
        successor.planner_argv);
    successor.mode = request.profile == "readiness-toy-v1"
        ? RevisionRunMode::Toy : RevisionRunMode::Paper;
    const RevisionMatrix matrix = LoadAndValidateRevisionMatrix(
        PICCARD_REVISION_MATRIX_PATH);
    successor.execution = PlanReviewRevisionExecution(
        matrix, successor.planner_argv, successor.mode);
#else
    throw std::runtime_error(
        "review successor requires PICCARD_REVISION_MATRIX_PATH");
#endif
    return successor;
}

std::vector<char*> MutableArgv(std::vector<std::string>& arguments) {
    std::vector<char*> argv;
    argv.reserve(arguments.size() + 1);
    static char program_name[] = "bench_review_comparison";
    argv.push_back(program_name);
    for (std::string& argument : arguments) {
        argv.push_back(argument.data());
    }
    return argv;
}

std::vector<std::string> MaterializeConcreteReviewArgs(
    const ReviewSuccessorOptions& successor) {
    std::vector<std::string> args =
        MakeConcreteReviewArgs(successor.execution);
    const std::filesystem::path output_parent =
        successor.concrete_output.parent_path().empty()
            ? std::filesystem::path(".")
            : successor.concrete_output.parent_path();
    for (std::string& arg : args) {
        if (arg == "--seed={seed}") {
            arg = "--seed=" + successor.concrete_seed;
        } else if (arg == "--manifest-out={output}/workload.bin") {
            arg = "--manifest-out=" +
                  (output_parent / "workload.bin").string();
        } else if (arg == "--execution-trace-out={output}/execution-trace.bin") {
            arg = "--execution-trace-out=" +
                  (output_parent / "execution-trace.bin").string();
        } else if (arg == "--raw-timing-out={output}/raw") {
            arg = "--raw-timing-out=" + (output_parent / "raw").string();
        }
    }
    return args;
}

void ValidateReviewSuccessorConfig(
    const Options& options,
    const ReviewRevisionExecutionPlan& execution) {
    const auto& cell = execution.selection.cell;
    if (options.revision_cell != cell.cell_id ||
        options.suite != execution.concrete_suite ||
        options.profile != execution.concrete_profile ||
        options.security != (execution.concrete_security == "TOY"
                                 ? SecurityLevel::TOY
                                 : execution.concrete_security == "STD192"
                                       ? SecurityLevel::STD192
                                       : SecurityLevel::STD128) ||
        options.k != std::stoull(cell.axes.at("k")) ||
        options.m != std::stoull(cell.axes.at("m")) ||
        options.set_size != execution.set_size ||
        options.universe != execution.universe ||
        options.trials != execution.timing_trials ||
        options.accuracy_trials != execution.accuracy_trials ||
        options.methods != execution.concrete_methods) {
        throw std::invalid_argument(
            "review successor flags do not match the selected matrix cell");
    }
    if (cell.invocation_status != "RUN" || execution.selected_point_count != 1 ||
        !execution.producer_must_spawn) {
        throw std::invalid_argument(
            "review successor can execute only one RUN matrix cell");
    }
}

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
        else if (key == "--raw-timing-out" || key == "--raw_timing_dir") {
            set_once("raw-timing-out");
            options.raw_timing_out = value;
        }
        else if (arg == "--strict-security") {
            set_once("security-policy"); options.policy = Options::SecurityPolicy::Strict;
        } else if (arg == "--diagnostic-security") {
            set_once("security-policy"); options.policy = Options::SecurityPolicy::Diagnostic;
        } else if (arg == "--allow-unmatched-security") {
            set_once("security-policy"); options.policy = Options::SecurityPolicy::AllowUnmatched;
        } else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: bench_review_comparison --suite=SUITE --profile=ID "
                   "--security=LEVEL (optional with --profile) --k=N --m=N "
                   "--set-size=N --universe=N "
                   "--target-jaccard=DECIMAL --trials=N --accuracy-trials=N "
                   "--seed=N --methods=CSV --sj16-key-bits=N "
                   "--manifest-out=PATH.bin --execution-trace-out=PATH.bin "
                   "[--raw_timing_dir=DIR|--raw-timing-out=DIR] "
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
    if (!options.raw_timing_out.empty() &&
        (!std::filesystem::exists(options.raw_timing_out) ||
         !std::filesystem::is_directory(options.raw_timing_out))) {
        throw std::invalid_argument("--raw-timing-out requires an existing directory");
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
    if (method == "piccard_encode") return BaselineMethod::PiccardEncode;
    if (method == "piccard_sqrt_encode") {
        return BaselineMethod::PiccardSqrtEncode;
    }
    if (method == "fhe_ind") return BaselineMethod::FheInd;
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
    // FHE-IND exposes the decrypted cardinality in addition to the common
    // Jaccard observation. Other adapters leave this field unset.
    std::optional<int64_t> intersection_count;
    // Versioned local-encoding timing is a pair measurement.  The legacy
    // serializer continues to use cost.total_ms, while successor rows expose
    // these three fields separately.
    double encode_a_ms = 0.0;
    double encode_b_ms = 0.0;
    double encode_pair_ms = 0.0;
};

struct EncodingAudit {
    uint32_t warmup_calls = 0;
    uint32_t timed_calls = 0;
    uint32_t correctness_calls = 0;
    uint32_t warmup_pair_calls = 0;
    uint32_t timed_pair_calls = 0;
    uint32_t correctness_pair_calls = 0;
    uint32_t feature_size = 0;
    uint32_t feature_size_b = 0;
    std::string correctness_feature_sha256;
    std::string correctness_feature_sha256_b;
    bool correctness_passed = false;
};

bool IsEncodingMethod(const std::string& method) {
    return method == "piccard_encode" || method == "piccard_sqrt_encode";
}

uint32_t CheckedFeatureRingDim(uint64_t feature_dim) {
    if (feature_dim == 0 || feature_dim > UINT32_MAX) {
        throw std::invalid_argument("encoding feature dimension exceeds uint32");
    }
    const uint32_t ring_dim = piccard::NextPowerOf2(
        static_cast<uint32_t>(feature_dim));
    if (ring_dim < feature_dim) {
        throw std::invalid_argument("encoding feature dimension overflows ring dimension");
    }
    return ring_dim;
}

uint32_t ExactSqrtBase(uint32_t m) {
    uint32_t base = 1;
    while (base <= m / base && static_cast<uint64_t>(base) * base < m) ++base;
    if (base == 0 || static_cast<uint64_t>(base) * base != m) {
        throw std::invalid_argument("sqrt encoding requires an exact-square m");
    }
    return base;
}

std::string FeatureSha256(const std::vector<int64_t>& feature) {
    std::vector<uint8_t> bytes;
    bytes.reserve(feature.size());
    for (int64_t value : feature) {
        if (value < 0 || value > UINT8_MAX) {
            throw std::logic_error("encoder emitted an invalid feature coefficient");
        }
        bytes.push_back(static_cast<uint8_t>(value));
    }
    return piccard::benchmark::Sha256Hex(bytes);
}

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
    virtual const EncodingAudit* Encoding() const { return nullptr; }

private:
    std::string name_;
    BaselineCapability capability_;
};

class EncodingAdapter final : public Adapter {
public:
    EncodingAdapter(std::string method, const WorkloadSpec& spec,
                    EncodingWorkUnit work_unit,
                    BaselineCapability capability)
        : Adapter(std::move(method), std::move(capability)),
          work_unit_(work_unit),
          sqrt_(Name() == "piccard_sqrt_encode") {
        params_.k = static_cast<uint32_t>(spec.k);
        params_.m = static_cast<uint32_t>(spec.m);
        if (sqrt_) {
            params_.sqrt_base = ExactSqrtBase(params_.m);
            const uint64_t feature_dim = static_cast<uint64_t>(params_.k) * 2 *
                params_.sqrt_base;
            params_.ring_dim = CheckedFeatureRingDim(feature_dim);
            params_.sqrt_feature_dim = static_cast<uint32_t>(feature_dim);
            sqrt_encoder_ = std::make_unique<SqrtEncoder>(params_);
        } else {
            const uint64_t feature_dim = static_cast<uint64_t>(params_.k) * params_.m;
            params_.ring_dim = CheckedFeatureRingDim(feature_dim);
            params_.feature_dim = static_cast<uint32_t>(feature_dim);
            onehot_encoder_ = std::make_unique<OneHotEncoder>(params_);
        }
    }

    Observation Run(const ComparisonTrial& trial) override {
        // Signature construction is intentionally complete before any warmup
        // or timing boundary. MinHash is never part of an encoder measurement.
        const MinHasher hasher(
            params_.k, std::numeric_limits<uint64_t>::max(), trial.hash_seed)
            ;
        const std::vector<uint64_t> signature_a =
            hasher.ComputeSignature(trial.set_a);
        std::optional<std::vector<uint64_t>> signature_b;
        if (work_unit_ == EncodingWorkUnit::VersionedPair) {
            signature_b = hasher.ComputeSignature(trial.set_b);
        }
        const std::vector<uint64_t>& endpoint_b =
            signature_b ? *signature_b : signature_a;
        Observation out;
        if (trial.kind == TrialKind::Warmup) {
            if (work_unit_ == EncodingWorkUnit::LegacyAOnly) {
                static_cast<void>(EncodeEndpointWorkUnit(
                    EncodingWorkUnit::LegacyAOnly, signature_a, endpoint_b,
                    [&](const std::vector<uint64_t>& signature) {
                        return Encode(signature);
                    }));
                ++audit_.warmup_calls;
                return out;
            }
            const auto warmup_start = Clock::now();
            static_cast<void>(EncodeEndpointWorkUnit(
                EncodingWorkUnit::VersionedPair, signature_a, endpoint_b,
                [&](const std::vector<uint64_t>& signature) {
                    return Encode(signature);
                }));
            const auto warmup_stop = Clock::now();
            // The aggregate still discards this record. Keeping a real
            // boundary here lets the optional raw sidecar label the discarded
            // first-touch pair instead of publishing a synthetic zero.
            out.encode_pair_ms = std::chrono::duration<double, std::milli>(
                warmup_stop - warmup_start).count();
            out.cost.total_ms = out.encode_pair_ms;
            ++audit_.warmup_calls;
            ++audit_.warmup_pair_calls;
            return out;
        }
        if (trial.kind == TrialKind::Timing) {
            if (work_unit_ == EncodingWorkUnit::LegacyAOnly) {
                const auto start = Clock::now();
                const auto result = EncodeEndpointWorkUnit(
                    EncodingWorkUnit::LegacyAOnly, signature_a, endpoint_b,
                    [&](const std::vector<uint64_t>& signature) {
                        return Encode(signature);
                    });
                const auto stop = Clock::now();
                const double elapsed = std::chrono::duration<double, std::milli>(
                    stop - start).count();
                out.encode_a_ms = elapsed;
                // Keep the raw sidecar's encoding phase tied to the legacy
                // scalar work unit without changing its old CSV schema.
                out.encode_pair_ms = elapsed;
                out.cost.total_ms = elapsed;
                audit_.feature_size = static_cast<uint32_t>(result.a.size());
                ++audit_.timed_calls;
                return out;
            }
            const auto result = EncodeEndpointWorkUnit(
                EncodingWorkUnit::VersionedPair, signature_a, endpoint_b,
                [&](const std::vector<uint64_t>& signature) {
                    const auto begin = Clock::now();
                    std::vector<int64_t> feature = Encode(signature);
                    const auto end = Clock::now();
                    struct TimedFeature {
                        std::vector<int64_t> feature;
                        double elapsed_ms;
                    };
                    return TimedFeature{
                        std::move(feature),
                        std::chrono::duration<double, std::milli>(
                            end - begin).count()};
                });
            const std::vector<int64_t>& feature_a = result.a.feature;
            if (!result.b.has_value()) {
                throw std::logic_error("versioned encoding omitted endpoint B");
            }
            const std::vector<int64_t>& feature_b = result.b->feature;
            const double a_ms = result.a.elapsed_ms;
            const double b_ms = result.b->elapsed_ms;
            out.encode_a_ms = a_ms;
            out.encode_b_ms = b_ms;
            out.encode_pair_ms = a_ms + b_ms;
            out.cost.total_ms = out.encode_pair_ms;
            audit_.feature_size = static_cast<uint32_t>(feature_a.size());
            audit_.feature_size_b = static_cast<uint32_t>(feature_b.size());
            ++audit_.timed_calls;
            ++audit_.timed_pair_calls;
            return out;
        }
        if (trial.kind != TrialKind::Accuracy &&
            trial.kind != TrialKind::Correctness) {
            throw std::logic_error("unknown encoding trial kind");
        }
        const auto result = EncodeEndpointWorkUnit(
            work_unit_, signature_a, endpoint_b,
            [&](const std::vector<uint64_t>& signature) {
                return Encode(signature);
            });
        const std::vector<int64_t>& feature_a = result.a;
        ValidateFeature(signature_a, feature_a);
        audit_.feature_size = static_cast<uint32_t>(feature_a.size());
        audit_.correctness_feature_sha256 = FeatureSha256(feature_a);
        if (work_unit_ == EncodingWorkUnit::VersionedPair) {
            if (!result.b.has_value()) {
                throw std::logic_error("versioned encoding omitted endpoint B");
            }
            ValidateFeature(endpoint_b, *result.b);
            audit_.feature_size_b = static_cast<uint32_t>(result.b->size());
            audit_.correctness_feature_sha256_b = FeatureSha256(*result.b);
            ++audit_.correctness_pair_calls;
        }
        audit_.correctness_passed = true;
        ++audit_.correctness_calls;
        return out;
    }

    BenchmarkProvenance Provenance() const override { return {}; }
    const EncodingAudit* Encoding() const override { return &audit_; }

private:
    std::vector<int64_t> Encode(const std::vector<uint64_t>& signature) const {
        return sqrt_ ? sqrt_encoder_->Encode(signature) : onehot_encoder_->Encode(signature);
    }

    void ValidateFeature(const std::vector<uint64_t>& signature,
                         const std::vector<int64_t>& feature) const {
        if (feature.size() != params_.ring_dim || signature.size() != params_.k) {
            throw std::runtime_error("encoding correctness shape mismatch");
        }
        std::vector<int64_t> expected(params_.ring_dim, 0);
        if (sqrt_) {
            const uint32_t block = 2 * params_.sqrt_base;
            for (uint32_t i = 0; i < params_.k; ++i) {
                const uint32_t value = static_cast<uint32_t>(signature[i] % params_.m);
                expected[i * block + value % params_.sqrt_base] = 1;
                expected[i * block + params_.sqrt_base +
                         value / params_.sqrt_base] = 1;
            }
        } else {
            for (uint32_t i = 0; i < params_.k; ++i) {
                expected[i * params_.m + signature[i] % params_.m] = 1;
            }
        }
        if (feature != expected) {
            throw std::runtime_error("encoding correctness content mismatch");
        }
    }

    EncodingWorkUnit work_unit_;
    bool sqrt_;
    PiccardParams params_;
    std::unique_ptr<OneHotEncoder> onehot_encoder_;
    std::unique_ptr<SqrtEncoder> sqrt_encoder_;
    EncodingAudit audit_;
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

class FheIndAdapter final : public Adapter {
public:
    FheIndAdapter(const WorkloadSpec& spec, SecurityLevel security,
                  BaselineCapability capability)
        : Adapter("fhe_ind", std::move(capability)) {
        BaselineParams params;
        params.universe_size = static_cast<uint32_t>(spec.universe);
        params.security = security;
        params.Validate();
        engine_ = std::make_unique<BaselineEngine>(params);
        // Context and keys are one-time setup. They are intentionally not
        // regenerated for a trial and are excluded from query timing.
        engine_->Initialize();
    }

    Observation Run(const ComparisonTrial& trial) override {
        // The manifest is the sole source of sets. In particular, the FHE-IND
        // adapter does not consume hash_seed or derive a method-specific seed.
        const auto result = engine_->RunQueryPhased(trial.set_a, trial.set_b);
        if (result.intersection !=
                static_cast<int64_t>(trial.exact_intersection) ||
            result.union_size != static_cast<int64_t>(trial.exact_union)) {
            throw std::runtime_error(
                "FHE-IND decrypted intersection is not workload-bound");
        }

        Observation out;
        out.cost.phase_encode_ms = result.phase_encode_ms;
        out.cost.phase_encrypt_ms = result.phase_encrypt_ms;
        out.cost.phase_compute_ms = result.phase_evaluate_ms;
        out.cost.phase_decrypt_ms = result.phase_decrypt_ms;
        out.cost.total_ms = result.online_ms;
        out.cost.ct_size_bytes = result.party_x_ciphertext_bytes;
        out.cost.comm_bytes = result.communication.total_bytes;
        out.cost.jaccard_estimate = result.jaccard;
        out.expected = RationalDouble(trial.exact_jaccard);
        out.intersection_count = result.intersection;
        return out;
    }

    BenchmarkProvenance Provenance() const override {
        return piccard::benchmark::MakeFheIndBenchmarkProvenance(
            engine_->GetBFVContext());
    }

    // FHE-IND has no Piccard k/m or sanitizer parameter map.
    const PiccardParams* Params() const override { return nullptr; }

private:
    std::unique_ptr<BaselineEngine> engine_;
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

std::string RawTimingProfileForReview(const Options& options) {
    if (std::string(kReadinessTimingProfileVersion) != "readiness-toy-v1" ||
        std::string(kPaperTimingProfileVersion) != "paper-v1") {
        throw std::logic_error("raw timing profile constants drifted");
    }
    if (options.trials == 1) return kReadinessTimingProfileVersion;
    if (options.trials == 30) return kPaperTimingProfileVersion;
    throw std::invalid_argument(
        "review raw timing requires exactly 1 toy or 30 paper measured trials");
}

double RawMillisecondsForReview(const std::string& method,
                                const Observation& observation) {
    // Encoding rows have a pair-specific timing boundary; all protocol
    // adapters expose the complete query boundary through total_ms.
    return IsEncodingMethod(method) ? observation.encode_pair_ms
                                    : observation.cost.total_ms;
}

RawTimingArtifact MakeReviewRawTimingArtifact(
    const Options& options,
    const std::string& profile_id,
    const std::string& method,
    std::vector<RawTimingSample> samples) {
    RawTimingArtifact artifact;
    artifact.producer_id = "bench_review_comparison";
    artifact.profile_id = profile_id;
    artifact.cell_id = options.revision_cell.empty()
        ? "review-" + std::to_string(options.universe) + "-" + method
        : options.revision_cell + "::" + method;
    artifact.warmup_policy = WarmupPolicy::DiscardOne;
    if (artifact.warmup_policy != ExpectedWarmupPolicy(artifact.producer_id)) {
        throw std::logic_error("review raw timing warmup policy drift");
    }
    artifact.expected_measured = ExpectedTimingTrials(profile_id);
    artifact.samples = std::move(samples);
    artifact.aggregates.push_back(ComputeTimingAggregateV1(
        artifact.producer_id, artifact.profile_id, artifact.cell_id, "total",
        artifact.samples));
    return artifact;
}

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

std::string Format17(const double value) {
    if (!std::isfinite(value) || value < 0.0) {
        throw std::invalid_argument("encoding timing must be finite and non-negative");
    }
    std::ostringstream out;
    out << std::setprecision(17) << std::defaultfloat
        << (value == 0.0 ? 0.0 : value);
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
           "intersection_count,phase_encode_ms,phase_encrypt_ms,"
           "phase_compute_ms,phase_decrypt_ms,ct_size_bytes,comm_bytes,"
           "measurement_status\n";
}

std::string EncodingCsvHeader() {
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
           "trials,hash_randomness,hash_seed,encoder_input_construction,"
           "encoder_warmup_calls,encoder_timed_calls,"
           "encoder_correctness_calls,encoder_correctness_status,"
           "encoded_feature_size,correctness_feature_sha256,total_ms,"
           "total_ms_sd,total_ms_median,measurement_status\n";
}

std::string VersionedEncodingCsvHeader() {
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
           "correctness_trials,trials,hash_randomness,hash_seed,"
           "encoder_input_construction,encoder_warmup_pairs,"
           "timed_encoder_pairs,correctness_pair_calls,"
           "signature_derivation_timed,encode_a_ms,encode_b_ms,"
           "encode_pair_ms,encoded_slots_a,encoded_slots_b,"
           "correctness_feature_sha256_a,correctness_feature_sha256_b,"
           "correctness_status,measurement_status\n";
}

std::string SerializeVersionedEncodingAggregate(
    const Options& options,
    const BenchmarkProfile& profile,
    const ComparisonWorkload& workload,
    const std::string& trace_sha,
    const Aggregate& aggregate) {
    const EncodingAudit* audit = aggregate.adapter->Encoding();
    const uint32_t expected_correctness = workload.Spec().correctness_trials;
    if (audit == nullptr || audit->warmup_pair_calls != profile.warmup_calls ||
        audit->timed_pair_calls != profile.timing_trials ||
        audit->correctness_pair_calls != expected_correctness ||
        !audit->correctness_passed || audit->feature_size == 0 ||
        audit->feature_size_b == 0 ||
        audit->correctness_feature_sha256.empty() ||
        audit->correctness_feature_sha256_b.empty()) {
        throw std::logic_error(
            "versioned encoding adapter did not complete pair audit schedule");
    }
    if (aggregate.kind != TrialKind::Timing ||
        aggregate.observations.size() != profile.timing_trials) {
        throw std::logic_error(
            "versioned encoding aggregate has an unexpected arm or count");
    }
    const BaselineCapability cap = ResolveBaselineCapability(
        MethodEnum(aggregate.adapter->Name(), options.sj16_key_bits),
        profile.target_security_bits, BaselineEvidenceKind::Timing,
        BaselineSecurityPolicy::AllowDiagnostic);
    const auto row_policy = ResolveReviewMethodRowPolicy(
        aggregate.adapter->Name(), TrialKind::Timing, options.k, options.m,
        workload.Records()[1].hash_seed);
    std::vector<double> a_values;
    std::vector<double> b_values;
    std::vector<double> pair_values;
    a_values.reserve(aggregate.observations.size());
    b_values.reserve(aggregate.observations.size());
    pair_values.reserve(aggregate.observations.size());
    for (const auto& observation : aggregate.observations) {
        a_values.push_back(observation.encode_a_ms);
        b_values.push_back(observation.encode_b_ms);
        pair_values.push_back(observation.encode_pair_ms);
    }
    const Stats a_stats = Summarize(a_values);
    const Stats b_stats = Summarize(b_values);
    const Stats pair_stats = Summarize(pair_values);
    const auto& realized = workload.Records().front();
    std::ostringstream out;
    out << options.suite << ",review-" << options.universe << ","
        << aggregate.adapter->Name() << "," << profile.id << ","
        << BenchmarkRunClassName(profile.run_class) << ","
        << profile.target_security_bits << "," << cap.cryptographic_profile << ","
        << OptionalU32(cap.nominal_security_bits) << ","
        << (cap.security_match ? "true" : "false") << ",false,"
        << ComparisonScopeName(cap.comparison_scope) << ","
        << PrimitiveName(cap.primitive) << ","
        << ProtocolModelName(cap.protocol_model) << ","
        << OutputSemanticsName(cap.output_semantics) << ","
        << AssuranceScopeName(cap.assurance_scope) << ","
        << SecurityBasisName(cap.security_basis) << ","
        << CostScopeName(cap.cost_scope) << ","
        << PrecomputationModeName(cap.precomputation_mode) << ",false,"
        << ReviewMeasurementKind(aggregate.adapter->Name(), TrialKind::Timing)
        << ",timing," << workload.WorkloadId() << ","
        << workload.ManifestSha256Hex() << "," << trace_sha << ","
        << options.seed << ","
#ifdef _OPENMP
        << omp_get_max_threads() << "," << (omp_get_dynamic() ? "true" : "false")
#else
        << 1 << ",false"
#endif
        << "," << OptionalU64(row_policy.k) << ","
        << OptionalU64(row_policy.m) << "," << options.set_size << ","
        << options.universe << ",jaccard,"
        << realized.exact_jaccard.numerator << ","
        << realized.exact_jaccard.denominator << ","
        << Format17(RationalDouble(workload.Spec().target_jaccard)) << ","
        << realized.exact_intersection << "," << realized.exact_union << ","
        << Format17(RationalDouble(realized.exact_jaccard)) << ","
        << workload.Spec().timing_trials << ","
        << workload.Spec().accuracy_trials << ","
        << workload.Spec().correctness_trials << ","
        << aggregate.observations.size()
        << ",fixed," << OptionalU64(row_policy.hash_seed) << ","
        << "canonical-minhash-signatures-untimed," << audit->warmup_pair_calls
        << "," << audit->timed_pair_calls << ","
        << audit->correctness_pair_calls << ",false,"
        << Format17(a_stats.mean) << "," << Format17(b_stats.mean) << ","
        // Compute the pair field from the serialized endpoint values so the
        // wire-level identity is an exact sum, not a separately rounded mean.
        << Format17(a_stats.mean + b_stats.mean) << "," << audit->feature_size
        << "," << audit->feature_size_b << ","
        << audit->correctness_feature_sha256 << ","
        << audit->correctness_feature_sha256_b << ",PASS,measured\n";
    (void)pair_stats;
    return out.str();
}

std::string SerializeEncodingAggregate(const Options& options,
                                       const BenchmarkProfile& profile,
                                       const ComparisonWorkload& workload,
                                       const std::string& trace_sha,
                                       const Aggregate& aggregate) {
    if (workload.Spec().correctness_trials != 0) {
        return SerializeVersionedEncodingAggregate(
            options, profile, workload, trace_sha, aggregate);
    }
    const EncodingAudit* audit = aggregate.adapter->Encoding();
    if (audit == nullptr || audit->warmup_calls != 1 || audit->timed_calls != 1 ||
        audit->correctness_calls != 1 || !audit->correctness_passed ||
        audit->feature_size == 0 || audit->correctness_feature_sha256.empty()) {
        throw std::logic_error("encoding adapter did not complete its exact audit schedule");
    }
    const BaselineCapability cap = ResolveBaselineCapability(
        MethodEnum(aggregate.adapter->Name(), options.sj16_key_bits),
        profile.target_security_bits,
        aggregate.kind == TrialKind::Timing
            ? BaselineEvidenceKind::Timing : BaselineEvidenceKind::Accuracy,
        BaselineSecurityPolicy::AllowDiagnostic);
    const auto row_policy = ResolveReviewMethodRowPolicy(
        aggregate.adapter->Name(), aggregate.kind, options.k, options.m,
        workload.Records()[1].hash_seed);
    std::vector<double> times;
    times.reserve(aggregate.observations.size());
    for (const auto& observation : aggregate.observations) {
        times.push_back(observation.cost.total_ms);
    }
    const Stats stats = Summarize(times);
    const auto& realized = workload.Records().front();
    const std::string arm = aggregate.kind == TrialKind::Timing
        ? "timing" : "accuracy";

    std::ostringstream out;
    out << options.suite << ",review-" << options.universe << ","
        << aggregate.adapter->Name() << "," << profile.id << ","
        << BenchmarkRunClassName(profile.run_class) << ","
        << profile.target_security_bits << "," << cap.cryptographic_profile << ","
        << OptionalU32(cap.nominal_security_bits) << ","
        << (cap.security_match ? "true" : "false") << ",false,"
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
        << OptionalU64(row_policy.m) << "," << options.set_size << ","
        << options.universe << ",jaccard,"
        << workload.Spec().target_jaccard.numerator << ","
        << workload.Spec().target_jaccard.denominator << ","
        << std::fixed << std::setprecision(12)
        << RationalDouble(workload.Spec().target_jaccard) << ","
        << realized.exact_intersection << "," << realized.exact_union << ","
        << RationalDouble(realized.exact_jaccard) << ","
        << options.trials << "," << options.accuracy_trials << ","
        << aggregate.observations.size() << "," << row_policy.hash_randomness << ","
        << OptionalU64(row_policy.hash_seed) << ","
        << "canonical-minhash-signature-untimed," << audit->warmup_calls << ","
        << audit->timed_calls << "," << audit->correctness_calls << ",PASS,"
        << audit->feature_size << "," << audit->correctness_feature_sha256 << ","
        << std::fixed << std::setprecision(6) << stats.mean << ","
        << ReviewNumericCell(stats.sd) << "," << stats.median << ",measured\n";
    return out.str();
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
    const bool fhe_ind = aggregate.adapter->Name() == "fhe_ind";
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
    Stats encode_stats;
    Stats encrypt_stats;
    Stats compute_stats;
    Stats decrypt_stats;
    int64_t observed_intersection = 0;
    size_t observed_ct_size = 0;
    size_t observed_comm = 0;
    if (fhe_ind) {
        std::vector<double> encode;
        std::vector<double> encrypt;
        std::vector<double> compute;
        std::vector<double> decrypt;
        encode.reserve(aggregate.observations.size());
        encrypt.reserve(aggregate.observations.size());
        compute.reserve(aggregate.observations.size());
        decrypt.reserve(aggregate.observations.size());
        if (aggregate.observations.empty() ||
            !aggregate.observations.front().intersection_count.has_value()) {
            throw std::logic_error(
                "FHE-IND observation is missing intersection count");
        }
        observed_intersection = *aggregate.observations.front().intersection_count;
        observed_ct_size = aggregate.observations.front().cost.ct_size_bytes;
        observed_comm = aggregate.observations.front().cost.comm_bytes;
        for (const auto& observation : aggregate.observations) {
            if (!observation.intersection_count.has_value()) {
                throw std::logic_error(
                    "FHE-IND observation is missing intersection count");
            }
            if (*observation.intersection_count != observed_intersection ||
                observation.cost.ct_size_bytes != observed_ct_size ||
                observation.cost.comm_bytes != observed_comm) {
                throw std::logic_error(
                    "FHE-IND aggregate metadata is not stable across trials");
            }
            encode.push_back(observation.cost.phase_encode_ms);
            encrypt.push_back(observation.cost.phase_encrypt_ms);
            compute.push_back(observation.cost.phase_compute_ms);
            decrypt.push_back(observation.cost.phase_decrypt_ms);
        }
        encode_stats = Summarize(std::move(encode));
        encrypt_stats = Summarize(std::move(encrypt));
        compute_stats = Summarize(std::move(compute));
        decrypt_stats = Summarize(std::move(decrypt));
    }
    const auto& realized = workload.Records().front();
    bool eligible = profile.comparison_eligible && cap.comparison_eligible;
    // The revision matrix intentionally keeps BCG12 exact-cardinality as a
    // diagnostic context row, even though the legacy matched-security
    // capability map marks the generic baseline table-eligible.  Scope this
    // reconciliation to the versioned revision suite; legacy Work 5 and
    // primary-review serialization retains its historical semantics.
    if (!options.revision_cell.empty() &&
        options.suite == RevisionSuiteForFamily("bcg12_exact")) {
        eligible = false;
    }
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
        << ((exact || fhe_ind) ? "not-applicable"
                               : "sha256-random-ranking-poc-v1") << ","
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
        << expected << "," << error;
    if (fhe_ind) {
        out << "," << observed_intersection
            << "," << encode_stats.mean
            << "," << encrypt_stats.mean
            << "," << compute_stats.mean
            << "," << decrypt_stats.mean
            << "," << observed_ct_size
            << "," << observed_comm;
    } else {
        // These detailed primitive fields are inapplicable to the legacy
        // adapters in this compact reviewer schema.
        out << ",,,,,,,";
    }
    out << ",measured\n";
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
        if (IsEncodingMethod(method)) {
            const EncodingWorkUnit work_unit = ResolveEncodingWorkUnit(
                profile.id, workload.Spec().suite,
                workload.Spec().correctness_trials);
            adapters.push_back(std::make_unique<EncodingAdapter>(
                method, workload.Spec(), work_unit, std::move(capability)));
        } else if (method == "piccard") {
            adapters.push_back(std::make_unique<PiccardAdapter>(
                workload.Spec(), options.security, profile, std::move(capability)));
        } else if (method == "piccard_sqrt") {
            adapters.push_back(std::make_unique<SqrtAdapter>(
                workload.Spec(), options.security, profile, std::move(capability)));
        } else if (method == "fhe_ind") {
            adapters.push_back(std::make_unique<FheIndAdapter>(
                workload.Spec(), options.security, std::move(capability)));
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
    const ReviewSuccessorOptions successor =
        ParseReviewSuccessorOptions(argc, argv);
    Options options;
    if (successor.enabled) {
        std::vector<std::string> concrete_args =
            MaterializeConcreteReviewArgs(successor);
        for (const std::string& argument : concrete_args) {
            if (argument.rfind("--raw-timing-out=", 0) != 0) continue;
            const std::filesystem::path raw_path = argument.substr(17);
            std::error_code error;
            std::filesystem::create_directories(raw_path, error);
            if (error) {
                throw std::runtime_error(
                    "cannot create review raw timing directory: " +
                    error.message());
            }
        }
        std::vector<char*> mutable_argv = MutableArgv(concrete_args);
        options = ParseOptions(static_cast<int>(mutable_argv.size()),
                               mutable_argv.data());
        options.revision_cell = successor.execution.selection.cell.cell_id;
        ValidateReviewSuccessorConfig(options, successor.execution);
    } else {
        options = ParseOptions(argc, argv);
    }
    const BenchmarkProfile& profile =
        piccard::benchmark::ResolveBenchmarkProfile(options.profile);
    if (!options.saw_security) {
        options.security = profile.security;
    } else if (profile.security != options.security) {
        throw std::invalid_argument("--security conflicts with --profile");
    }
    const bool diagnostic_policy =
        options.policy == Options::SecurityPolicy::Diagnostic ||
        options.policy == Options::SecurityPolicy::AllowUnmatched;
    if ((options.suite == "primary-review" &&
         options.policy != Options::SecurityPolicy::Strict) ||
        (options.suite != "primary-review" && !diagnostic_policy)) {
        throw std::invalid_argument("security policy does not match frozen suite");
    }
    if (options.suite == "work5-std192-sj16" &&
        options.policy != Options::SecurityPolicy::AllowUnmatched) {
        throw std::invalid_argument(
            "work5-std192-sj16 requires literal --allow-unmatched-security");
    }
    const bool readiness_toy_suite = options.suite == "toy-smoke" ||
                                     options.suite == "readiness-toy-v1";
    const unsigned expected_sj16_bits = readiness_toy_suite ? 1024 : 3072;
    if (options.sj16_key_bits != expected_sj16_bits) {
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
    if (options.suite == "paper-std192-encoding-v1" ||
        (options.suite == "readiness-toy-v1" &&
         std::all_of(spec.methods.begin(), spec.methods.end(),
                     [](const std::string& method) {
                         return IsEncodingMethod(method);
                     })) ||
        (successor.enabled &&
         successor.execution.selection.cell.family ==
             "piccard_std192_encoding")) {
        spec.correctness_trials = 1;
    }

    // Contract boundary: every set/seed is generated and persisted before any
    // adapter construction, group setup, Paillier keygen, or FHE keygen.
    const ComparisonWorkload workload = ComparisonWorkload::Generate(spec);
    workload.WriteNew(options.manifest_out);

    const bool has_encoding_method = std::any_of(
        workload.Spec().methods.begin(), workload.Spec().methods.end(),
        [](const std::string& method) { return IsEncodingMethod(method); });
    const bool encoding_only = has_encoding_method && std::all_of(
        workload.Spec().methods.begin(), workload.Spec().methods.end(),
        [](const std::string& method) { return IsEncodingMethod(method); });
    if (has_encoding_method && !encoding_only) {
        throw std::invalid_argument(
            "encoding-only methods cannot share a reviewer producer with FHE methods");
    }

    const bool write_raw_timing = !options.raw_timing_out.empty();
    const std::string raw_timing_profile = write_raw_timing
        ? RawTimingProfileForReview(options) : "";
    // Keep raw calls in a separate sidecar collection.  In particular, the
    // binary ExecutionTrace below remains the Work 5 dispatch trace and is
    // never folded into a timing artifact.
    std::map<std::string, std::vector<RawTimingSample>> raw_samples;

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
                if (write_raw_timing &&
                    (trial.kind == TrialKind::Warmup ||
                     trial.kind == TrialKind::Timing)) {
                    RawTimingSample sample;
                    sample.producer_id = "bench_review_comparison";
                    sample.profile_id = raw_timing_profile;
                    sample.cell_id = options.revision_cell.empty()
                        ? "review-" + std::to_string(options.universe) +
                              "-" + method
                        : options.revision_cell + "::" + method;
                    sample.phase = "total";
                    sample.sample_kind = trial.kind == TrialKind::Warmup
                        ? SampleKind::DiscardedWarmup : SampleKind::Measured;
                    sample.trial_index = trial.kind == TrialKind::Warmup
                        ? 0 : static_cast<uint64_t>(trial.index);
                    sample.seed = trial.trial_seed;
                    sample.raw_ms = RawMillisecondsForReview(method, observation);
                    raw_samples[method].push_back(std::move(sample));
                }
                if (trial.kind == TrialKind::Timing ||
                    trial.kind == TrialKind::Accuracy) {
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
    if (write_raw_timing) {
        std::vector<RawTimingArtifact> artifacts;
        artifacts.reserve(workload.Spec().methods.size());
        for (const auto& method : workload.Spec().methods) {
            artifacts.push_back(MakeReviewRawTimingArtifact(
                options, raw_timing_profile, method,
                std::move(raw_samples.at(method))));
        }
        WriteRawTimingArtifactsV1(options.raw_timing_out.string(), artifacts);
    }
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
            rows.push_back(encoding_only
                ? SerializeEncodingAggregate(options, profile, workload,
                                           trace_sha, aggregate)
                : SerializeAggregate(options, profile, workload,
                                     trace_sha, aggregate));
        }
    }
    ValidateAggregateMembership(workload, identities);

    // The frozen stdout encoding CSV remains unchanged.  For revision
    // encoding cells, publish the versioned terminal rows on stderr so the
    // runner can bind the applicable one-hot measurement and the structural
    // sqrt NOT_APPLICABLE row without mistaking it for a NO_SPAWN cell.
    if (successor.enabled &&
        successor.execution.selection.cell.family ==
            "piccard_std192_encoding") {
        for (const std::string& terminal_row :
             SerializeReviewEncodingTerminalRowsV1(successor.execution)) {
            std::cerr << terminal_row << "\n";
        }
    }

    // Aggregate CSV is emitted only after the complete trace is durably bound.
    const bool versioned_encoding =
        encoding_only && workload.Spec().correctness_trials != 0;
    std::cout << (versioned_encoding
        ? VersionedEncodingCsvHeader()
        : (encoding_only ? EncodingCsvHeader() : CsvHeader()));
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
