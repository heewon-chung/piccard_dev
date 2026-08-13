#include "raw_timing_schema.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

// Two-sided 95% Student-t critical values for df 1..29.  Paper timing uses
// N=30, so the final entry is the only paper-row value; keeping the table
// explicit also makes the calculation independent of libm/statistics APIs.
constexpr double kStudentT95[] = {
    0.0,
    12.706204736432095,
    4.302652729911275,
    3.182446305284264,
    2.7764451051977987,
    2.570581835636305,
    2.4469118487916806,
    2.3646242515927844,
    2.3060041350333704,
    2.2621571628540993,
    2.2281388519649385,
    2.200985160082949,
    2.1788128296634177,
    2.1603686564610127,
    2.1447866879169273,
    2.131449545559323,
    2.119905299221011,
    2.1098155778331806,
    2.10092204024096,
    2.093024054408263,
    2.0859634472658364,
    2.079613844727662,
    2.0738730679040147,
    2.0686576104190406,
    2.0638985616280205,
    2.059538552753294,
    2.055529438642871,
    2.0518305164802833,
    2.048407141795244,
    2.045229642132703};

using PhaseSamples = std::map<std::string, std::vector<RawTimingSample>>;

std::string Format17(double value) {
    if (!std::isfinite(value)) {
        throw std::invalid_argument("timing value must be finite");
    }
    if (value == 0.0) value = 0.0;
    char buffer[64] = {};
    const int written = std::snprintf(buffer, sizeof(buffer), "%.17g", value);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(buffer)) {
        throw std::runtime_error("failed to format timing value");
    }
    return std::string(buffer, static_cast<size_t>(written));
}

bool FormattedEqual(double left, double right) {
    return Format17(left) == Format17(right);
}

std::vector<std::string> SplitTabs(const std::string& line) {
    std::vector<std::string> fields;
    size_t start = 0;
    while (true) {
        const size_t tab = line.find('\t', start);
        if (tab == std::string::npos) {
            fields.push_back(line.substr(start));
            return fields;
        }
        fields.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
}

void RequireToken(const std::string& value, const char* field) {
    if (value.empty() || value.find_first_of("\t\n\r") != std::string::npos) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
}

uint64_t ParseU64(const std::string& value, const char* field) {
    RequireToken(value, field);
    if (value.front() == '+' || value.front() == '-' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
    size_t consumed = 0;
    unsigned long long parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 10);
    } catch (...) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
    if (consumed != value.size()) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
    return static_cast<uint64_t>(parsed);
}

double ParseDouble(const std::string& value, const char* field) {
    RequireToken(value, field);
    size_t consumed = 0;
    double parsed = 0.0;
    try {
        parsed = std::stod(value, &consumed);
    } catch (...) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
    if (consumed != value.size() || !std::isfinite(parsed)) {
        throw std::invalid_argument(std::string("invalid timing ") + field);
    }
    return parsed;
}

std::optional<double> ParseOptionalDouble(const std::string& value,
                                          const char* field) {
    if (value == "N/A") return std::nullopt;
    return ParseDouble(value, field);
}

bool IsPaperProfile(const std::string& profile_id) {
    return profile_id == kPaperTimingProfileVersion ||
           profile_id.rfind("paper-", 0) == 0;
}

bool IsToyProfile(const std::string& profile_id) {
    return profile_id == kReadinessTimingProfileVersion ||
           profile_id == "toy-smoke" || profile_id.rfind("toy-", 0) == 0;
}

const PaperTimingProducerContract* FindContract(
    const std::string& producer_id) {
    const auto& contracts = PaperTimingProducerContracts();
    const auto it = std::find_if(
        contracts.begin(), contracts.end(), [&](const auto& contract) {
            return contract.producer_id == producer_id;
        });
    return it == contracts.end() ? nullptr : &*it;
}

const char* WarmupPolicyNameInternal(WarmupPolicy policy) {
    switch (policy) {
        case WarmupPolicy::None: return "none";
        case WarmupPolicy::DiscardOne: return "discard_one";
    }
    throw std::invalid_argument("unknown warmup policy");
}

WarmupPolicy ParseWarmupPolicy(const std::string& value) {
    if (value == "none") return WarmupPolicy::None;
    if (value == "discard_one") return WarmupPolicy::DiscardOne;
    throw std::invalid_argument("unknown warmup policy");
}

const char* SampleKindNameInternal(SampleKind kind) {
    switch (kind) {
        case SampleKind::DiscardedWarmup: return "discarded_warmup";
        case SampleKind::Measured: return "measured";
    }
    throw std::invalid_argument("unknown timing sample kind");
}

SampleKind ParseSampleKind(const std::string& value) {
    if (value == "discarded_warmup") return SampleKind::DiscardedWarmup;
    if (value == "measured") return SampleKind::Measured;
    throw std::invalid_argument("unknown timing sample kind");
}

std::string MetadataKey(const std::string& producer,
                       const std::string& profile,
                       const std::string& cell,
                       const std::string& phase) {
    return producer + "\x1f" + profile + "\x1f" + cell + "\x1f" + phase;
}

std::vector<RawTimingSample> CanonicalSamples(const RawTimingArtifact& artifact) {
    auto samples = artifact.samples;
    std::sort(samples.begin(), samples.end(), [](const auto& left, const auto& right) {
        if (left.phase != right.phase) return left.phase < right.phase;
        if (left.sample_kind != right.sample_kind) {
            return left.sample_kind == SampleKind::DiscardedWarmup;
        }
        if (left.trial_index != right.trial_index) {
            return left.trial_index < right.trial_index;
        }
        return left.seed < right.seed;
    });
    return samples;
}

double StudentT95(uint64_t count) {
    if (count < 2) {
        throw std::invalid_argument("Student-t interval requires N >= 2");
    }
    const uint64_t degrees_of_freedom = count - 1;
    if (degrees_of_freedom >=
        sizeof(kStudentT95) / sizeof(kStudentT95[0])) {
        // This API is frozen to the paper N=30 and toy N=1 contracts.  A
        // value above the table would otherwise silently turn into a normal
        // approximation and weaken reproducibility.
        throw std::invalid_argument("timing sample count has no frozen t value");
    }
    return kStudentT95[degrees_of_freedom];
}

void CompareOptional(const std::optional<double>& expected,
                     const std::optional<double>& actual,
                     const char* field) {
    if (expected.has_value() != actual.has_value()) {
        throw std::invalid_argument(std::string("timing aggregate ") + field +
                                    " N/A mismatch");
    }
    if (expected.has_value() && !FormattedEqual(*expected, *actual)) {
        throw std::invalid_argument(std::string("timing aggregate ") + field +
                                    " mismatch");
    }
}

void CompareAggregate(const TimingAggregateV1& expected,
                      const TimingAggregateV1& actual) {
    if (expected.producer_id != actual.producer_id ||
        expected.profile_id != actual.profile_id ||
        expected.cell_id != actual.cell_id || expected.phase != actual.phase ||
        expected.measured_count != actual.measured_count ||
        expected.format_version != actual.format_version ||
        !FormattedEqual(expected.mean_ms, actual.mean_ms) ||
        !FormattedEqual(expected.median_ms, actual.median_ms)) {
        throw std::invalid_argument("timing aggregate metadata/value mismatch");
    }
    CompareOptional(expected.sample_sd_ms, actual.sample_sd_ms, "sample_sd_ms");
    CompareOptional(expected.ci95_low_ms, actual.ci95_low_ms, "ci95_low_ms");
    CompareOptional(expected.ci95_high_ms, actual.ci95_high_ms,
                    "ci95_high_ms");
}

void AppendLine(std::ostringstream& output,
                std::initializer_list<std::string> fields) {
    bool first = true;
    for (const auto& field : fields) {
        if (!first) output << '\t';
        first = false;
        output << field;
    }
    output << '\n';
}

}  // namespace

const std::vector<PaperTimingProducerContract>&
PaperTimingProducerContracts() {
    static const std::vector<PaperTimingProducerContract> contracts = {
        {"bench_piccard", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_onehot_sqrt", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_sqrt_comparison", 30, 1, WarmupPolicy::None,
         "RAW_MEASURED_V1"},
        {"bench_crossover", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_dynamic", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_threshold", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_review_comparison", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"bench_fhe_ind", 30, 1, WarmupPolicy::None,
         "RAW_MEASURED_V1"},
        {"bench_sj16_calibrate", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"real_timing", 30, 1, WarmupPolicy::DiscardOne,
         "RAW_MEASURED_V1"},
        {"dynamic_refresh", 30, 1, WarmupPolicy::None,
         "RAW_MEASURED_V1"},
    };
    return contracts;
}

std::string TimingContractFor(const std::string& producer_id) {
    const auto* contract = FindContract(producer_id);
    return contract == nullptr ? kTimingNotApplicable : contract->timing_contract;
}

uint64_t ExpectedTimingTrials(const std::string& profile_id) {
    if (IsToyProfile(profile_id)) return 1;
    if (IsPaperProfile(profile_id)) return 30;
    throw std::invalid_argument("unknown timing profile: " + profile_id);
}

WarmupPolicy ExpectedWarmupPolicy(const std::string& producer_id) {
    const auto* contract = FindContract(producer_id);
    if (contract == nullptr) {
        throw std::invalid_argument("unknown timing producer: " + producer_id);
    }
    return contract->warmup_policy;
}

const char* WarmupPolicyName(WarmupPolicy policy) {
    return WarmupPolicyNameInternal(policy);
}

const char* SampleKindName(SampleKind kind) {
    return SampleKindNameInternal(kind);
}

TimingAggregateV1 ComputeTimingAggregateV1(
    const std::string& producer_id,
    const std::string& profile_id,
    const std::string& cell_id,
    const std::string& phase,
    const std::vector<RawTimingSample>& samples) {
    RequireToken(producer_id, "producer_id");
    RequireToken(profile_id, "profile_id");
    RequireToken(cell_id, "cell_id");
    RequireToken(phase, "phase");
    std::vector<double> values;
    for (const auto& sample : samples) {
        if (sample.producer_id != producer_id ||
            sample.profile_id != profile_id || sample.cell_id != cell_id ||
            sample.phase != phase) {
            throw std::invalid_argument("timing aggregate sample metadata mismatch");
        }
        if (sample.sample_kind == SampleKind::Measured) {
            if (!std::isfinite(sample.raw_ms) || sample.raw_ms < 0.0) {
                throw std::invalid_argument("timing sample must be finite/non-negative");
            }
            values.push_back(sample.raw_ms);
        }
    }
    if (values.empty()) {
        throw std::invalid_argument("timing aggregate has no measured samples");
    }
    const double sum = std::accumulate(values.begin(), values.end(), 0.0);
    const double mean = sum / static_cast<double>(values.size());
    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    const size_t n = sorted.size();

    TimingAggregateV1 aggregate;
    aggregate.producer_id = producer_id;
    aggregate.profile_id = profile_id;
    aggregate.cell_id = cell_id;
    aggregate.phase = phase;
    aggregate.measured_count = static_cast<uint64_t>(n);
    aggregate.mean_ms = mean;
    aggregate.median_ms = n % 2 == 0
                              ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
                              : sorted[n / 2];
    if (n >= 2) {
        double sum_sq = 0.0;
        for (double value : values) {
            const double delta = value - mean;
            sum_sq += delta * delta;
        }
        aggregate.sample_sd_ms =
            std::sqrt(sum_sq / static_cast<double>(n - 1));
        const double margin = StudentT95(n) * *aggregate.sample_sd_ms /
                              std::sqrt(static_cast<double>(n));
        aggregate.ci95_low_ms = mean - margin;
        aggregate.ci95_high_ms = mean + margin;
    }
    return aggregate;
}

void ValidateRawTimingArtifact(const RawTimingArtifact& artifact) {
    RequireToken(artifact.producer_id, "producer_id");
    RequireToken(artifact.profile_id, "profile_id");
    RequireToken(artifact.cell_id, "cell_id");
    if (TimingContractFor(artifact.producer_id) == kTimingNotApplicable) {
        throw std::invalid_argument("producer has no timing contract");
    }
    const uint64_t expected_profile_trials =
        ExpectedTimingTrials(artifact.profile_id);
    if (artifact.expected_measured != expected_profile_trials) {
        throw std::invalid_argument("timing measured count disagrees with profile");
    }
    if (ExpectedWarmupPolicy(artifact.producer_id) != artifact.warmup_policy) {
        throw std::invalid_argument("timing warmup policy disagrees with producer");
    }
    if (artifact.samples.empty()) {
        throw std::invalid_argument("timing artifact has no raw samples");
    }

    PhaseSamples by_phase;
    std::set<std::string> phase_names;
    for (const auto& sample : artifact.samples) {
        RequireToken(sample.producer_id, "sample producer_id");
        RequireToken(sample.profile_id, "sample profile_id");
        RequireToken(sample.cell_id, "sample cell_id");
        RequireToken(sample.phase, "sample phase");
        if (sample.producer_id != artifact.producer_id ||
            sample.profile_id != artifact.profile_id ||
            sample.cell_id != artifact.cell_id) {
            throw std::invalid_argument("timing sample metadata disagrees with artifact");
        }
        if (!std::isfinite(sample.raw_ms) || sample.raw_ms < 0.0) {
            throw std::invalid_argument("timing sample must be finite/non-negative");
        }
        by_phase[sample.phase].push_back(sample);
        phase_names.insert(sample.phase);
    }

    std::vector<TimingAggregateV1> expected_aggregates;
    expected_aggregates.reserve(phase_names.size());
    std::set<uint64_t> reference_indices;
    bool reference_indices_set = false;
    for (const auto& [phase, samples] : by_phase) {
        size_t warmups = 0;
        std::set<uint64_t> indices;
        std::vector<RawTimingSample> measured;
        for (const auto& sample : samples) {
            if (sample.sample_kind == SampleKind::DiscardedWarmup) {
                ++warmups;
                if (sample.trial_index != 0) {
                    throw std::invalid_argument("warmup trial index must be zero");
                }
            } else if (sample.sample_kind == SampleKind::Measured) {
                if (!indices.insert(sample.trial_index).second ||
                    sample.trial_index >= artifact.expected_measured) {
                    throw std::invalid_argument("timing trial index is duplicate/out of range");
                }
                measured.push_back(sample);
            } else {
                throw std::invalid_argument("unknown timing sample kind");
            }
        }
        if (artifact.warmup_policy == WarmupPolicy::DiscardOne) {
            if (warmups != 1) {
                throw std::invalid_argument("timing phase requires exactly one warmup");
            }
        } else if (warmups != 0) {
            throw std::invalid_argument("timing phase forbids a warmup");
        }
        if (measured.size() != artifact.expected_measured ||
            indices.size() != artifact.expected_measured) {
            throw std::invalid_argument("timing phase measured count mismatch");
        }
        for (uint64_t index = 0; index < artifact.expected_measured; ++index) {
            if (indices.count(index) == 0) {
                throw std::invalid_argument("timing trial indices are not zero-based contiguous");
            }
        }
        if (!reference_indices_set) {
            reference_indices = indices;
            reference_indices_set = true;
        } else if (reference_indices != indices) {
            throw std::invalid_argument("timing phases do not share trial indices");
        }
        expected_aggregates.push_back(
            ComputeTimingAggregateV1(artifact.producer_id, artifact.profile_id,
                                     artifact.cell_id, phase, samples));
    }

    if (!artifact.aggregates.empty()) {
        if (artifact.aggregates.size() != expected_aggregates.size()) {
            throw std::invalid_argument("timing aggregate phase count mismatch");
        }
        std::vector<TimingAggregateV1> actual = artifact.aggregates;
        std::sort(actual.begin(), actual.end(),
                  [](const auto& left, const auto& right) {
                      return left.phase < right.phase;
                  });
        for (size_t index = 0; index < expected_aggregates.size(); ++index) {
            CompareAggregate(expected_aggregates[index], actual[index]);
        }
    }
}

std::string SerializeRawTimingArtifactV1(const RawTimingArtifact& artifact) {
    ValidateRawTimingArtifact(artifact);
    std::map<std::string, std::vector<RawTimingSample>> by_phase;
    for (const auto& sample : artifact.samples) by_phase[sample.phase].push_back(sample);

    std::vector<TimingAggregateV1> aggregates;
    for (const auto& [phase, samples] : by_phase) {
        aggregates.push_back(ComputeTimingAggregateV1(
            artifact.producer_id, artifact.profile_id, artifact.cell_id, phase,
            samples));
    }
    if (!artifact.aggregates.empty()) {
        RawTimingArtifact checked = artifact;
        checked.aggregates = aggregates;
        ValidateRawTimingArtifact(artifact);
    }

    std::ostringstream output;
    AppendLine(output, {"schema_version", kPaperRawTimingSchemaVersion});
    AppendLine(output, {"artifact_type", "raw_timing_v1"});
    AppendLine(output, {"producer_id", artifact.producer_id});
    AppendLine(output, {"profile_id", artifact.profile_id});
    AppendLine(output, {"cell_id", artifact.cell_id});
    AppendLine(output, {"warmup_policy", WarmupPolicyName(artifact.warmup_policy)});
    AppendLine(output, {"expected_measured", std::to_string(artifact.expected_measured)});
    AppendLine(output, {"samples"});
    AppendLine(output, {"sample", "producer_id", "profile_id", "cell_id",
                        "phase", "sample_kind", "trial_index", "seed", "raw_ms"});
    for (const auto& sample : CanonicalSamples(artifact)) {
        AppendLine(output, {"sample", sample.producer_id, sample.profile_id,
                            sample.cell_id, sample.phase,
                            SampleKindName(sample.sample_kind),
                            std::to_string(sample.trial_index),
                            std::to_string(sample.seed), Format17(sample.raw_ms)});
    }
    AppendLine(output, {"aggregates"});
    AppendLine(output, {"aggregate", "producer_id", "profile_id", "cell_id",
                        "phase", "measured_count", "mean_ms", "sample_sd_ms",
                        "median_ms", "ci95_low_ms", "ci95_high_ms",
                        "format_version"});
    for (const auto& aggregate : aggregates) {
        AppendLine(output, {"aggregate", aggregate.producer_id,
                            aggregate.profile_id, aggregate.cell_id,
                            aggregate.phase,
                            std::to_string(aggregate.measured_count),
                            Format17(aggregate.mean_ms),
                            aggregate.sample_sd_ms.has_value()
                                ? Format17(*aggregate.sample_sd_ms)
                                : "N/A",
                            Format17(aggregate.median_ms),
                            aggregate.ci95_low_ms.has_value()
                                ? Format17(*aggregate.ci95_low_ms)
                                : "N/A",
                            aggregate.ci95_high_ms.has_value()
                                ? Format17(*aggregate.ci95_high_ms)
                                : "N/A",
                            aggregate.format_version});
    }
    return output.str();
}

void WriteRawTimingArtifactV1(const std::string& path,
                              const RawTimingArtifact& artifact) {
    if (path.empty()) {
        throw std::invalid_argument("raw timing output path is empty");
    }
    const std::filesystem::path destination(path);
    if (std::filesystem::exists(destination)) {
        throw std::invalid_argument("raw timing output already exists: " + path);
    }
    const std::filesystem::path parent = destination.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        throw std::invalid_argument("raw timing output parent does not exist: " +
                                    parent.string());
    }
    const std::filesystem::path temporary = destination.string() + ".tmp";
    if (std::filesystem::exists(temporary)) {
        throw std::invalid_argument("raw timing temporary output already exists: " +
                                    temporary.string());
    }
    const std::string content = SerializeRawTimingArtifactV1(artifact);
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw std::runtime_error("cannot open raw timing temporary output: " +
                                     temporary.string());
        }
        output.write(content.data(), static_cast<std::streamsize>(content.size()));
        output.flush();
        if (!output) {
            throw std::runtime_error("cannot write raw timing temporary output: " +
                                     temporary.string());
        }
    }
    std::error_code error;
    std::filesystem::rename(temporary, destination, error);
    if (error) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("cannot publish raw timing output: " +
                                 destination.string());
    }
}

namespace {

std::string SafeFilenameComponent(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (const char character : value) {
        const bool safe = (character >= 'a' && character <= 'z') ||
                          (character >= 'A' && character <= 'Z') ||
                          (character >= '0' && character <= '9') ||
                          character == '_' || character == '-' ||
                          character == '.';
        output.push_back(safe ? character : '_');
    }
    return output.empty() ? "artifact" : output;
}

}  // namespace

void WriteRawTimingArtifactsV1(
    const std::string& output_directory,
    const std::vector<RawTimingArtifact>& artifacts) {
    if (output_directory.empty()) {
        throw std::invalid_argument("raw timing output directory is empty");
    }
    if (artifacts.empty()) {
        throw std::invalid_argument("raw timing artifact list is empty");
    }
    const std::filesystem::path directory(output_directory);
    if (!std::filesystem::exists(directory) ||
        !std::filesystem::is_directory(directory)) {
        throw std::invalid_argument("raw timing output directory does not exist: " +
                                    output_directory);
    }
    std::set<std::string> paths;
    for (const auto& artifact : artifacts) {
        ValidateRawTimingArtifact(artifact);
        const std::string filename =
            SafeFilenameComponent(artifact.producer_id) + "__" +
            SafeFilenameComponent(artifact.cell_id) + "__" +
            SafeFilenameComponent(artifact.profile_id) + ".tsv";
        if (!paths.insert(filename).second) {
            throw std::invalid_argument("duplicate raw timing artifact path: " +
                                        filename);
        }
    }
    // Validate the complete set before publishing any file. This prevents a
    // partial campaign root when one phase/cell has malformed records.
    for (const auto& artifact : artifacts) {
        const std::string filename =
            SafeFilenameComponent(artifact.producer_id) + "__" +
            SafeFilenameComponent(artifact.cell_id) + "__" +
            SafeFilenameComponent(artifact.profile_id) + ".tsv";
        WriteRawTimingArtifactV1((directory / filename).string(), artifact);
    }
}

RawTimingArtifact ParseRawTimingArtifactV1(const std::string& serialized) {
    if (serialized.empty() || serialized.back() != '\n') {
        throw std::invalid_argument("timing artifact must end with LF");
    }
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < serialized.size()) {
        const size_t end = serialized.find('\n', start);
        if (end == std::string::npos) break;
        lines.push_back(serialized.substr(start, end - start));
        start = end + 1;
    }
    size_t index = 0;
    auto require_line = [&](const std::string& expected) {
        if (index >= lines.size() || lines[index++] != expected) {
            throw std::invalid_argument("timing artifact header mismatch");
        }
    };
    require_line(std::string("schema_version\t") + kPaperRawTimingSchemaVersion);
    require_line("artifact_type\traw_timing_v1");
    auto read_value = [&](const char* key) {
        if (index >= lines.size()) {
            throw std::invalid_argument("timing artifact missing metadata");
        }
        const auto fields = SplitTabs(lines[index++]);
        if (fields.size() != 2 || fields[0] != key) {
            throw std::invalid_argument("timing artifact metadata key mismatch");
        }
        RequireToken(fields[1], key);
        return fields[1];
    };
    RawTimingArtifact artifact;
    artifact.producer_id = read_value("producer_id");
    artifact.profile_id = read_value("profile_id");
    artifact.cell_id = read_value("cell_id");
    artifact.warmup_policy = ParseWarmupPolicy(read_value("warmup_policy"));
    artifact.expected_measured = ParseU64(read_value("expected_measured"),
                                          "expected_measured");
    require_line("samples");
    require_line("sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\ttrial_index\tseed\traw_ms");
    while (index < lines.size() && lines[index] != "aggregates") {
        const auto fields = SplitTabs(lines[index++]);
        if (fields.size() != 9 || fields[0] != "sample") {
            throw std::invalid_argument("timing sample row shape mismatch");
        }
        RawTimingSample sample;
        sample.producer_id = fields[1];
        sample.profile_id = fields[2];
        sample.cell_id = fields[3];
        sample.phase = fields[4];
        sample.sample_kind = ParseSampleKind(fields[5]);
        sample.trial_index = ParseU64(fields[6], "trial_index");
        sample.seed = ParseU64(fields[7], "seed");
        sample.raw_ms = ParseDouble(fields[8], "raw_ms");
        artifact.samples.push_back(std::move(sample));
    }
    require_line("aggregates");
    require_line("aggregate\tproducer_id\tprofile_id\tcell_id\tphase\tmeasured_count\tmean_ms\tsample_sd_ms\tmedian_ms\tci95_low_ms\tci95_high_ms\tformat_version");
    while (index < lines.size()) {
        const auto fields = SplitTabs(lines[index++]);
        if (fields.size() != 12 || fields[0] != "aggregate") {
            throw std::invalid_argument("timing aggregate row shape mismatch");
        }
        TimingAggregateV1 aggregate;
        aggregate.producer_id = fields[1];
        aggregate.profile_id = fields[2];
        aggregate.cell_id = fields[3];
        aggregate.phase = fields[4];
        aggregate.measured_count = ParseU64(fields[5], "measured_count");
        aggregate.mean_ms = ParseDouble(fields[6], "mean_ms");
        aggregate.sample_sd_ms = ParseOptionalDouble(fields[7], "sample_sd_ms");
        aggregate.median_ms = ParseDouble(fields[8], "median_ms");
        aggregate.ci95_low_ms = ParseOptionalDouble(fields[9], "ci95_low_ms");
        aggregate.ci95_high_ms = ParseOptionalDouble(fields[10], "ci95_high_ms");
        aggregate.format_version = fields[11];
        artifact.aggregates.push_back(std::move(aggregate));
    }
    if (index != lines.size()) {
        throw std::invalid_argument("timing artifact trailing data");
    }
    ValidateRawTimingArtifact(artifact);
    return artifact;
}

}  // namespace piccard::benchmark
