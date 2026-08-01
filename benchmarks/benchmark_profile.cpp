#include "benchmark_profile.h"

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace piccard {
namespace benchmark {
namespace {

constexpr uint64_t kProfileMaxQueries = UINT64_C(1) << 20;

const std::array<BenchmarkProfile, 7> kProfiles = {{
    {"std128-t40-primary", SecurityLevel::STD128, 128, 40,
     kProfileMaxQueries, 20, BenchmarkRunClass::Primary, true, true},
    {"std192-t40-primary", SecurityLevel::STD192, 192, 40,
     kProfileMaxQueries, 20, BenchmarkRunClass::Primary, true, true},
    {"std128-t64-sensitivity", SecurityLevel::STD128, 128, 64,
     kProfileMaxQueries, 20, BenchmarkRunClass::Sensitivity, true, false},
    {"std192-t64-sensitivity", SecurityLevel::STD192, 192, 64,
     kProfileMaxQueries, 20, BenchmarkRunClass::Sensitivity, true, false},
    {"std128-t128-feasibility", SecurityLevel::STD128, 128, 128,
     kProfileMaxQueries, 20, BenchmarkRunClass::Feasibility, false, false},
    {"std192-t128-feasibility", SecurityLevel::STD192, 192, 128,
     kProfileMaxQueries, 20, BenchmarkRunClass::Feasibility, false, false},
    {"toy-smoke", SecurityLevel::TOY, 0, 40,
     kProfileMaxQueries, 20, BenchmarkRunClass::Smoke, true, false},
}};

void AddKGrid(std::vector<BenchmarkGridPoint>& out,
              const std::vector<uint32_t>& values) {
    for (uint32_t k : values) out.push_back({"k", k, 64, 1000, 0, 0.5});
}

void AddMGrid(std::vector<BenchmarkGridPoint>& out,
              const std::vector<uint32_t>& values) {
    for (uint32_t m : values) out.push_back({"m", 128, m, 1000, 0, 0.5});
}

void AddNGrid(std::vector<BenchmarkGridPoint>& out,
              const std::vector<size_t>& values) {
    for (size_t n : values) out.push_back({"n", 128, 64, n, 0, 0.5});
}

std::vector<BenchmarkGridPoint> PiccardTimingGrid() {
    std::vector<BenchmarkGridPoint> out;
    AddKGrid(out, {16, 32, 64, 128, 256, 512});
    AddMGrid(out, {16, 32, 64, 128, 256});
    AddNGrid(out, {100, 1000, 10000, 100000});
    return out;
}

std::vector<BenchmarkGridPoint> OneHotTimingGrid() {
    std::vector<BenchmarkGridPoint> out;
    AddKGrid(out, {16, 32, 64, 128, 256, 512});
    AddMGrid(out, {4, 16, 64, 256});
    AddNGrid(out, {100, 1000, 10000, 100000});
    return out;
}

std::vector<BenchmarkGridPoint> AccuracyJaccardGrid() {
    std::vector<BenchmarkGridPoint> out;
    for (uint32_t tenth = 0; tenth <= 10; ++tenth) {
        out.push_back({"j", 128, 64, 1000, 0,
                       static_cast<double>(tenth) / 10.0});
    }
    return out;
}

}  // namespace

std::string BenchmarkGridPoint::Key() const {
    std::ostringstream out;
    out << axis << ":k=" << k << ",m=" << m << ",n=" << set_size;
    if (universe_size != 0) out << ",U=" << universe_size;
    out << ",j=" << std::setprecision(12) << target_jaccard;
    return out.str();
}

const BenchmarkProfile& ResolveBenchmarkProfile(std::string_view profile_id) {
    for (const auto& profile : kProfiles) {
        if (profile.id == profile_id) return profile;
    }
    throw std::invalid_argument("Unknown benchmark profile: " +
                                std::string(profile_id));
}

BenchmarkProfile LegacyBenchmarkProfile() {
    BenchmarkProfile profile;
    profile.id = "legacy";
    profile.run_class = BenchmarkRunClass::Legacy;
    profile.failure_is_blocking = false;
    profile.comparison_eligible = false;
    return profile;
}

const char* BenchmarkRunClassName(BenchmarkRunClass run_class) {
    switch (run_class) {
        case BenchmarkRunClass::Primary: return "primary";
        case BenchmarkRunClass::Sensitivity: return "sensitivity";
        case BenchmarkRunClass::Feasibility: return "feasibility";
        case BenchmarkRunClass::Smoke: return "smoke";
        case BenchmarkRunClass::Legacy: return "legacy";
    }
    throw std::logic_error("unknown benchmark run class");
}

const char* BenchmarkMeasurementKindName(BenchmarkMeasurementKind kind) {
    switch (kind) {
        case BenchmarkMeasurementKind::FheTiming: return "fhe-timing";
        case BenchmarkMeasurementKind::FheAccuracy: return "fhe-accuracy";
        case BenchmarkMeasurementKind::Diagnostic: return "diagnostic";
    }
    throw std::logic_error("unknown benchmark measurement kind");
}

BenchmarkMode ParseBenchmarkMode(std::string_view mode) {
    if (mode == "timing") return BenchmarkMode::Timing;
    if (mode == "accuracy") return BenchmarkMode::Accuracy;
    if (mode == "combined") return BenchmarkMode::Combined;
    throw std::invalid_argument("Invalid benchmark mode: " + std::string(mode));
}

std::vector<BenchmarkMeasurementKind> MeasurementKindsForMode(
    BenchmarkMode mode) {
    switch (mode) {
        case BenchmarkMode::Timing:
            return {BenchmarkMeasurementKind::FheTiming};
        case BenchmarkMode::Accuracy:
            return {BenchmarkMeasurementKind::FheAccuracy};
        case BenchmarkMode::Combined:
            return {BenchmarkMeasurementKind::FheTiming,
                    BenchmarkMeasurementKind::FheAccuracy};
    }
    throw std::logic_error("unknown benchmark mode");
}

std::vector<BenchmarkGridPoint> ResolveBenchmarkGrid(
    const BenchmarkProfile& profile,
    BenchmarkProducer producer,
    BenchmarkMode mode,
    bool evidence_point,
    const BenchmarkGridPoint& supplied) {
    if (evidence_point) {
        if (producer == BenchmarkProducer::Crossover ||
            producer == BenchmarkProducer::SqrtComparison) {
            throw std::invalid_argument(
                "--evidence_point is not valid for diagnostic grid producers");
        }
        return {supplied};
    }

    if (profile.run_class == BenchmarkRunClass::Sensitivity ||
        profile.run_class == BenchmarkRunClass::Feasibility) {
        throw std::invalid_argument(
            "sensitivity and feasibility profiles require --evidence_point");
    }

    if ((producer == BenchmarkProducer::Crossover ||
         producer == BenchmarkProducer::SqrtComparison) &&
        profile.run_class == BenchmarkRunClass::Legacy) {
        throw std::invalid_argument(
            "diagnostic benchmark executables require a named profile");
    }

    switch (producer) {
        case BenchmarkProducer::Piccard:
            return PiccardTimingGrid();
        case BenchmarkProducer::OneHotSqrt:
            return mode == BenchmarkMode::Accuracy
                ? AccuracyJaccardGrid() : OneHotTimingGrid();
        case BenchmarkProducer::Dynamic:
            if (mode == BenchmarkMode::Accuracy) {
                throw std::invalid_argument(
                    "dynamic evidence supports timing mode only");
            }
            return PiccardTimingGrid();
        case BenchmarkProducer::Comparison:
            return {{"U", 128, 64, 1000, 16384, 0.5},
                    {"U", 128, 64, 1000, 65536, 0.5}};
        case BenchmarkProducer::Crossover: {
            std::vector<BenchmarkGridPoint> out;
            for (uint32_t k : {32u, 64u, 128u, 256u, 512u}) {
                for (uint32_t m : {4u, 16u, 64u, 256u, 1024u}) {
                    out.push_back({"diagnostic", k, m, 1000, 0, 0.5});
                }
            }
            return out;
        }
        case BenchmarkProducer::SqrtComparison:
            return {{"diagnostic", 128, 64, 500, 0, 0.5},
                    {"diagnostic", 256, 64, 500, 0, 0.5},
                    {"diagnostic", 512, 64, 500, 0, 0.5},
                    {"diagnostic", 1024, 64, 500, 0, 0.5},
                    {"diagnostic", 128, 256, 500, 0, 0.5},
                    {"diagnostic", 128, 1024, 500, 0, 0.5}};
    }
    throw std::logic_error("unknown benchmark producer");
}

}  // namespace benchmark
}  // namespace piccard
