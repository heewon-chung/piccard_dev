#include "threshold_revision_adapter.h"

#include <charconv>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid threshold revision argv: " + reason);
}

uint64_t ParseUnsigned(const std::string& value, const char* field,
                       bool allow_zero = false) {
    if (value.empty() || value.front() == '-' || value.front() == '+' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    uint64_t parsed = 0;
    const char* first = value.data();
    const char* last = first + value.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last ||
        std::to_string(parsed) != value || (!allow_zero && parsed == 0)) {
        Reject(std::string(field) + " must be a canonical " +
               (allow_zero ? "unsigned integer" : "positive integer"));
    }
    return parsed;
}

int32_t ParseSigned(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '+' ||
        value.find_first_not_of("-0123456789") != std::string::npos ||
        (value.find('-') != std::string::npos && value.front() != '-')) {
        Reject(std::string(field) + " must be a canonical signed integer");
    }
    int32_t parsed = 0;
    const char* first = value.data();
    const char* last = first + value.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last ||
        std::to_string(parsed) != value) {
        Reject(std::string(field) + " must be a canonical signed integer");
    }
    return parsed;
}

void MarkSeen(std::set<std::string>& seen, const std::string& name) {
    if (!seen.insert(name).second) Reject("duplicate " + name);
}

void RequireSeen(const std::set<std::string>& seen, const char* name) {
    if (seen.find(name) == seen.end()) Reject(std::string("missing ") + name);
}

template <typename Setter>
void ParseValue(const std::string& arg, const char* prefix,
                std::set<std::string>& seen, Setter&& setter) {
    if (arg.rfind(prefix, 0) != 0) return;
    const std::string name(prefix, prefix + std::char_traits<char>::length(prefix) - 1);
    MarkSeen(seen, name);
    const std::string value = arg.substr(std::char_traits<char>::length(prefix));
    if (value.empty()) Reject(name + " must not be empty");
    setter(value);
}

void CheckUint32Range(uint64_t value, const char* field) {
    if (value > std::numeric_limits<uint32_t>::max()) {
        Reject(std::string(field) + " is out of range");
    }
}

bool IsFheFamily(const std::string& family) {
    return family == "threshold_timing" || family == "threshold_spec" ||
           family == "threshold_agreement";
}

bool IsSyntheticFamily(const std::string& family) {
    return family == "threshold_synthetic_fpfn";
}

std::string KindForFamily(const std::string& family) {
    if (family == "threshold_timing") return "timing";
    if (family == "threshold_spec") return "spec";
    if (family == "threshold_agreement") return "agreement";
    if (family == "threshold_synthetic_fpfn") return "synthetic_fpfn";
    Reject("unsupported threshold family");
}

RevisionRunMode ModeForProfile(const std::string& profile) {
    if (profile == "readiness-toy-v1") return RevisionRunMode::Toy;
    if (profile == "paper-v1") return RevisionRunMode::Paper;
    Reject("unsupported profile");
}

}  // namespace

ThresholdRevisionRequest ParseThresholdRevisionArgs(
    const std::vector<std::string>& argv) {
    ThresholdRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& arg : argv) {
        bool recognized = false;

        auto string_arg = [&](const char* prefix, std::string& destination) {
            if (arg.rfind(prefix, 0) != 0) return;
            recognized = true;
            ParseValue(arg, prefix, seen,
                        [&](const std::string& value) { destination = value; });
        };
        auto uint32_arg = [&](const char* prefix, const char* field,
                              uint32_t& destination,
                              bool allow_zero = false) {
            if (arg.rfind(prefix, 0) != 0) return;
            recognized = true;
            ParseValue(arg, prefix, seen, [&](const std::string& value) {
                const uint64_t parsed = ParseUnsigned(value, field, allow_zero);
                CheckUint32Range(parsed, field);
                destination = static_cast<uint32_t>(parsed);
            });
        };

        string_arg("--revision-cell=", request.revision_cell);
        string_arg("--profile=", request.profile);
        string_arg("--mode=", request.mode);
        string_arg("--cell=", request.cell);
        string_arg("--security=", request.security);
        string_arg("--seed=", request.seed);
        string_arg("--hash_randomness=", request.hash_randomness);
        string_arg("--raw_timing_dir=", request.raw_timing_dir);
        if (recognized) continue;

        uint32_arg("--k=", "--k", request.k);
        if (recognized) continue;
        uint32_arg("--m=", "--m", request.m);
        if (recognized) continue;
        uint32_arg("--set_size=", "--set_size", request.set_size);
        if (recognized) continue;
        uint32_arg("--point-k=", "--point-k", request.point_k);
        if (recognized) continue;

        if (arg.rfind("--grid-index=", 0) == 0) {
            recognized = true;
            ParseValue(arg, "--grid-index=", seen, [&](const std::string& value) {
                request.grid_index = ParseSigned(value, "--grid-index");
            });
            continue;
        }
        if (arg.rfind("--trials=", 0) == 0) {
            recognized = true;
            ParseValue(arg, "--trials=", seen, [&](const std::string& value) {
                request.trials = ParseUnsigned(value, "--trials", true);
            });
            continue;
        }

        if (!recognized) Reject("unknown option " + arg);
    }

    for (const char* name : {"--revision-cell", "--profile", "--mode",
                             "--m", "--set_size", "--trials", "--seed"}) {
        RequireSeen(seen, name);
    }
    if (request.revision_cell.empty()) Reject("missing --revision-cell value");
    if (request.profile != "paper-v1" && request.profile != "readiness-toy-v1") {
        Reject("unsupported --profile");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (request.m != 64u || request.set_size != 1000u) {
        Reject("threshold revision geometry requires --m=64 and --set_size=1000");
    }
    if (request.mode == "fpfn") {
        if (!request.cell.empty()) Reject("synthetic FPFN does not accept --cell");
        if (request.hash_randomness != "resampled") {
            Reject("synthetic FPFN requires --hash_randomness=resampled");
        }
        RequireSeen(seen, "--point-k");
        RequireSeen(seen, "--grid-index");
    } else if (request.mode == "timing" || request.mode == "spec" ||
               request.mode == "accuracy") {
        RequireSeen(seen, "--security");
        if (request.security !=
            (request.profile == "readiness-toy-v1" ? "TOY" : "STD128")) {
            Reject("--security conflicts with --profile");
        }
        RequireSeen(seen, "--k");
        RequireSeen(seen, "--cell");
        if (request.cell != "timing" && request.cell != "spec" &&
            request.cell != "agreement") {
            Reject("unsupported --cell");
        }
        if (!request.hash_randomness.empty()) {
            Reject("FHE threshold cells do not accept --hash_randomness");
        }
    } else {
        Reject("unsupported --mode");
    }
    return request;
}

ThresholdRevisionSelection SelectThresholdRevisionCell(
    const RevisionMatrix& matrix,
    const ThresholdRevisionRequest& request,
    const RevisionRunMode mode) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != request.revision_cell) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");
    if (!IsFheFamily(selected->family) && !IsSyntheticFamily(selected->family)) {
        Reject("cell is not owned by bench_threshold");
    }

    const std::string expected_profile =
        mode == RevisionRunMode::Toy ? "readiness-toy-v1" : "paper-v1";
    if (request.profile != expected_profile) {
        Reject("profile does not match requested run mode");
    }

    const std::string kind = KindForFamily(selected->family);
    if (IsFheFamily(selected->family)) {
        if (request.cell != kind ||
            request.mode != (kind == "agreement" ? "accuracy" : kind)) {
            Reject("threshold method selector does not match cell family");
        }
    } else if (request.mode != "fpfn") {
        Reject("synthetic threshold cell requires --mode=fpfn");
    }

    const RevisionInvocationPlan plan =
        PlanThresholdRevisionCell(*selected, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }

    ThresholdRevisionSelection selection;
    selection.cell = *selected;
    selection.plan = plan;
    selection.kind = kind;
    return selection;
}

ThresholdRevisionSelection SelectThresholdRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return SelectThresholdRevisionCell(matrix, ParseThresholdRevisionArgs(argv),
                                       mode);
}

ThresholdRevisionExecutionPlan PlanThresholdRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const ThresholdRevisionRequest request = ParseThresholdRevisionArgs(argv);
    ThresholdRevisionExecutionPlan execution;
    execution.selection = SelectThresholdRevisionCell(matrix, request, mode);
    execution.k = request.k;
    execution.m = request.m;
    execution.set_size = request.set_size;
    execution.point_k = request.point_k;
    execution.grid_index = request.grid_index;
    execution.trials = request.trials;
    execution.selected_point_count = 1;
    execution.keygen_calls = 0;
    execution.native_sweep = false;
    if (execution.selection.kind == "synthetic_fpfn") {
        execution.k = request.point_k;
    }
    return execution;
}

std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return {PlanThresholdRevisionExecution(matrix, argv, mode)};
}

std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    const RevisionRunMode mode) {
    return PlanThresholdExecutionSpy(matrix, argv, mode);
}

std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix) {
    const ThresholdRevisionRequest request = ParseThresholdRevisionArgs(argv);
    return PlanThresholdExecutionSpy(
        matrix, argv, ModeForProfile(request.profile));
}

}  // namespace piccard::benchmark
