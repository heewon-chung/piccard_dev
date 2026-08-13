#include "dynamic_revision_adapter.h"

#include <charconv>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid dynamic revision argv: " + reason);
}

uint64_t ParseUnsigned(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '-' || value.front() == '+' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    uint64_t parsed = 0;
    const char* first = value.data();
    const char* last = first + value.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last ||
        std::to_string(parsed) != value || parsed == 0) {
        Reject(std::string(field) + " must be a positive canonical integer");
    }
    return parsed;
}

void MarkSeen(std::set<std::string>& seen, const std::string& name) {
    if (!seen.insert(name).second) Reject("duplicate " + name);
}

template <typename Setter>
void ParseStringValue(const std::string& arg,
                      const char* prefix,
                      const char* field,
                      std::set<std::string>& seen,
                      Setter&& setter,
                      bool& recognized) {
    if (arg.rfind(prefix, 0) != 0) return;
    recognized = true;
    const std::string name(prefix, std::char_traits<char>::length(prefix) - 1);
    MarkSeen(seen, name);
    const std::string value = arg.substr(std::char_traits<char>::length(prefix));
    if (value.empty()) Reject(std::string(field) + " must not be empty");
    setter(value);
}

template <typename Setter>
void ParseUnsignedValue(const std::string& arg,
                        const char* prefix,
                        const char* field,
                        std::set<std::string>& seen,
                        Setter&& setter,
                        bool& recognized) {
    if (arg.rfind(prefix, 0) != 0) return;
    recognized = true;
    const std::string name(prefix, std::char_traits<char>::length(prefix) - 1);
    MarkSeen(seen, name);
    const std::string value = arg.substr(std::char_traits<char>::length(prefix));
    setter(ParseUnsigned(value, field));
}

void RequireSeen(const std::set<std::string>& seen, const char* name) {
    if (seen.find(name) == seen.end()) Reject(std::string("missing ") + name);
}

void RequireProfileContract(const DynamicRevisionRequest& request) {
    if (request.profile != "paper-std128-t40-v1" &&
        request.profile != "readiness-toy-v1") {
        Reject("unsupported --profile");
    }
    if (request.cell != "timing" && request.cell != "accuracy" &&
        request.cell != "refresh") {
        Reject("--cell must be timing, accuracy, or refresh");
    }
    if (request.mode != request.cell) {
        Reject("--mode must equal --cell");
    }
    const bool toy = request.profile == "readiness-toy-v1";
    if (request.security != (toy ? "TOY" : "STD128")) {
        Reject("--security conflicts with --profile");
    }
    const uint64_t expected_trials = toy ? 1u :
        (request.cell == "accuracy" ? 50u : 30u);
    if (request.trials != expected_trials) {
        Reject("--trials conflicts with --profile/--cell");
    }
    if (request.updates != 1u) {
        Reject("--updates must be exactly one");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (request.cell == "accuracy") {
        if (!request.raw_timing_dir.empty() ||
            !request.raw_timing_profile.empty()) {
            Reject("accuracy cells must not request raw timing");
        }
    } else {
        const std::string expected_profile =
            toy ? "readiness-toy-v1" : "paper-v1";
        if (request.raw_timing_dir != "{output}/raw" ||
            request.raw_timing_profile != expected_profile) {
            Reject("timing/refresh raw timing contract mismatch");
        }
    }
}

}  // namespace

DynamicRevisionRequest ParseDynamicRevisionArgs(
    const std::vector<std::string>& argv) {
    DynamicRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& arg : argv) {
        if (arg == "--evidence_point") {
            MarkSeen(seen, "--evidence_point");
            request.evidence_point = true;
            continue;
        }

        bool recognized = false;
        ParseStringValue(arg, "--revision-cell=", "--revision-cell", seen,
                         [&](const std::string& value) {
                             request.revision_cell = value;
                         }, recognized);
        ParseStringValue(arg, "--profile=", "--profile", seen,
                         [&](const std::string& value) {
                             request.profile = value;
                         }, recognized);
        ParseStringValue(arg, "--cell=", "--cell", seen,
                         [&](const std::string& value) { request.cell = value; },
                         recognized);
        ParseStringValue(arg, "--mode=", "--mode", seen,
                         [&](const std::string& value) { request.mode = value; },
                         recognized);
        ParseStringValue(arg, "--security=", "--security", seen,
                         [&](const std::string& value) {
                             request.security = value;
                         }, recognized);
        ParseStringValue(arg, "--seed=", "--seed", seen,
                         [&](const std::string& value) { request.seed = value; },
                         recognized);
        ParseStringValue(arg, "--raw-timing-dir=", "--raw-timing-dir", seen,
                         [&](const std::string& value) {
                             request.raw_timing_dir = value;
                         }, recognized);
        ParseStringValue(arg, "--raw-timing-profile=", "--raw-timing-profile",
                         seen,
                         [&](const std::string& value) {
                             request.raw_timing_profile = value;
                         }, recognized);

        ParseUnsignedValue(arg, "--k=", "--k", seen, [&](uint64_t value) {
            if (value > std::numeric_limits<uint32_t>::max()) {
                Reject("--k is out of range");
            }
            request.k = static_cast<uint32_t>(value);
        }, recognized);
        ParseUnsignedValue(arg, "--m=", "--m", seen, [&](uint64_t value) {
            if (value > std::numeric_limits<uint32_t>::max()) {
                Reject("--m is out of range");
            }
            request.m = static_cast<uint32_t>(value);
        }, recognized);
        ParseUnsignedValue(arg, "--set_size=", "--set_size", seen,
                           [&](uint64_t value) { request.set_size = value; },
                           recognized);
        ParseUnsignedValue(arg, "--universe=", "--universe", seen,
                           [&](uint64_t value) { request.universe = value; },
                           recognized);
        ParseUnsignedValue(arg, "--trials=", "--trials", seen,
                           [&](uint64_t value) { request.trials = value; },
                           recognized);
        ParseUnsignedValue(arg, "--updates=", "--updates", seen,
                           [&](uint64_t value) { request.updates = value; },
                           recognized);

        if (!recognized) Reject("unknown option " + arg);
    }

    for (const char* name : {"--revision-cell", "--profile", "--cell",
                             "--mode", "--security", "--k", "--m",
                             "--set_size", "--universe", "--trials",
                             "--updates", "--seed"}) {
        RequireSeen(seen, name);
    }
    RequireSeen(seen, "--evidence_point");
    if (!request.evidence_point) Reject("--evidence_point is required");
    RequireProfileContract(request);
    return request;
}

DynamicRevisionSelection SelectDynamicRevisionCell(
    const RevisionMatrix& matrix,
    const DynamicRevisionRequest& request,
    const RevisionRunMode mode) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != request.revision_cell) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");

    RevisionInvocationPlan plan = PlanDynamicRevisionCell(*selected, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }

    DynamicRevisionSelection selection;
    selection.cell = *selected;
    selection.plan = std::move(plan);
    return selection;
}

DynamicRevisionSelection SelectDynamicRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return SelectDynamicRevisionCell(matrix, ParseDynamicRevisionArgs(argv),
                                     mode);
}

DynamicRevisionExecutionPlan PlanDynamicRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const DynamicRevisionRequest request = ParseDynamicRevisionArgs(argv);
    DynamicRevisionExecutionPlan execution;
    execution.selection = SelectDynamicRevisionCell(matrix, request, mode);
    execution.kind = request.cell;
    execution.point = {
        request.cell, request.k, request.m,
        static_cast<std::size_t>(request.set_size),
        static_cast<uint32_t>(request.universe), 0.5};
    execution.update_count = request.updates;
    execution.protocol_runs = request.trials;
    execution.selected_point_count = 1;
    execution.keygen_calls = 0;
    execution.versioned_correctness = request.cell == "accuracy";
    execution.raw_timing = !request.raw_timing_dir.empty();
    execution.native_sweep = false;
    return execution;
}

std::vector<DynamicRevisionExecutionPlan> PlanDynamicExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return {PlanDynamicRevisionExecution(matrix, argv, mode)};
}

std::vector<DynamicRevisionExecutionPlan> PlanDynamicExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix) {
    const DynamicRevisionRequest request = ParseDynamicRevisionArgs(argv);
    const RevisionRunMode mode = request.profile == "readiness-toy-v1"
                                     ? RevisionRunMode::Toy
                                     : RevisionRunMode::Paper;
    return PlanDynamicExecutionSpy(matrix, argv, mode);
}

}  // namespace piccard::benchmark
