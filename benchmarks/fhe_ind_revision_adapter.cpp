#include "fhe_ind_revision_adapter.h"

#include <cmath>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid FHE-IND revision argv: " + reason);
}

uint64_t ParseUnsigned(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '+' || value.front() == '-' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    size_t consumed = 0;
    uint64_t parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 10);
    } catch (const std::exception&) {
        Reject(std::string(field) + " is out of range");
    }
    if (consumed != value.size() || std::to_string(parsed) != value ||
        parsed == 0) {
        Reject(std::string(field) + " must be a positive canonical integer");
    }
    return parsed;
}

void MarkSeen(std::set<std::string>& seen, const char* field) {
    if (!seen.insert(field).second) {
        Reject(std::string("duplicate ") + field);
    }
}

std::string ValueAfter(const std::string& argument,
                       const char* prefix,
                       const char* field,
                       std::set<std::string>& seen) {
    if (argument.rfind(prefix, 0) != 0) return {};
    MarkSeen(seen, field);
    const std::string value = argument.substr(std::string(prefix).size());
    if (value.empty()) Reject(std::string(field) + " must not be empty");
    return value;
}

void RequireSeen(const std::set<std::string>& seen, const char* field) {
    if (seen.find(field) == seen.end()) Reject(std::string("missing ") + field);
}

bool IsProfile(const std::string& profile) {
    return profile == "paper-v1" || profile == "readiness-toy-v1";
}

std::string ProfileForRequest(const FheIndRevisionRequest& request) {
    if (request.raw_timing_profile == "paper-v1") return "paper-v1";
    if (request.raw_timing_profile == "readiness-toy-v1") {
        return "readiness-toy-v1";
    }
    Reject("unsupported --raw-timing-profile");
}

uint64_t ExpectedTrials(const std::string& profile) {
    return profile == "readiness-toy-v1" ? 1u : 30u;
}

}  // namespace

FheIndRevisionRequest ParseFheIndRevisionArgs(
    const std::vector<std::string>& argv) {
    FheIndRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& argument : argv) {
        std::string value;
        if (!(value = ValueAfter(argument, "--revision-cell=",
                                 "--revision-cell", seen)).empty()) {
            request.revision_cell = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--mode=", "--mode", seen))
                 .empty()) {
            request.mode = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--cell-id=", "--cell-id", seen))
                 .empty()) {
            request.cell_id = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--security=", "--security", seen))
                 .empty()) {
            request.security = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--n=", "--n", seen)).empty()) {
            request.set_size = ParseUnsigned(value, "--n");
            continue;
        }
        if (!(value = ValueAfter(argument, "--universe=", "--universe", seen))
                 .empty()) {
            request.universe = ParseUnsigned(value, "--universe");
            continue;
        }
        if (!(value = ValueAfter(argument, "--trials=", "--trials", seen))
                 .empty()) {
            request.trials = ParseUnsigned(value, "--trials");
            continue;
        }
        if (!(value = ValueAfter(argument, "--raw-timing-out=",
                                 "--raw-timing-out", seen)).empty()) {
            request.raw_timing_out = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--raw-timing-profile=",
                                 "--raw-timing-profile", seen)).empty()) {
            request.raw_timing_profile = std::move(value);
            continue;
        }
        if (!(value = ValueAfter(argument, "--seed=", "--seed", seen))
                 .empty()) {
            request.seed = std::move(value);
            continue;
        }
        Reject("unknown option " + argument);
    }

    for (const char* field : {"--revision-cell", "--mode", "--cell-id",
                              "--security", "--n", "--universe", "--trials",
                              "--raw-timing-out", "--raw-timing-profile",
                              "--seed"}) {
        RequireSeen(seen, field);
    }
    if (request.mode != "e2e") Reject("--mode must be e2e");
    if (request.revision_cell != request.cell_id) {
        Reject("--cell-id must equal --revision-cell");
    }
    if (request.raw_timing_out != "{output}/raw") {
        Reject("--raw-timing-out must be {output}/raw");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (!IsProfile(request.raw_timing_profile)) {
        Reject("unsupported --raw-timing-profile");
    }
    const std::string profile = ProfileForRequest(request);
    const bool toy = profile == "readiness-toy-v1";
    if (request.security != (toy ? "TOY" : "STD128")) {
        Reject("--security conflicts with --raw-timing-profile");
    }
    if (request.trials != ExpectedTrials(profile)) {
        Reject("--trials conflicts with --raw-timing-profile");
    }
    return request;
}

FheIndRevisionSelection SelectFheIndRevisionCell(
    const RevisionMatrix& matrix,
    const FheIndRevisionRequest& request,
    const RevisionRunMode mode) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != request.revision_cell) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");

    const RevisionInvocationPlan plan =
        PlanFheIndRevisionCell(*selected, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }

    return {*selected, selected->axes, plan};
}

FheIndRevisionSelection SelectFheIndRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return SelectFheIndRevisionCell(matrix, ParseFheIndRevisionArgs(argv), mode);
}

FheIndBoundedWorkload MakeFheIndBoundedWorkload(
    const uint64_t set_size,
    const double target_jaccard,
    const uint64_t universe) {
    if (set_size == 0 || universe == 0) {
        Reject("set size and universe must be positive");
    }
    if (!std::isfinite(target_jaccard) || target_jaccard < 0.0 ||
        target_jaccard > 1.0) {
        Reject("target Jaccard must be finite and in [0,1]");
    }
    if (set_size > std::numeric_limits<uint64_t>::max() / 2u) {
        Reject("set size overflows union cardinality");
    }
    if (set_size > std::numeric_limits<size_t>::max()) {
        Reject("set size is too large for this host");
    }

    const long double requested_overlap =
        (2.0L * static_cast<long double>(target_jaccard) *
         static_cast<long double>(set_size)) /
        (1.0L + static_cast<long double>(target_jaccard));
    uint64_t intersection = static_cast<uint64_t>(
        std::floor(requested_overlap));
    if (intersection > set_size) intersection = set_size;
    const uint64_t union_size = 2u * set_size - intersection;
    if (union_size > universe) {
        Reject("universe is insufficient for requested set union");
    }

    const uint64_t unique = set_size - intersection;
    FheIndBoundedWorkload workload;
    workload.set_a.reserve(static_cast<size_t>(set_size));
    workload.set_b.reserve(static_cast<size_t>(set_size));
    for (uint64_t index = 0; index < intersection; ++index) {
        workload.set_a.push_back(index);
        workload.set_b.push_back(index);
    }
    for (uint64_t index = 0; index < unique; ++index) {
        workload.set_a.push_back(intersection + index);
        workload.set_b.push_back(intersection + unique + index);
    }
    workload.intersection_size = intersection;
    workload.union_size = union_size;
    workload.target_jaccard = target_jaccard;
    workload.realized_jaccard = static_cast<double>(intersection) /
                                static_cast<double>(union_size);
    return workload;
}

std::string SerializeFheIndRevisionIdentityHeader() {
    return "schema,cell_id,set_size,universe_size,trial_count\n";
}

std::string SerializeFheIndRevisionIdentityRow(
    const FheIndRevisionSelection& selection) {
    const auto n = selection.cell.axes.find("n");
    const auto u = selection.cell.axes.find("u");
    if (n == selection.cell.axes.end() || u == selection.cell.axes.end()) {
        throw std::invalid_argument(
            "FHE-IND revision cell is missing n/u identity axes");
    }
    const uint64_t count = selection.plan.expected_rows.empty()
        ? 0u : selection.plan.expected_rows.front().measured_count;
    return "fhe-ind-revision-cell-v1," + selection.cell.cell_id + "," +
           n->second + "," + u->second + "," + std::to_string(count) +
           "\n";
}

std::string SerializeFheIndRevisionTerminalRow(
    const FheIndRevisionExecutionPlan& execution) {
    const auto identity = SerializeFheIndRevisionIdentityRow(
        execution.selection);
    const std::string without_newline = identity.substr(0, identity.size() - 1);
    return without_newline + ",DIAGNOSTIC,fhe_ind\n";
}

FheIndRevisionExecutionPlan PlanFheIndRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const FheIndRevisionRequest request = ParseFheIndRevisionArgs(argv);
    FheIndRevisionExecutionPlan execution;
    execution.selection = SelectFheIndRevisionCell(matrix, request, mode);
    execution.set_size = request.set_size;
    execution.universe = request.universe;
    execution.trial_count = request.trials;
    execution.selected_point_count = 1;
    execution.keygen_calls = 0;
    execution.native_sweep = false;
    return execution;
}

std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return {PlanFheIndRevisionExecution(matrix, argv, mode)};
}

std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    const RevisionRunMode mode) {
    return PlanFheIndExecutionSpy(matrix, argv, mode);
}

std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix) {
    const auto request = ParseFheIndRevisionArgs(argv);
    const RevisionRunMode mode =
        request.raw_timing_profile == "readiness-toy-v1"
            ? RevisionRunMode::Toy : RevisionRunMode::Paper;
    return PlanFheIndExecutionSpy(matrix, argv, mode);
}

}  // namespace piccard::benchmark
