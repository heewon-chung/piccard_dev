#include "sqrt_revision_adapter.h"

#include <charconv>
#include <limits>
#include <set>
#include <stdexcept>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid sqrt revision argv: " + reason);
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
bool ParseValue(const std::string& arg, const char* prefix, const char* field,
                std::set<std::string>& seen, Setter&& setter) {
    if (arg.rfind(prefix, 0) != 0) return false;
    std::string name(prefix);
    if (!name.empty() && name.back() == '=') name.pop_back();
    MarkSeen(seen, name);
    const std::string value = arg.substr(std::string(prefix).size());
    if (value.empty()) Reject(std::string(field) + " must not be empty");
    setter(value);
    return true;
}

void RequireSeen(const std::set<std::string>& seen, const char* name) {
    if (seen.find(name) == seen.end()) Reject(std::string("missing ") + name);
}

std::string RoleForAxis(const std::string& axis) {
    if (axis == "timing_m") return "timing";
    if (axis == "accuracy_m") return "accuracy";
    if (axis == "ciphertext_m") return "ciphertext";
    if (axis == "crossover_m") return "crossover";
    Reject("unsupported canonical sqrt axis");
}

}  // namespace

std::vector<std::string> CanonicalizeSqrtRevisionPlannerArgv(
    const std::vector<std::string>& argv) {
    std::vector<std::string> canonical;
    canonical.reserve(argv.size());
    for (const std::string& arg : argv) {
        if (arg.rfind("--seed=", 0) != 0) {
            canonical.push_back(arg);
            continue;
        }

        const std::string value = arg.substr(std::string("--seed=").size());
        if (value == "{seed}") {
            canonical.push_back(arg);
            continue;
        }
        // ParseUnsigned rejects empty, signed, non-decimal, zero, and
        // non-canonical values before any producer setup can begin.
        (void)ParseUnsigned(value, "--seed");
        canonical.emplace_back("--seed={seed}");
    }
    return canonical;
}

SqrtRevisionRequest ParseSqrtRevisionArgs(
    const std::vector<std::string>& argv) {
    SqrtRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& arg : argv) {
        if (ParseValue(arg, "--revision-cell=", "--revision-cell", seen,
                       [&](const std::string& value) {
                           request.revision_cell = value;
                       }) ||
            ParseValue(arg, "--profile=", "--profile", seen,
                       [&](const std::string& value) { request.profile = value; }) ||
            ParseValue(arg, "--cell=", "--cell", seen,
                       [&](const std::string& value) { request.cell = value; }) ||
            ParseValue(arg, "--mode=", "--mode", seen,
                       [&](const std::string& value) { request.mode = value; }) ||
            ParseValue(arg, "--security=", "--security", seen,
                       [&](const std::string& value) {
                           request.security = value;
                       }) ||
            ParseValue(arg, "--seed=", "--seed", seen,
                       [&](const std::string& value) { request.seed = value; })) {
            continue;
        }

        uint64_t value = 0;
        if (ParseValue(arg, "--k=", "--k", seen,
                       [&](const std::string& text) {
                           value = ParseUnsigned(text, "--k");
                       })) {
            if (value > std::numeric_limits<uint32_t>::max()) {
                Reject("--k is out of range");
            }
            request.k = static_cast<uint32_t>(value);
            continue;
        }
        if (ParseValue(arg, "--m=", "--m", seen,
                       [&](const std::string& text) {
                           value = ParseUnsigned(text, "--m");
                       })) {
            if (value > std::numeric_limits<uint32_t>::max()) {
                Reject("--m is out of range");
            }
            request.m = static_cast<uint32_t>(value);
            continue;
        }
        if (ParseValue(arg, "--set_size=", "--set_size", seen,
                       [&](const std::string& text) {
                           request.set_size = ParseUnsigned(text, "--set_size");
                       }) ||
            ParseValue(arg, "--universe=", "--universe", seen,
                       [&](const std::string& text) {
                           request.universe = ParseUnsigned(text, "--universe");
                       }) ||
            ParseValue(arg, "--trials=", "--trials", seen,
                       [&](const std::string& text) {
                           request.trials = ParseUnsigned(text, "--trials");
                       })) {
            continue;
        }
        Reject("unknown option " + arg);
    }

    for (const char* name : {"--revision-cell", "--profile", "--cell",
                             "--mode", "--security", "--k", "--m",
                             "--set_size", "--universe", "--trials",
                             "--seed"}) {
        RequireSeen(seen, name);
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (request.profile != "paper-std128-t40-v1" &&
        request.profile != "readiness-toy-v1") {
        Reject("unsupported --profile");
    }
    if (request.mode != "timing" && request.mode != "accuracy" &&
        request.mode != "ciphertext" && request.mode != "crossover") {
        Reject("unsupported --mode");
    }
    if (request.security !=
        (request.profile == "readiness-toy-v1" ? "TOY" : "STD128")) {
        Reject("--security conflicts with --profile");
    }
    if (request.trials == 0) Reject("--trials must be positive");
    return request;
}

SqrtRevisionSelection SelectSqrtRevisionCell(
    const RevisionMatrix& matrix, const SqrtRevisionRequest& request,
    RevisionRunMode mode) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != request.revision_cell) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");
    RevisionInvocationPlan plan = PlanSqrtRevisionCell(*selected, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }
    return {*selected, std::move(plan)};
}

SqrtRevisionSelection SelectSqrtRevisionCell(
    const RevisionMatrix& matrix, const std::vector<std::string>& argv,
    RevisionRunMode mode) {
    return SelectSqrtRevisionCell(
        matrix, ParseSqrtRevisionArgs(
                    CanonicalizeSqrtRevisionPlannerArgv(argv)),
        mode);
}

SqrtRevisionExecutionPlan PlanSqrtRevisionExecution(
    const RevisionMatrix& matrix, const std::vector<std::string>& argv,
    RevisionRunMode mode) {
    const std::vector<std::string> canonical_argv =
        CanonicalizeSqrtRevisionPlannerArgv(argv);
    const SqrtRevisionRequest request = ParseSqrtRevisionArgs(canonical_argv);
    SqrtRevisionExecutionPlan execution;
    execution.selection = SelectSqrtRevisionCell(matrix, request, mode);
    execution.role = RoleForAxis(execution.selection.cell.axis);
    execution.point = {
        execution.selection.cell.axis,
        request.k,
        request.m,
        static_cast<std::size_t>(request.set_size),
        static_cast<uint32_t>(request.universe),
        0.5};
    execution.selected_point_count = 1;
    execution.onehot_runs = execution.selection.plan.expected_rows.at(0).measured_count;
    execution.sqrt_applicable = IsSqrtRevisionArmApplicable(execution.selection.cell);
    execution.sqrt_runs = execution.sqrt_applicable
        ? execution.selection.plan.expected_rows.at(1).measured_count : 0;
    execution.native_sweep = false;
    return execution;
}

bool IsSqrtRevisionArmApplicable(const RevisionCell& cell) {
    if (cell.family != "sqrt_comparison") {
        throw std::invalid_argument("sqrt arm applicability requires sqrt cell");
    }
    const auto it = cell.axes.find("m");
    if (it == cell.axes.end()) throw std::invalid_argument("sqrt cell missing m");
    return it->second == "16" || it->second == "64" || it->second == "256";
}

std::string SqrtRevisionArmReason(const RevisionCell& cell) {
    if (IsSqrtRevisionArmApplicable(cell)) return {};
    return "sqrt-m-not-perfect-square";
}

}  // namespace piccard::benchmark
