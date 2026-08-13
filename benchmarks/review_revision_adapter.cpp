#include "review_revision_adapter.h"

#include <algorithm>
#include <charconv>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid review revision argv: " + reason);
}

uint64_t ParsePositive(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '+' || value.front() == '-' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(),
                                        parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed == 0 || std::to_string(parsed) != value) {
        Reject(std::string(field) + " must be a positive canonical integer");
    }
    return parsed;
}

void MarkSeen(std::set<std::string>& seen, const std::string& name) {
    if (!seen.insert(name).second) Reject("duplicate " + name);
}

std::vector<std::string> SplitMethods(const std::string& value) {
    if (value.empty()) Reject("--methods must not be empty");
    std::vector<std::string> methods;
    size_t begin = 0;
    while (true) {
        const size_t comma = value.find(',', begin);
        const std::string method = value.substr(begin, comma - begin);
        if (method.empty()) Reject("--methods contains an empty method");
        methods.push_back(method);
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    return methods;
}

bool IsSupportedFamily(const std::string& family) {
    return family == "bcg12_minhash" || family == "bcg12_exact" ||
           family == "sj16" || family == "piccard_std192_encoding";
}

bool IsEncodingFamily(const std::string& family) {
    return family == "piccard_std192_encoding";
}

void RequireSeen(const std::set<std::string>& seen, const char* name) {
    if (!seen.count(name)) Reject(std::string("missing ") + name);
}

std::string JoinMethods(const std::vector<std::string>& methods) {
    std::ostringstream out;
    for (size_t i = 0; i < methods.size(); ++i) {
        if (i != 0) out << ',';
        out << methods[i];
    }
    return out.str();
}

bool IsSquare(uint64_t value) {
    if (value == 0) return false;
    uint64_t root = 1;
    while (root <= value / root && root * root < value) ++root;
    return root * root == value;
}

const RevisionCell* FindCell(const RevisionMatrix& matrix,
                             const std::string& cell_id) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != cell_id) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");
    return selected;
}

}  // namespace

ReviewRevisionRequest ParseReviewRevisionArgs(
    const std::vector<std::string>& argv) {
    ReviewRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& arg : argv) {
        const size_t equals = arg.find('=');
        if (equals == std::string::npos || equals == 0 ||
            arg.front() != '-') {
            Reject("malformed option " + arg);
        }
        const std::string key = arg.substr(0, equals);
        const std::string value = arg.substr(equals + 1);
        if (value.empty()) Reject(key + " must not be empty");
        MarkSeen(seen, key);

        if (key == "--revision-cell") request.revision_cell = value;
        else if (key == "--profile") request.profile = value;
        else if (key == "--suite") request.suite = value;
        else if (key == "--cell") request.cell = value;
        else if (key == "--method") request.method = value;
        else if (key == "--methods") request.methods = SplitMethods(value);
        else if (key == "--security") request.security = value;
        else if (key == "--seed") request.seed = value;
        else if (key == "--output") request.output = value;
        else if (key == "--k") request.k = ParsePositive(value, "--k");
        else if (key == "--m") request.m = ParsePositive(value, "--m");
        else if (key == "--n") request.set_size = ParsePositive(value, "--n");
        else if (key == "--universe") request.universe = ParsePositive(value, "--universe");
        else if (key == "--trials") request.trials = ParsePositive(value, "--trials");
        else if (key == "--accuracy-trials") {
            request.accuracy_trials = ParsePositive(value, "--accuracy-trials");
        } else if (key == "--encoding-iters") {
            request.encoding_iters = ParsePositive(value, "--encoding-iters");
        } else if (key == "--correctness-trials") {
            request.correctness_trials = ParsePositive(value, "--correctness-trials");
        } else if (key == "--key-bits") {
            request.key_bits = ParsePositive(value, "--key-bits");
        } else if (key == "--threads") {
            request.threads = ParsePositive(value, "--threads");
        } else if (key == "--warmup") {
            // The precomputed SJ16 review point has one discarded warmup;
            // exact planner-byte matching below binds its literal value.
            static_cast<void>(ParsePositive(value, "--warmup"));
        } else {
            Reject("unknown option " + arg);
        }
    }

    for (const char* required : {"--revision-cell", "--profile",
                                 "--k", "--m", "--n", "--universe",
                                 "--seed", "--output"}) {
        RequireSeen(seen, required);
    }
    if (!seen.count("--suite") && !seen.count("--cell")) {
        Reject("missing --suite or --cell");
    }
    if (request.profile != "paper-v1" &&
        request.profile != "readiness-toy-v1" &&
        request.profile != "paper-std192-encoding-v1") {
        Reject("unsupported --profile");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (request.output != "{output}/comparison.csv" &&
        request.output != "{output}/encoding.csv") {
        Reject("--output must use the canonical {output} placeholder");
    }
    return request;
}

ReviewRevisionSelection SelectReviewRevisionCell(
    const RevisionMatrix& matrix,
    const ReviewRevisionRequest& request,
    const RevisionRunMode mode) {
    const RevisionCell* selected = FindCell(matrix, request.revision_cell);
    if (!IsSupportedFamily(selected->family)) {
        Reject("family is not owned by bench_review_comparison: " +
               selected->family);
    }
    if (selected->producer != "bench_review_comparison") {
        Reject("producer is not bench_review_comparison");
    }
    if (selected->invocation_status != "RUN") {
        Reject("NO_SPAWN/non-RUN cell must be handled by the orchestrator");
    }
    if (selected->family == "sj16" && selected->axis == "fit" &&
        selected->axis_value == "per_element") {
        Reject("SJ16 per-element calibration belongs to bench_sj16_calibrate");
    }

    const RevisionInvocationPlan plan = PlanRevisionCell(*selected, mode);
    if (plan.argv.empty()) {
        Reject("selected cell has no producer argv (orchestrator-only)");
    }
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }

    return { *selected, plan };
}

ReviewRevisionSelection SelectReviewRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return SelectReviewRevisionCell(matrix, ParseReviewRevisionArgs(argv), mode);
}

ReviewRevisionExecutionPlan PlanReviewRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const ReviewRevisionRequest request = ParseReviewRevisionArgs(argv);
    ReviewRevisionExecutionPlan execution;
    execution.selection = SelectReviewRevisionCell(matrix, request, mode);

    const RevisionCell& cell = execution.selection.cell;
    const bool toy = mode == RevisionRunMode::Toy;
    const bool encoding = IsEncodingFamily(cell.family);
    execution.concrete_profile = toy
        ? "readiness-toy-v1"
        : (encoding ? "paper-std192-encoding-v1" : "std128-t40-primary");
    execution.concrete_suite = cell.family;
    execution.concrete_security = toy ? "TOY" : (encoding ? "STD192" : "STD128");
    execution.concrete_methods = request.methods;
    if (execution.concrete_methods.empty() && !request.method.empty()) {
        execution.concrete_methods.push_back(request.method);
    }
    if (execution.concrete_methods.empty()) {
        Reject("selected review cell has no method");
    }
    if (encoding && !IsSquare(request.m)) {
        execution.concrete_methods.erase(
            std::remove(execution.concrete_methods.begin(),
                        execution.concrete_methods.end(),
                        "piccard_sqrt_encode"),
            execution.concrete_methods.end());
    }
    if (execution.concrete_methods.empty()) {
        Reject("non-square encoding cell has no applicable method");
    }
    execution.timing_trials = encoding ? request.encoding_iters : request.trials;
    execution.accuracy_trials = 0;
    execution.set_size = request.set_size;
    execution.universe = request.universe;
    execution.selected_point_count = 1;
    execution.producer_must_spawn = true;

    if (execution.timing_trials == 0 ||
        execution.timing_trials !=
            execution.selection.plan.expected_rows.front().measured_count) {
        Reject("concrete timing count does not match the selected terminal row");
    }
    if (request.accuracy_trials != 0 ||
        (encoding ? request.correctness_trials != 1
                  : request.correctness_trials != 0)) {
        Reject(encoding
                   ? "encoding cell requires exactly one correctness trial"
                   : "review baseline cell must not add an accuracy arm");
    }
    return execution;
}

std::vector<std::string> MakeConcreteReviewArgs(
    const ReviewRevisionExecutionPlan& execution) {
    const ReviewRevisionRequest request = ParseReviewRevisionArgs(
        execution.selection.plan.argv);
    std::vector<std::string> args = {
        "--suite=" + execution.concrete_suite,
        "--profile=" + execution.concrete_profile,
        "--security=" + execution.concrete_security,
        "--k=" + std::to_string(request.k),
        "--m=" + std::to_string(request.m),
        "--set-size=" + std::to_string(execution.set_size),
        "--universe=" + std::to_string(execution.universe),
        "--target-jaccard=0.5",
        "--trials=" + std::to_string(execution.timing_trials),
        "--accuracy-trials=0",
        "--seed={seed}",
        "--methods=" + JoinMethods(execution.concrete_methods),
        "--sj16-key-bits=3072",
        "--diagnostic-security",
        "--manifest-out={output}/workload.bin",
        "--execution-trace-out={output}/execution-trace.bin",
    };
    return args;
}

bool ReviewSqrtEncodingApplicable(
    const ReviewRevisionExecutionPlan& execution) {
    if (!IsEncodingFamily(execution.selection.cell.family)) return false;
    const auto it = execution.selection.cell.axes.find("m");
    if (it == execution.selection.cell.axes.end()) return false;
    uint32_t m = 0;
    const auto result = std::from_chars(it->second.data(),
                                        it->second.data() + it->second.size(), m);
    return result.ec == std::errc{} &&
           result.ptr == it->second.data() + it->second.size() &&
           IsSquare(m);
}

}  // namespace piccard::benchmark
