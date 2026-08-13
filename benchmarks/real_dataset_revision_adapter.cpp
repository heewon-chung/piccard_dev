#include "real_dataset_revision_adapter.h"

#include "data/real_dataset.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& message) {
    throw std::invalid_argument("invalid real-dataset revision argv: " +
                                message);
}

std::pair<std::string, std::string> SplitOption(const std::string& arg) {
    if (arg.empty() || arg.front() != '-' || arg.find('=') == std::string::npos) {
        Reject("every successor option must be --name=value");
    }
    const size_t equals = arg.find('=');
    if (equals < 3 || equals + 1 == arg.size()) {
        Reject("option name and value must not be empty");
    }
    return {arg.substr(0, equals), arg.substr(equals + 1)};
}

bool IsDecimal(const std::string& value) {
    return !value.empty() &&
           value.find_first_not_of("0123456789") == std::string::npos;
}

bool IsPathOption(const std::string& option) {
    return option == "--dataset-manifest" || option == "--csv" ||
           option == "--workload-manifest-out" ||
           option == "--workload-rows-out" || option == "--raw-timing-dir" ||
           option == "--accuracy-csv" || option == "--output";
}

bool IsSeedOption(const std::string& option) {
    return option == "--seed";
}

bool IsCountPlaceholderOption(const std::string& option) {
    return option == "--max-pairs";
}

std::string ExpectedValueFor(const std::vector<std::string>& plan,
                             const std::string& option) {
    std::string result;
    for (const std::string& arg : plan) {
        const auto split = SplitOption(arg);
        if (split.first != option) continue;
        if (!result.empty()) Reject("canonical plan contains duplicate " + option);
        result = split.second;
    }
    return result;
}

std::string CanonicalPathValue(const std::string& option,
                               const std::string& actual,
                               const std::string& expected) {
    if (expected.empty()) return actual;
    if (actual == expected) return expected;

    // The planner's manifest token also carries the expected variant in the
    // threshold case.  The actual file is bound separately by
    // ValidateRealDatasetRevisionManifest; replacing only its spelling here
    // keeps exact argv selection independent of the temporary result root.
    if (option == "--dataset-manifest") return expected;

    if (expected.rfind("{output}/", 0) == 0) {
        const std::string suffix = expected.substr(std::string("{output}/").size());
        if (actual.size() >= suffix.size() &&
            actual.compare(actual.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return expected;
        }
        if (option == "--raw-timing-dir" &&
            actual.size() >= 4 && actual.compare(actual.size() - 4, 4, "/raw") == 0) {
            return expected;
        }
        Reject(option + " must resolve to the canonical output suffix " + suffix);
    }
    Reject(option + " does not match the canonical planner path");
}

std::string CanonicalValue(const std::string& option,
                           const std::string& actual,
                           const std::string& expected) {
    if (expected.empty()) Reject("option is not present in the canonical plan: " + option);
    if (actual.empty()) Reject(option + " value must not be empty");
    if (IsPathOption(option)) return CanonicalPathValue(option, actual, expected);
    if (IsSeedOption(option) && expected == "{seed}") {
        if (actual == "{seed}" || IsDecimal(actual)) return expected;
        Reject("--seed must be a decimal value or {seed}");
    }
    if (IsCountPlaceholderOption(option) && expected == "{max_pairs}") {
        if (actual == "{max_pairs}" || IsDecimal(actual)) return expected;
        Reject("--max-pairs must be a decimal value or {max_pairs}");
    }
    if (actual != expected) {
        Reject(option + " does not match the canonical planner value");
    }
    return expected;
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

RevisionInvocationPlan PlanSupportedCell(const RevisionCell& cell,
                                         const RevisionRunMode mode) {
    if (cell.family == "real_dataset") {
        return PlanRealDatasetRevisionCell(cell, mode);
    }
    if (cell.family == "threshold_dblp_fpfn") {
        return PlanThresholdRevisionCell(cell, mode);
    }
    Reject("cell is not a supported real-data producer family");
}

std::string RequiredAxis(const RevisionCell& cell, const char* axis) {
    const auto it = cell.axes.find(axis);
    if (it == cell.axes.end() || it->second.empty()) {
        Reject(std::string("cell is missing axis ") + axis);
    }
    return it->second;
}

}  // namespace

RealDatasetRevisionRequest ParseRealDatasetRevisionArgs(
    const std::vector<std::string>& argv) {
    RealDatasetRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;
    static const std::set<std::string> allowed = {
        "--revision-cell", "--mode", "--dataset-manifest", "--profile",
        "--security", "--k", "--m", "--max-pairs", "--accuracy_trials",
        "--trials", "--threshold-trials", "--seed", "--hash_randomness",
        "--csv", "--workload-manifest-out", "--workload-rows-out",
        "--raw-timing-dir", "--raw-timing-profile", "--methods",
        "--encoding-iters", "--correctness-trials", "--timing-pair",
        "--method", "--cell", "--accuracy-csv", "--output", "--variant"};

    for (const std::string& arg : argv) {
        const auto split = SplitOption(arg);
        if (allowed.find(split.first) == allowed.end()) {
            Reject("unknown option " + split.first);
        }
        if (!seen.insert(split.first).second) {
            Reject("duplicate " + split.first);
        }
        if (split.first == "--revision-cell") request.revision_cell = split.second;
        if (split.first == "--mode") request.mode = split.second;
    }
    if (request.revision_cell.empty()) Reject("missing --revision-cell");
    return request;
}

std::vector<std::string> CanonicalizeRealDatasetRevisionArgs(
    const std::vector<std::string>& argv,
    const std::vector<std::string>& canonical_plan_argv) {
    const RealDatasetRevisionRequest request =
        ParseRealDatasetRevisionArgs(argv);
    std::vector<std::string> canonical;
    canonical.reserve(argv.size());
    for (const std::string& arg : argv) {
        const auto split = SplitOption(arg);
        const std::string expected = ExpectedValueFor(canonical_plan_argv, split.first);
        if (split.first == "--revision-cell") {
            if (split.second != request.revision_cell) Reject("cell ID changed during canonicalization");
            canonical.push_back(arg);
        } else {
            canonical.push_back(split.first + "=" +
                               CanonicalValue(split.first, split.second, expected));
        }
    }
    return canonical;
}

RealDatasetRevisionSelection SelectRealDatasetRevisionCell(
    const RevisionMatrix& matrix,
    const RealDatasetRevisionRequest& request,
    const RevisionRunMode mode) {
    const RevisionCell* selected = FindCell(matrix, request.revision_cell);
    const RevisionInvocationPlan plan = PlanSupportedCell(*selected, mode);
    if (request.mode != "" &&
        ((selected->family == "real_dataset" && selected->axis_value != "summary" &&
          request.mode != (selected->axis_value == "std128_timing" ? "timing" :
                           selected->axis_value == "std192_encoding" ? "encoding" :
                           "accuracy")) ||
         (selected->family == "threshold_dblp_fpfn" && request.mode != "threshold"))) {
        Reject("--mode does not match the selected cell");
    }
    const std::vector<std::string> canonical =
        CanonicalizeRealDatasetRevisionArgs(request.argv, plan.argv);
    if (canonical != plan.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }
    return { *selected, plan };
}

RealDatasetRevisionSelection SelectRealDatasetRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return SelectRealDatasetRevisionCell(
        matrix, ParseRealDatasetRevisionArgs(argv), mode);
}

bool IsRealDatasetSummaryCell(const RevisionCell& cell) {
    return cell.family == "real_dataset" && cell.axis_value == "summary";
}

void ValidateRealDatasetRevisionManifest(
    const RevisionCell& cell,
    const std::filesystem::path& manifest_path) {
    if (cell.family != "real_dataset" && cell.family != "threshold_dblp_fpfn") {
        Reject("manifest binding requires a real-data or DBLP threshold cell");
    }
    const std::string path_text = manifest_path.string();
    if (path_text.empty() || path_text.find('{') != std::string::npos ||
        path_text.find('}') != std::string::npos) {
        Reject("dataset manifest must be a concrete path before producer dispatch");
    }
    const data::RealDataset dataset = data::LoadRealDataset(manifest_path);
    const std::string expected_variant =
        cell.family == "threshold_dblp_fpfn"
            ? RequiredAxis(cell, "variant")
            : RequiredAxis(cell, "variant");
    const std::string expected_dataset =
        cell.family == "threshold_dblp_fpfn" ? "dblp_acm" : cell.dataset;
    const uint64_t expected_universe =
        std::stoull(RequiredAxis(cell, "u"));
    if (dataset.dataset != expected_dataset || dataset.variant != expected_variant ||
        dataset.universe_size != expected_universe) {
        Reject("processed manifest dataset/variant/universe does not match cell");
    }
    if (cell.family == "threshold_dblp_fpfn") {
        if (expected_variant != "dblp_acm_u65536") {
            Reject("DBLP threshold cell is the only supported real threshold");
        }
        for (const auto& pair : dataset.pairs) {
            if (pair.label != 0 && pair.label != 1) {
                Reject("threshold manifest labels must be 0 or 1; -1 is not admissible");
            }
        }
    }
}

RealDatasetRevisionExecutionPlan PlanRealDatasetRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const RealDatasetRevisionSelection selection =
        SelectRealDatasetRevisionCell(matrix, argv, mode);
    if (IsRealDatasetSummaryCell(selection.cell)) {
        Reject("summary cell is owned by summarize_real_datasets.py, not bench_real_datasets");
    }
    RealDatasetRevisionExecutionPlan execution;
    execution.selection = selection;
    execution.artifact = selection.cell.axis_value;
    execution.dataset = selection.cell.dataset;
    execution.variant = RequiredAxis(selection.cell, "variant");
    execution.concrete_profile = selection.plan.concrete_profile;
    execution.selected_cell_count = 1;
    execution.expected_row_count = selection.plan.expected_rows.size();
    execution.keygen_calls = 0;
    execution.encoding_only = execution.artifact == "std192_encoding";
    execution.native_sweep = false;
    if (execution.expected_row_count != 1u) {
        Reject("real-data revision cells require exactly one expected row");
    }
    return execution;
}

std::vector<RealDatasetRevisionExecutionPlan>
PlanRealDatasetRevisionExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return {PlanRealDatasetRevisionExecution(matrix, argv, mode)};
}

}  // namespace piccard::benchmark
