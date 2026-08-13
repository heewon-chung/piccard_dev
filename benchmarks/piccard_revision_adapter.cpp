#include "piccard_revision_adapter.h"

#include <charconv>
#include <cmath>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid Piccard revision argv: " + reason);
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
    if (!seen.insert(name).second) {
        Reject("duplicate " + name);
    }
}

template <typename Setter>
void ParseValue(const std::string& arg,
                const char* prefix,
                const char* field,
                std::set<std::string>& seen,
                Setter&& setter) {
    if (arg.rfind(prefix, 0) != 0) return;
    std::string name(prefix);
    name.pop_back();
    MarkSeen(seen, name);
    const std::string value = arg.substr(std::string(prefix).size());
    if (value.empty()) Reject(std::string(field) + " must not be empty");
    setter(value);
}

void RequireSeen(const std::set<std::string>& seen, const char* name) {
    if (seen.find(name) == seen.end()) Reject(std::string("missing ") + name);
}

}  // namespace

PiccardRevisionRequest ParsePiccardRevisionArgs(
    const std::vector<std::string>& argv) {
    PiccardRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& arg : argv) {
        if (arg == "--evidence_point") {
            MarkSeen(seen, "--evidence_point");
            request.evidence_point = true;
            continue;
        }

        bool recognized = false;
        auto parse_string = [&](const char* prefix, const char* field,
                                std::string& destination) {
            if (arg.rfind(prefix, 0) != 0) return;
            recognized = true;
            ParseValue(arg, prefix, field, seen,
                        [&](const std::string& value) { destination = value; });
        };
        auto parse_unsigned = [&](const char* prefix, const char* field,
                                  uint64_t& destination) {
            if (arg.rfind(prefix, 0) != 0) return;
            recognized = true;
            ParseValue(arg, prefix, field, seen,
                        [&](const std::string& value) {
                            destination = ParseUnsigned(value, field);
                        });
        };

        parse_string("--revision-cell=", "--revision-cell",
                     request.revision_cell);
        parse_string("--profile=", "--profile", request.profile);
        parse_string("--mode=", "--mode", request.mode);
        parse_string("--security=", "--security", request.security);
        parse_string("--seed=", "--seed", request.seed);
        parse_string("--raw_timing_dir=", "--raw_timing_dir",
                     request.raw_timing_dir);

        const bool string_recognized = recognized;
        recognized = false;
        uint64_t parsed = 0;
        parse_unsigned("--k=", "--k", parsed);
        if (recognized) {
            if (parsed > std::numeric_limits<uint32_t>::max()) {
                Reject("--k is out of range");
            }
            request.k = static_cast<uint32_t>(parsed);
            continue;
        }
        parse_unsigned("--m=", "--m", parsed);
        if (recognized) {
            if (parsed > std::numeric_limits<uint32_t>::max()) {
                Reject("--m is out of range");
            }
            request.m = static_cast<uint32_t>(parsed);
            continue;
        }
        parse_unsigned("--set_size=", "--set_size", request.set_size);
        if (recognized) continue;
        parse_unsigned("--universe=", "--universe", request.universe);
        if (recognized) continue;
        parse_unsigned("--trials=", "--trials", request.trials);
        if (recognized) continue;
        parse_unsigned("--accuracy_trials=", "--accuracy_trials",
                       request.accuracy_trials);
        if (recognized) continue;

        if (!recognized && !string_recognized) {
            Reject("unknown option " + arg);
        }
    }

    for (const char* name : {"--revision-cell", "--profile", "--mode",
                             "--security", "--k", "--m", "--set_size",
                             "--universe", "--trials", "--accuracy_trials",
                             "--seed", "--raw_timing_dir"}) {
        RequireSeen(seen, name);
    }
    RequireSeen(seen, "--evidence_point");

    if (request.profile != "paper-std128-t40-v1" &&
        request.profile != "readiness-toy-v1") {
        Reject("unsupported --profile");
    }
    if (request.mode != "combined") Reject("--mode must be combined");
    if (request.evidence_point == false) {
        Reject("--evidence_point is required");
    }
    const bool toy = request.profile == "readiness-toy-v1";
    if (request.security != (toy ? "TOY" : "STD128")) {
        Reject("--security conflicts with --profile");
    }
    if (request.trials != (toy ? 1u : 30u) ||
        request.accuracy_trials != (toy ? 1u : 50u)) {
        Reject("trial counts conflict with --profile");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");
    if (request.raw_timing_dir != "{output}") {
        Reject("--raw_timing_dir must be {output}");
    }

    return request;
}

PiccardRevisionSelection SelectPiccardRevisionCell(
    const RevisionMatrix& matrix,
    const PiccardRevisionRequest& request,
    RevisionRunMode mode) {
    const RevisionCell* selected = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != request.revision_cell) continue;
        if (selected != nullptr) Reject("matrix contains duplicate cell ID");
        selected = &cell;
    }
    if (selected == nullptr) Reject("unknown --revision-cell");

    RevisionInvocationPlan plan = PlanPiccardRevisionCell(*selected, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }

    PiccardRevisionSelection selection;
    selection.cell = *selected;
    selection.axes = selected->axes;
    selection.plan = std::move(plan);
    return selection;
}

PiccardRevisionSelection SelectPiccardRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode) {
    return SelectPiccardRevisionCell(matrix, ParsePiccardRevisionArgs(argv),
                                     mode);
}

BoundedOverlapSets MakeBoundedOverlapSets(
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
    if (set_size > static_cast<uint64_t>(
                       std::numeric_limits<std::size_t>::max())) {
        Reject("set size is too large for this host");
    }
    if (set_size > std::numeric_limits<uint64_t>::max() / 2u) {
        Reject("set size overflows the union cardinality");
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
        Reject("universe is insufficient for the requested set union");
    }

    const uint64_t unique_a = set_size - intersection;
    // Place the canonical union at the beginning of the explicit universe.
    // This keeps the output deterministic without consuming process-global
    // randomness and makes the sorted/range invariant easy to audit.
    const uint64_t start = 0;
    const uint64_t unique_b_start = start + intersection + unique_a;

    BoundedOverlapSets workload;
    workload.set_a.reserve(static_cast<std::size_t>(set_size));
    workload.set_b.reserve(static_cast<std::size_t>(set_size));
    for (uint64_t index = 0; index < intersection; ++index) {
        workload.set_a.push_back(start + index);
        workload.set_b.push_back(start + index);
    }
    for (uint64_t index = 0; index < unique_a; ++index) {
        workload.set_a.push_back(start + intersection + index);
    }
    for (uint64_t index = 0; index < unique_a; ++index) {
        workload.set_b.push_back(unique_b_start + index);
    }
    workload.intersection_size = intersection;
    workload.union_size = union_size;
    workload.target_jaccard = target_jaccard;
    workload.realized_jaccard = static_cast<double>(intersection) /
                                static_cast<double>(union_size);
    return workload;
}

std::string PiccardRevisionIdentityHeader() {
    return "schema,cell_id,universe_size";
}

std::string SerializePiccardRevisionIdentity(
    const PiccardRevisionIdentity& identity) {
    if (identity.schema != "piccard-revision-cell-v1") {
        throw std::invalid_argument("Piccard revision schema mismatch");
    }
    if (identity.cell_id.empty() || identity.cell_id.find_first_of(",\n\r") !=
                                         std::string::npos) {
        throw std::invalid_argument("Piccard revision cell ID is malformed");
    }
    if (identity.universe_size == 0) {
        throw std::invalid_argument("Piccard revision universe must be positive");
    }
    return identity.schema + "," + identity.cell_id + "," +
           std::to_string(identity.universe_size);
}

std::string SerializePiccardRevisionIdentityHeader() {
    return PiccardRevisionIdentityHeader() + "\n";
}

std::string SerializePiccardRevisionIdentityRow(
    const PiccardRevisionSelection& selection) {
    return SerializePiccardRevisionIdentity(MakePiccardRevisionIdentity(
               selection)) +
           "\n";
}

PiccardRevisionExecutionPlan PlanPiccardRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    const PiccardRevisionRequest request = ParsePiccardRevisionArgs(argv);
    PiccardRevisionExecutionPlan execution;
    execution.selection = SelectPiccardRevisionCell(matrix, request, mode);
    execution.point = {
        "revision", request.k, request.m,
        static_cast<std::size_t>(request.set_size),
        static_cast<uint32_t>(request.universe), 0.5};
    execution.selected_point_count = 1;
    execution.keygen_calls = 0;
    execution.native_sweep = false;
    return execution;
}

std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    const RevisionRunMode mode) {
    return {PlanPiccardRevisionExecution(matrix, argv, mode)};
}

std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    const RevisionRunMode mode) {
    return PlanPiccardExecutionSpy(matrix, argv, mode);
}

std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix) {
    const PiccardRevisionRequest request = ParsePiccardRevisionArgs(argv);
    const RevisionRunMode mode =
        request.profile == "readiness-toy-v1" ? RevisionRunMode::Toy
                                               : RevisionRunMode::Paper;
    return PlanPiccardExecutionSpy(matrix, argv, mode);
}

std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv) {
    return PlanPiccardExecutionSpy(argv, matrix);
}

PiccardRevisionIdentity MakePiccardRevisionIdentity(
    const PiccardRevisionSelection& selection) {
    const auto it = selection.cell.axes.find("u");
    if (it == selection.cell.axes.end()) {
        throw std::invalid_argument(
            "Piccard revision cell is missing universe axis");
    }
    uint64_t universe = 0;
    const char* first = it->second.data();
    const char* last = first + it->second.size();
    const auto result = std::from_chars(first, last, universe);
    if (result.ec != std::errc{} || result.ptr != last || universe == 0) {
        throw std::invalid_argument(
            "Piccard revision universe axis is malformed");
    }
    return {"piccard-revision-cell-v1", selection.cell.cell_id, universe};
}

}  // namespace piccard::benchmark
