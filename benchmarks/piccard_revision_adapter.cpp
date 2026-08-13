#include "piccard_revision_adapter.h"

#include <charconv>
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

}  // namespace piccard::benchmark
