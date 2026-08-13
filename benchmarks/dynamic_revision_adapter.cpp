#include "dynamic_revision_adapter.h"

#include <charconv>
#include <filesystem>
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

void RejectRuntime(const std::string& reason) {
    throw std::invalid_argument("invalid dynamic successor runtime argv: " +
                                reason);
}

void RequireConcretePath(const std::string& value, const char* field) {
    if (value.empty()) {
        RejectRuntime(std::string(field) + " must not be empty");
    }
    if (value.find('{') != std::string::npos ||
        value.find('}') != std::string::npos) {
        RejectRuntime(std::string(field) + " must be a concrete path");
    }
    const std::filesystem::path path(value);
    if (!path.is_absolute() || path == path.root_path()) {
        RejectRuntime(std::string(field) + " must be an absolute non-root path");
    }
}

std::string RuntimeValue(const std::string& argument, const char* prefix) {
    return argument.substr(std::char_traits<char>::length(prefix));
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

std::vector<std::string> CanonicalizeDynamicRevisionPlannerArgv(
    const std::vector<std::string>& argv) {
    std::vector<std::string> canonical;
    canonical.reserve(argv.size());
    for (const std::string& argument : argv) {
        if (argument.rfind("--seed=", 0) == 0) {
            const std::string value = RuntimeValue(argument, "--seed=");
            if (value == "{seed}") {
                canonical.push_back(argument);
            } else {
                (void)ParseUnsigned(value, "--seed");
                canonical.emplace_back("--seed={seed}");
            }
            continue;
        }

        const bool hyphen_path = argument.rfind("--raw-timing-dir=", 0) == 0;
        const bool underscore_path =
            argument.rfind("--raw_timing_dir=", 0) == 0;
        if (hyphen_path || underscore_path) {
            const char* prefix = hyphen_path ? "--raw-timing-dir="
                                              : "--raw_timing_dir=";
            const std::string value = RuntimeValue(argument, prefix);
            if (value == "{output}/raw") {
                canonical.emplace_back("--raw-timing-dir={output}/raw");
            } else {
                RequireConcretePath(value, "--raw-timing-dir");
                canonical.emplace_back("--raw-timing-dir={output}/raw");
            }
            continue;
        }
        canonical.push_back(argument);
    }
    return canonical;
}

DynamicRevisionCliOptions ParseDynamicRevisionCliOptions(
    const std::vector<std::string>& argv) {
    DynamicRevisionCliOptions options;
    bool identity_seen = false;
    bool seed_seen = false;
    bool raw_timing_seen = false;
    std::string cell;

    // Legacy invocations retain their historical permissive handling.  Only
    // a revision-cell invocation enters the strict runtime-materialization
    // boundary below; this keeps ordinary --seed/--raw-timing-dir runs
    // byte-for-byte compatible with the pre-successor CLI.
    bool successor_requested = false;
    size_t legacy_identity_count = 0;
    std::string legacy_identity_value;
    for (const std::string& argument : argv) {
        if (argument.rfind("--revision-cell=", 0) == 0) {
            successor_requested = true;
        }
        if (argument.rfind("--revision-identity-out=", 0) == 0) {
            ++legacy_identity_count;
            if (legacy_identity_count == 1) {
                legacy_identity_value =
                    RuntimeValue(argument, "--revision-identity-out=");
            }
        }
    }
    if (!successor_requested) {
        if (legacy_identity_count > 1) {
            throw std::invalid_argument(
                "duplicate --revision-identity-out");
        }
        if (legacy_identity_count == 1 && legacy_identity_value.empty()) {
            throw std::invalid_argument(
                "--revision-identity-out must not be empty");
        }
        if (legacy_identity_count == 1) {
            throw std::invalid_argument(
                "--revision-identity-out requires --revision-cell");
        }
        options.planner_argv.clear();
        return options;
    }
    identity_seen = false;

    for (const std::string& argument : argv) {
        if (argument.rfind("--revision-cell=", 0) == 0) {
            options.enabled = true;
            options.planner_argv.push_back(argument);
            continue;
        }
        if (argument.rfind("--revision-identity-out=", 0) == 0) {
            if (identity_seen) {
                RejectRuntime("duplicate --revision-identity-out");
            }
            identity_seen = true;
            options.identity_output =
                RuntimeValue(argument, "--revision-identity-out=");
            RequireConcretePath(options.identity_output,
                                "--revision-identity-out");
            continue;
        }

        if (argument.rfind("--seed=", 0) == 0) {
            if (seed_seen) RejectRuntime("duplicate --seed");
            seed_seen = true;
            const std::string value = RuntimeValue(argument, "--seed=");
            if (value == "{seed}") {
                RejectRuntime("--seed must be a concrete runtime value");
            }
            options.runtime_seed = ParseUnsigned(value, "--seed");
            options.planner_argv.push_back(argument);
            continue;
        }

        const bool hyphen_path = argument.rfind("--raw-timing-dir=", 0) == 0;
        const bool underscore_path =
            argument.rfind("--raw_timing_dir=", 0) == 0;
        if (hyphen_path || underscore_path) {
            if (raw_timing_seen) {
                RejectRuntime("duplicate --raw-timing-dir");
            }
            raw_timing_seen = true;
            const char* prefix = hyphen_path ? "--raw-timing-dir="
                                              : "--raw_timing_dir=";
            options.raw_timing_dir = RuntimeValue(argument, prefix);
            if (options.raw_timing_dir == "{output}/raw") {
                RejectRuntime("--raw-timing-dir must be a concrete path");
            }
            RequireConcretePath(options.raw_timing_dir, "--raw-timing-dir");
            options.planner_argv.push_back(argument);
            continue;
        }

        if (argument.rfind("--cell=", 0) == 0) {
            cell = RuntimeValue(argument, "--cell=");
        }
        options.planner_argv.push_back(argument);
    }

    if (!options.enabled) {
        if (identity_seen) {
            throw std::invalid_argument(
                "--revision-identity-out requires --revision-cell");
        }
        options.planner_argv.clear();
        return options;
    }
    if (!identity_seen) {
        throw std::invalid_argument(
            "successor --revision-cell requires --revision-identity-out");
    }
    if (!seed_seen) RejectRuntime("missing --seed");
    if ((cell == "timing" || cell == "refresh") && !raw_timing_seen) {
        RejectRuntime("missing --raw-timing-dir");
    }
    if (cell == "accuracy" && raw_timing_seen) {
        RejectRuntime("accuracy successor must not request raw timing");
    }

    options.planner_argv =
        CanonicalizeDynamicRevisionPlannerArgv(options.planner_argv);
    return options;
}

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
