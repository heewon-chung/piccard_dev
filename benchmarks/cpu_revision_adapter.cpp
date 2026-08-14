#include "cpu_revision_adapter.h"

#include <charconv>
#include <initializer_list>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>

namespace piccard::benchmark {
namespace {

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid CPU revision argv: " + reason);
}

uint64_t ParseUnsigned(const std::string& value, const char* field,
                       bool allow_zero = false) {
    if (value.empty() || value.front() == '+' || value.front() == '-' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(),
                                        value.data() + value.size(), parsed);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size() ||
        std::to_string(parsed) != value || (!allow_zero && parsed == 0)) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    return parsed;
}

uint32_t ParseUint32(const std::string& value, const char* field,
                     bool allow_zero = false) {
    const uint64_t parsed = ParseUnsigned(value, field, allow_zero);
    if (parsed > std::numeric_limits<uint32_t>::max()) {
        Reject(std::string(field) + " exceeds uint32 range");
    }
    return static_cast<uint32_t>(parsed);
}

void MarkSeen(std::set<std::string>& seen, const std::string& name) {
    if (!seen.insert(name).second) Reject("duplicate " + name);
}

std::string Value(const std::string& argument, const char* prefix,
                  std::set<std::string>& seen) {
    if (argument.rfind(prefix, 0) != 0) return {};
    const std::string name(prefix, std::string(prefix).find('=') + 1);
    MarkSeen(seen, name.substr(0, name.size() - 1));
    const std::string value = argument.substr(std::string(prefix).size());
    if (value.empty()) Reject(name + " must not be empty");
    return value;
}

std::vector<uint32_t> ParseSizes(const std::string& value) {
    std::vector<uint32_t> result;
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t end = value.find(',', begin);
        const std::string token = value.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin);
        if (token.empty()) Reject("sizes contains an empty value");
        result.push_back(ParseUint32(token, "sizes"));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    if (result.empty()) Reject("sizes must not be empty");
    return result;
}

void Require(const std::set<std::string>& seen,
             std::initializer_list<const char*> fields) {
    for (const char* field : fields) {
        if (seen.find(field) == seen.end()) Reject(std::string("missing ") + field);
    }
}

void RejectUnexpected(const std::set<std::string>& seen,
                      std::initializer_list<const char*> fields) {
    const std::set<std::string> allowed(fields.begin(), fields.end());
    for (const std::string& field : seen) {
        if (allowed.find(field) == allowed.end()) {
            Reject("option " + field + " is not accepted by this producer");
        }
    }
}

bool IsOneOf(const std::string& value,
             std::initializer_list<const char*> choices) {
    for (const char* choice : choices) {
        if (value == choice) return true;
    }
    return false;
}

const RevisionCell* FindCell(const RevisionMatrix& matrix,
                             const std::string& cell_id) {
    const RevisionCell* result = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id != cell_id) continue;
        if (result != nullptr) Reject("matrix contains duplicate cell ID");
        result = &cell;
    }
    if (result == nullptr) Reject("unknown --revision-cell");
    return result;
}

RevisionInvocationPlan PlanFor(const RevisionCell& cell,
                               CpuRevisionProducer producer,
                               RevisionRunMode mode) {
    switch (producer) {
        case CpuRevisionProducer::EstimatorBias:
            return PlanEstimatorRevisionCell(cell, mode);
        case CpuRevisionProducer::DeletionSurvival:
            return PlanDeletionRevisionCell(cell, mode);
        case CpuRevisionProducer::Sj16Calibrate:
            return PlanSj16RevisionCell(cell, mode);
    }
    Reject("unknown CPU revision producer");
}

const char* ProducerName(CpuRevisionProducer producer) {
    switch (producer) {
        case CpuRevisionProducer::EstimatorBias: return "bench_estimator_bias";
        case CpuRevisionProducer::DeletionSurvival: return "bench_deletion_survival";
        case CpuRevisionProducer::Sj16Calibrate: return "bench_sj16_calibrate";
    }
    return "unknown";
}

}  // namespace

RevisionRunMode RevisionRunModeForProfile(const std::string& profile) {
    if (profile == "paper-v1") return RevisionRunMode::Paper;
    if (profile == "readiness-toy-v1") return RevisionRunMode::Toy;
    Reject("unsupported --profile");
}

CpuRevisionRequest ParseCpuRevisionArgs(
    const std::vector<std::string>& argv, CpuRevisionProducer producer) {
    CpuRevisionRequest request;
    request.argv = argv;
    std::set<std::string> seen;

    for (const std::string& argument : argv) {
        bool recognized = false;
        auto string_option = [&](const char* prefix, const char* field,
                                 std::string& destination) {
            if (argument.rfind(prefix, 0) != 0) return;
            recognized = true;
            destination = Value(argument, prefix, seen);
            (void)field;
        };
        auto integer_option = [&](const char* prefix, const char* field,
                                  uint64_t& destination, bool allow_zero = false) {
            if (argument.rfind(prefix, 0) != 0) return;
            recognized = true;
            destination = ParseUnsigned(Value(argument, prefix, seen), field,
                                        allow_zero);
        };
        auto uint32_option = [&](const char* prefix, const char* field,
                                 uint32_t& destination, bool allow_zero = false) {
            if (argument.rfind(prefix, 0) != 0) return;
            recognized = true;
            destination = ParseUint32(Value(argument, prefix, seen), field,
                                      allow_zero);
        };

        string_option("--revision-cell=", "revision-cell",
                      request.revision_cell);
        string_option("--profile=", "profile", request.profile);
        string_option("--cell=", "cell", request.cell);
        string_option("--jaccard-grid=", "jaccard-grid",
                      request.jaccard_grid);
        string_option("--seed=", "seed", request.seed);
        string_option("--output=", "output", request.output);
        string_option("--raw_timing_dir=", "raw-timing-dir",
                      request.raw_timing_dir);
        string_option("--raw_timing_profile=", "raw-timing-profile",
                      request.raw_timing_profile);
        integer_option("--k=", "k", request.k);
        integer_option("--m=", "m", request.m);
        integer_option("--set_size=", "set_size", request.set_size);
        integer_option("--universe=", "universe", request.universe);
        integer_option("--trials=", "trials", request.trials,
                       producer == CpuRevisionProducer::DeletionSurvival);
        integer_option("--query-trials=", "query-trials", request.query_trials);
        integer_option("--enc-iters=", "enc-iters", request.enc_iters);
        integer_option("--key-bits=", "key-bits", request.key_bits);
        integer_option("--warmup=", "warmup", request.warmup);
        uint32_option("--held-out=", "held-out", request.held_out);
        uint32_option("--threads=", "threads", request.threads);

        if (argument.rfind("--sizes=", 0) == 0) {
            recognized = true;
            request.sizes = ParseSizes(Value(argument, "--sizes=", seen));
        }
        if (argument == "--precomputed=false" ||
            argument == "--precomputed=true") {
            MarkSeen(seen, "--precomputed");
            request.precomputed = argument == "--precomputed=true";
            recognized = true;
        }
        if (!recognized) Reject("unknown option " + argument);
    }

    if (!IsOneOf(request.profile, {"paper-v1", "readiness-toy-v1"})) {
        Reject("unsupported --profile");
    }
    if (request.seed != "{seed}") Reject("--seed must be {seed}");

    switch (producer) {
        case CpuRevisionProducer::EstimatorBias:
            RejectUnexpected(seen, {"--revision-cell", "--profile", "--cell",
                                    "--k", "--m", "--set_size", "--universe",
                                    "--trials", "--jaccard-grid", "--seed"});
            Require(seen, {"--revision-cell", "--profile", "--cell", "--k",
                           "--m", "--set_size", "--universe", "--trials",
                           "--jaccard-grid", "--seed"});
            if (!request.output.empty() ||
                (request.cell != "estimator-j" &&
                 request.cell != "estimator-k")) {
                if (seen.find("--output") != seen.end()) {
                    Reject("estimator does not accept --output");
                }
                Reject("invalid estimator --cell");
            }
            if (request.jaccard_grid.empty()) Reject("missing --jaccard-grid");
            break;
        case CpuRevisionProducer::DeletionSurvival:
            RejectUnexpected(seen, {"--revision-cell", "--profile", "--cell",
                                    "--k", "--m", "--set_size", "--universe",
                                    "--trials", "--seed"});
            Require(seen, {"--revision-cell", "--profile", "--cell", "--k",
                           "--m", "--set_size", "--universe", "--trials",
                           "--seed"});
            if (request.cell != "exact" && request.cell != "monte-carlo") {
                Reject("invalid deletion --cell");
            }
            if (request.cell == "exact" && request.trials != 0) {
                Reject("exact deletion requires --trials=0");
            }
            if (request.cell == "monte-carlo" && request.trials == 0) {
                Reject("Monte Carlo deletion requires positive --trials");
            }
            break;
        case CpuRevisionProducer::Sj16Calibrate:
            RejectUnexpected(seen, {"--revision-cell", "--profile", "--cell",
                                    "--key-bits", "--sizes", "--held-out",
                                    "--threads", "--precomputed",
                                    "--query-trials", "--enc-iters", "--warmup",
                                    "--seed", "--output", "--raw_timing_dir",
                                    "--raw_timing_profile"});
            Require(seen, {"--revision-cell", "--profile", "--cell",
                           "--key-bits", "--sizes", "--held-out", "--threads",
                           "--precomputed", "--query-trials", "--enc-iters",
                           "--warmup", "--seed", "--output", "--raw_timing_dir",
                           "--raw_timing_profile"});
            if (request.cell != "fit-per-element" || request.precomputed) {
                Reject("SJ16 calibration requires --cell=fit-per-element and "
                       "--precomputed=false");
            }
            if (request.output != "{output}/calibration.csv") {
                Reject("SJ16 --output must be {output}/calibration.csv");
            }
            if (request.warmup != 1) Reject("SJ16 --warmup must be 1");
            break;
    }

    return request;
}

CpuRevisionSelection SelectCpuRevisionCell(
    const RevisionMatrix& matrix, const CpuRevisionRequest& request,
    CpuRevisionProducer producer, RevisionRunMode mode) {
    const RevisionCell* cell = FindCell(matrix, request.revision_cell);
    const char* expected_producer = ProducerName(producer);
    if (cell->producer != expected_producer) {
        Reject("matrix producer does not match selected CPU producer");
    }
    const RevisionInvocationPlan plan = PlanFor(*cell, producer, mode);
    if (plan.argv != request.argv) {
        Reject("argv does not byte-match the canonical cell plan");
    }
    return {*cell, plan};
}

CpuRevisionSelection SelectCpuRevisionCell(
    const RevisionMatrix& matrix, const std::vector<std::string>& argv,
    CpuRevisionProducer producer, RevisionRunMode mode) {
    return SelectCpuRevisionCell(matrix, ParseCpuRevisionArgs(argv, producer),
                                 producer, mode);
}

CpuRevisionExecutionPlan PlanCpuRevisionExecution(
    const RevisionMatrix& matrix, const std::vector<std::string>& argv,
    CpuRevisionProducer producer, RevisionRunMode mode) {
    CpuRevisionExecutionPlan execution;
    execution.selection = SelectCpuRevisionCell(matrix, argv, producer, mode);
    execution.selected_cell_count = 1;
    execution.producer_invocation_count = 1;
    execution.native_sweep = false;
    return execution;
}

std::vector<CpuRevisionExecutionPlan> PlanCpuRevisionExecutionSpy(
    const RevisionMatrix& matrix, const std::vector<std::string>& argv,
    CpuRevisionProducer producer, RevisionRunMode mode) {
    return {PlanCpuRevisionExecution(matrix, argv, producer, mode)};
}

}  // namespace piccard::benchmark
