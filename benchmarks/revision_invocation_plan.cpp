#include "revision_invocation_plan.h"

#include <cstdint>
#include <initializer_list>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace piccard::benchmark {
namespace {

constexpr const char* kFamily = "piccard_std128";
constexpr const char* kProducer = "bench_piccard";
constexpr const char* kMatrixProfile = "paper-v1";
constexpr const char* kPaperProfile = "paper-std128-t40-v1";
constexpr const char* kToyProfile = "readiness-toy-v1";

std::string ExecutableForCell(const RevisionCell& cell) {
    if (cell.family == "flooding") return "scripts/run_noise_profiles.sh";
    if (cell.family == "real_dataset" && cell.axis_value == "summary") {
        return "scripts/summarize_real_datasets.py";
    }
    return cell.producer;
}

RevisionInvocationPlan MakePlan(const RevisionCell& cell,
                                RevisionRunMode mode,
                                const std::string& concrete_profile) {
    RevisionInvocationPlan plan;
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.family = cell.family;
    plan.abstract_profile = cell.profile;
    plan.concrete_profile = concrete_profile;
    plan.timeout_class = cell.timeout_class;
    plan.expected_artifact_schema = cell.expected_artifact_schema;
    plan.executable = ExecutableForCell(cell);
    plan.environment = {
        {"OMP_DYNAMIC", "FALSE"},
        {"OMP_NUM_THREADS", cell.family == "sj16" ? "2" : "{threads}"},
    };
    if (mode == RevisionRunMode::DryRun) {
        plan.environment.emplace("PICCARD_REVISION_DRY_RUN", "1");
        if (cell.family == "flooding") {
            plan.environment.emplace("DRY_RUN", "1");
        }
    }
    plan.invocation_status = cell.invocation_status;
    return plan;
}

[[noreturn]] void Reject(const std::string& reason) {
    throw std::invalid_argument("invalid Piccard revision invocation cell: " +
                                reason);
}

uint64_t ParseUnsigned(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '-' ||
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
    if (consumed != value.size() || std::to_string(parsed) != value) {
        Reject(std::string(field) + " must be a canonical unsigned integer");
    }
    return parsed;
}

int64_t ParseSigned(const std::string& value, const char* field) {
    if (value.empty() || value.front() == '+' || value == "-" ||
        value.find_first_not_of("-0123456789") != std::string::npos ||
        (value.front() == '-' && value.size() == 1u)) {
        Reject(std::string(field) + " must be a canonical signed integer");
    }
    const size_t digits_start = value.front() == '-' ? 1u : 0u;
    if (value.find_first_not_of("0123456789", digits_start) !=
        std::string::npos) {
        Reject(std::string(field) + " must be a canonical signed integer");
    }
    size_t consumed = 0;
    int64_t parsed = 0;
    try {
        parsed = std::stoll(value, &consumed, 10);
    } catch (const std::exception&) {
        Reject(std::string(field) + " is out of range");
    }
    if (consumed != value.size() || std::to_string(parsed) != value) {
        Reject(std::string(field) + " must be a canonical signed integer");
    }
    return parsed;
}

uint64_t Axis(const RevisionCell& cell, const char* name) {
    const auto it = cell.axes.find(name);
    if (it == cell.axes.end()) Reject(std::string("missing axis ") + name);
    return ParseUnsigned(it->second, name);
}

int64_t SignedAxis(const RevisionCell& cell, const char* name) {
    const auto it = cell.axes.find(name);
    if (it == cell.axes.end()) Reject(std::string("missing axis ") + name);
    return ParseSigned(it->second, name);
}

void RequireAxisValue(const RevisionCell& cell, const char* name,
                      uint64_t expected) {
    const auto it = cell.axes.find(name);
    if (it == cell.axes.end()) Reject(std::string("missing axis ") + name);
    if (it->second != std::to_string(expected)) {
        Reject(std::string("axis ") + name + " is not " +
               std::to_string(expected));
    }
}

void RequireControlGeometry(const RevisionCell& cell, uint64_t k, uint64_t m,
                            uint64_t n, uint64_t u) {
    RequireAxisValue(cell, "k", k);
    RequireAxisValue(cell, "m", m);
    RequireAxisValue(cell, "n", n);
    RequireAxisValue(cell, "u", u);
}

bool IsOneOf(uint64_t value, std::initializer_list<uint64_t> choices) {
    for (const uint64_t choice : choices) {
        if (value == choice) return true;
    }
    return false;
}

void ValidateGeometryAndIdentity(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::piccard_std128::" + cell.axis + "=" +
                            cell.axis_value) {
        Reject("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axes.size() != 4u) Reject("Piccard cells require exactly k,m,n,u");

    const uint64_t k = Axis(cell, "k");
    const uint64_t m = Axis(cell, "m");
    const uint64_t n = Axis(cell, "n");
    const uint64_t u = Axis(cell, "u");

    if (cell.axis == "control") {
        if (cell.axis_value != "default") Reject("control selector is not default");
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    if (cell.axis == "k") {
        if (!IsOneOf(k, {16, 32, 64, 128, 256, 512}) ||
            cell.axis_value != std::to_string(k)) {
            Reject("invalid k selector");
        }
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "m") {
        if (!IsOneOf(m, {16, 32, 64, 128, 256}) ||
            cell.axis_value != std::to_string(m)) {
            Reject("invalid m selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            Reject("invalid n selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }
    if (cell.axis == "u") {
        if (!IsOneOf(u, {16384, 65536, 262144, 1048576}) ||
            cell.axis_value != std::to_string(u)) {
            Reject("invalid u selector");
        }
        RequireControlGeometry(cell, 128, 64, 1000, u);
        return;
    }
    Reject("unsupported Piccard selector axis");
}

void ValidateCounts(const RevisionCell& cell) {
    if (cell.paper_count != 30 || cell.toy_count != 1 ||
        cell.paper_trials != 30 || cell.toy_trials != 1) {
        Reject("Piccard invocation counts must be paper=30 and toy=1");
    }
    const std::map<std::string, uint64_t> paper_counts = {
        {"accuracy", 50}, {"timing", 30}};
    const std::map<std::string, uint64_t> toy_counts = {
        {"accuracy", 1}, {"timing", 1}};
    if (cell.paper_counts != paper_counts || cell.toy_counts != toy_counts) {
        Reject("Piccard per-kind counts do not match the frozen contract");
    }

    if (cell.expected_rows.size() != 2u) {
        Reject("Piccard cells require timing and accuracy rows");
    }
    const RevisionRow& timing = cell.expected_rows.at(0);
    if (timing.row_id != "onehot_timing" || timing.status != "MEASURED" ||
        timing.terminal_status != "MEASURED" || timing.method != "piccard" ||
        timing.timing_contract != "full-query" || !timing.reason.empty() ||
        !timing.reason_code.empty() || timing.paper_measured_count != 30 ||
        timing.toy_measured_count != 1 || timing.measured_count != 30) {
        Reject("Piccard timing row contract mismatch");
    }
    const RevisionRow& accuracy = cell.expected_rows.at(1);
    if (accuracy.row_id != "onehot_accuracy" ||
        accuracy.status != "MEASURED" ||
        accuracy.terminal_status != "MEASURED" ||
        accuracy.method != "piccard" ||
        accuracy.timing_contract != "NOT_APPLICABLE" ||
        !accuracy.reason.empty() || !accuracy.reason_code.empty() ||
        accuracy.paper_measured_count != 50 ||
        accuracy.toy_measured_count != 1 || accuracy.measured_count != 50) {
        Reject("Piccard accuracy row contract mismatch");
    }
}

void ValidateCell(const RevisionCell& cell) {
    if (cell.family != kFamily) Reject("family must be piccard_std128");
    if (cell.producer != kProducer) Reject("producer must be bench_piccard");
    if (cell.profile != kMatrixProfile) Reject("matrix profile must be paper-v1");
    if (cell.dataset != "synthetic") Reject("dataset must be synthetic");
    if (cell.invocation_status != "RUN") Reject("cell is not RUN");
    if (cell.expected_artifact_schema != "piccard-benchmark-csv-v1") {
        Reject("unexpected Piccard artifact schema");
    }
    ValidateGeometryAndIdentity(cell);
    ValidateCounts(cell);
}

std::string ProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return kPaperProfile;
        case RevisionRunMode::Toy:
            return kToyProfile;
    }
    Reject("unknown run mode");
}

bool IsToyMode(RevisionRunMode mode) {
    return mode == RevisionRunMode::Toy;
}

[[noreturn]] void RejectFheInd(const std::string& reason) {
    throw std::invalid_argument("invalid FHE-IND revision invocation cell: " +
                                reason);
}

void ValidateFheIndGeometry(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::fhe_ind::" + cell.axis + "=" +
                            cell.axis_value) {
        RejectFheInd("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axes.size() != 4u) {
        RejectFheInd("FHE-IND cells require exactly k,m,n,u");
    }

    const uint64_t k = Axis(cell, "k");
    const uint64_t m = Axis(cell, "m");
    const uint64_t n = Axis(cell, "n");
    const uint64_t u = Axis(cell, "u");
    if (k != 128 || m != 64) RejectFheInd("k/m geometry must be 128/64");

    if (cell.axis == "control") {
        if (cell.axis_value != "default") {
            RejectFheInd("control selector is not default");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            RejectFheInd("invalid n selector");
        }
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }
    if (cell.axis == "u") {
        if (!IsOneOf(u, {16384, 65536, 262144, 1048576}) ||
            cell.axis_value != std::to_string(u)) {
            RejectFheInd("invalid u selector");
        }
        RequireAxisValue(cell, "n", 1000);
        return;
    }
    RejectFheInd("unsupported FHE-IND selector axis");
}

void ValidateFheIndCounts(const RevisionCell& cell) {
    if (cell.paper_count != 30 || cell.toy_count != 1 ||
        cell.paper_trials != 30 || cell.toy_trials != 1) {
        RejectFheInd("FHE-IND invocation counts must be paper=30 and toy=1");
    }
    const std::map<std::string, uint64_t> paper_counts = {{"timing", 30}};
    const std::map<std::string, uint64_t> toy_counts = {{"timing", 1}};
    if (cell.paper_counts != paper_counts || cell.toy_counts != toy_counts) {
        RejectFheInd("FHE-IND per-kind counts do not match the frozen contract");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectFheInd("FHE-IND cells require one diagnostic row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    if (row.row_id != "fhe_ind" || row.status != "DIAGNOSTIC" ||
        row.terminal_status != "DIAGNOSTIC" || row.method != "fhe_ind" ||
        row.raw_timing_contract != "raw-phase-v1" || !row.reason.empty() ||
        !row.reason_code.empty() || row.paper_measured_count != 30 ||
        row.toy_measured_count != 1 || row.measured_count != 30) {
        RejectFheInd("FHE-IND diagnostic row contract mismatch");
    }
}

void ValidateFheIndCell(const RevisionCell& cell) {
    if (cell.family != "fhe_ind") RejectFheInd("family must be fhe_ind");
    if (cell.producer != "bench_fhe_ind") {
        RejectFheInd("producer must be bench_fhe_ind");
    }
    if (cell.profile != "paper-v1") {
        RejectFheInd("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") RejectFheInd("dataset must be synthetic");
    if (cell.invocation_status != "RUN") RejectFheInd("cell is not RUN");
    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectFheInd("cell must remain diagnostic-only");
    }
    if (cell.expected_artifact_schema != "fhe-ind-csv-v1") {
        RejectFheInd("unexpected FHE-IND artifact schema");
    }
    ValidateFheIndGeometry(cell);
    ValidateFheIndCounts(cell);
}

std::string FheIndProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectFheInd("unknown run mode");
}

[[noreturn]] void RejectEstimator(const std::string& reason) {
    throw std::invalid_argument(
        "invalid estimator revision invocation cell: " + reason);
}

bool IsEstimatorJValue(const std::string& value) {
    for (const char* candidate : {"0.0", "0.1", "0.2", "0.3", "0.4",
                                 "0.5", "0.6", "0.7", "0.8", "0.9",
                                 "1.0"}) {
        if (value == candidate) return true;
    }
    return false;
}

void ValidateEstimatorCell(const RevisionCell& cell) {
    if (cell.family != "estimator_accuracy") {
        RejectEstimator("family must be estimator_accuracy");
    }
    if (cell.producer != "bench_estimator_bias") {
        RejectEstimator("producer must be bench_estimator_bias");
    }
    if (cell.profile != "paper-v1") {
        RejectEstimator("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectEstimator("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "estimator-diagnostic-csv-v1") {
        RejectEstimator("unexpected estimator artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectEstimator("cell is not RUN");
    }
    if (cell.eligibility != "TABLE_ELIGIBLE" || !cell.table_eligible ||
        !cell.comparison_eligible) {
        RejectEstimator("estimator cell must be table/comparison eligible");
    }

    const bool j_cell = cell.axis == "j";
    const bool k_cell = cell.axis == "k";
    if (!j_cell && !k_cell) RejectEstimator("selector axis must be j or k");

    const size_t expected_axis_count = j_cell ? 5u : 4u;
    if (cell.axes.size() != expected_axis_count) {
        RejectEstimator("unexpected estimator axis topology");
    }
    const auto k_axis = cell.axes.find("k");
    if (k_axis == cell.axes.end()) RejectEstimator("missing axis k");
    const uint64_t k = Axis(cell, "k");
    if (!IsOneOf(k, {16, 32, 64, 128, 256, 512})) {
        RejectEstimator("invalid estimator k");
    }
    if (j_cell) {
        const auto j_axis = cell.axes.find("j");
        if (j_axis == cell.axes.end() || !IsEstimatorJValue(j_axis->second) ||
            j_axis->second != cell.axis_value ||
            cell.cell_id != "paper-v1::estimator_accuracy::j=" +
                                cell.axis_value ||
            k != 128) {
            RejectEstimator("invalid estimator j selector");
        }
    } else {
        if (cell.axis_value != std::to_string(k) ||
            cell.cell_id != "paper-v1::estimator_accuracy::k=" +
                                cell.axis_value) {
            RejectEstimator("invalid estimator k selector");
        }
    }
    RequireAxisValue(cell, "m", 64);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);

    const uint64_t paper_trials = j_cell ? 50 : 500;
    if (cell.paper_count != paper_trials || cell.toy_count != 1 ||
        cell.paper_trials != paper_trials || cell.toy_trials != 1 ||
        cell.paper_counts !=
            std::map<std::string, uint64_t>{{"trials", paper_trials}} ||
        cell.toy_counts != std::map<std::string, uint64_t>{{"trials", 1}}) {
        RejectEstimator("paper/toy count contract mismatch");
    }
    if (j_cell) {
        if (cell.attributes !=
            std::map<std::string, std::string>{{"trials", "50"}} ||
            !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
            RejectEstimator("j estimator cell attributes mismatch");
        }
    } else {
        const std::map<std::string, std::string> attributes = {
            {"trials", "500"}};
        const std::map<std::string, std::map<std::string, std::string>> objects = {
            {"toy_dispersion_sentinels", { {"median", "N/A"},
                                             {"sd", "-1"} }}};
        if (cell.attributes != attributes || !cell.list_attributes.empty() ||
            cell.object_attributes != objects) {
            RejectEstimator("k estimator cell attributes mismatch");
        }
    }

    if (cell.expected_rows.size() != 1u) {
        RejectEstimator("estimator cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    const std::string expected_row_id =
        j_cell ? "estimator" : "estimator_convergence";
    const std::map<std::string, std::string> row_attributes = {
        {"toy_trials", "1"}, {"trials", std::to_string(paper_trials)}};
    if (row.row_id != expected_row_id || row.status != "MEASURED" ||
        row.terminal_status != "MEASURED" || row.method != "estimator" ||
        !row.reason.empty() || !row.reason_code.empty() ||
        row.measured_count != paper_trials ||
        row.paper_measured_count != paper_trials ||
        row.toy_measured_count != 1 || row.attributes != row_attributes ||
        !row.list_attributes.empty() || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        !row.pattern.empty() || !row.variant.empty() ||
        !row.fit_authority.empty()) {
        RejectEstimator("estimator expected row contract mismatch");
    }
}

std::string EstimatorProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectEstimator("unknown run mode");
}

[[noreturn]] void RejectDeletion(const std::string& reason) {
    throw std::invalid_argument(
        "invalid deletion revision invocation cell: " + reason);
}

void ValidateDeletionCell(const RevisionCell& cell) {
    if (cell.family != "deletion_exact" && cell.family != "deletion_mc") {
        RejectDeletion("family must be deletion_exact or deletion_mc");
    }
    if (cell.producer != "bench_deletion_survival") {
        RejectDeletion("producer must be bench_deletion_survival");
    }
    if (cell.profile != "paper-v1") {
        RejectDeletion("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectDeletion("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "deletion-survival-csv-v1") {
        RejectDeletion("unexpected deletion artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectDeletion("cell is not RUN");
    }
    if (cell.axis != "control" || cell.axis_value != "default" ||
        cell.axes.size() != 4u ||
        cell.cell_id != "paper-v1::" + cell.family + "::control=default") {
        RejectDeletion("deletion control identity mismatch");
    }
    RequireAxisValue(cell, "k", 128);
    RequireAxisValue(cell, "m", 64);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);
    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectDeletion("deletion cell must be diagnostic-only");
    }

    const bool exact = cell.family == "deletion_exact";
    const uint64_t paper_trials = exact ? 0 : 1000;
    const uint64_t toy_trials = exact ? 0 : 1;
    const std::map<std::string, uint64_t> expected_paper_counts = {
        {exact ? "measured" : "trials", paper_trials}};
    const std::map<std::string, uint64_t> expected_toy_counts = {
        {exact ? "measured" : "trials", toy_trials}};
    if (cell.paper_count != paper_trials || cell.toy_count != toy_trials ||
        cell.paper_trials != paper_trials || cell.toy_trials != toy_trials ||
        cell.paper_counts != expected_paper_counts ||
        cell.toy_counts != expected_toy_counts) {
        RejectDeletion("paper/toy count contract mismatch");
    }
    const std::map<std::string, std::string> expected_attributes = {
        {"trials", std::to_string(paper_trials)}};
    if (cell.attributes != expected_attributes ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectDeletion("deletion cell attributes mismatch");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectDeletion("deletion cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    const std::string expected_row_id = exact ? "exact" : "monte_carlo";
    const std::map<std::string, std::string> expected_row_attributes =
        exact ? std::map<std::string, std::string>{}
              : std::map<std::string, std::string>{{"trials", "1000"}};
    if (row.row_id != expected_row_id || row.status != "DIAGNOSTIC" ||
        row.terminal_status != "DIAGNOSTIC" || row.method != expected_row_id ||
        !row.reason.empty() || !row.reason_code.empty() ||
        row.measured_count != paper_trials ||
        row.paper_measured_count != paper_trials ||
        row.toy_measured_count != toy_trials ||
        row.attributes != expected_row_attributes ||
        !row.list_attributes.empty() || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        !row.pattern.empty() || !row.variant.empty() ||
        !row.fit_authority.empty()) {
        RejectDeletion("deletion expected row contract mismatch");
    }
}

std::string DeletionProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectDeletion("unknown run mode");
}

[[noreturn]] void RejectSqrt(const std::string& reason) {
    throw std::invalid_argument(
        "invalid sqrt revision invocation cell: " + reason);
}

bool IsSqrtAxis(const std::string& axis) {
    return axis == "timing_m" || axis == "accuracy_m" ||
           axis == "ciphertext_m" || axis == "crossover_m";
}

std::string SqrtProducer(const std::string& axis) {
    if (axis == "timing_m") return "bench_onehot_sqrt";
    if (axis == "accuracy_m") return "bench_sqrt_comparison";
    if (axis == "ciphertext_m" || axis == "crossover_m") {
        return "bench_crossover";
    }
    RejectSqrt("unsupported sqrt selector axis");
}

std::string SqrtMode(const std::string& axis) {
    if (axis == "timing_m") return "timing";
    if (axis == "accuracy_m") return "accuracy";
    if (axis == "ciphertext_m") return "ciphertext";
    if (axis == "crossover_m") return "crossover";
    RejectSqrt("unsupported sqrt selector axis");
}

uint64_t SqrtPaperTrials(const std::string& axis) {
    if (axis == "timing_m" || axis == "crossover_m") return 30;
    if (axis == "accuracy_m") return 50;
    if (axis == "ciphertext_m") return 1;
    RejectSqrt("unsupported sqrt selector axis");
}

bool IsPerfectSquareM(uint64_t m) {
    return m == 16 || m == 64 || m == 256;
}

void ValidateSqrtCell(const RevisionCell& cell) {
    if (cell.family != "sqrt_comparison") {
        RejectSqrt("family must be sqrt_comparison");
    }
    if (!IsSqrtAxis(cell.axis)) RejectSqrt("invalid sqrt selector axis");
    if (cell.producer != SqrtProducer(cell.axis)) {
        RejectSqrt("producer does not match sqrt selector axis");
    }
    if (cell.profile != "paper-v1") {
        RejectSqrt("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectSqrt("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "sqrt-comparison-csv-v1") {
        RejectSqrt("unexpected sqrt artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectSqrt("cell is not RUN");
    }
    if (cell.eligibility != "TABLE_ELIGIBLE" || !cell.table_eligible ||
        !cell.comparison_eligible) {
        RejectSqrt("sqrt cell must be table/comparison eligible");
    }
    if (cell.axes.size() != 4u) RejectSqrt("sqrt cells require k,m,n,u axes");
    const uint64_t m = Axis(cell, "m");
    if (!IsOneOf(m, {16, 32, 64, 128, 256}) ||
        cell.axis_value != std::to_string(m) ||
        cell.cell_id != "paper-v1::sqrt_comparison::" + cell.axis + "=" +
                            cell.axis_value) {
        RejectSqrt("sqrt m selector identity mismatch");
    }
    RequireAxisValue(cell, "k", 128);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);

    const uint64_t paper_trials = SqrtPaperTrials(cell.axis);
    const bool square = IsPerfectSquareM(m);
    const std::map<std::string, uint64_t> expected_paper_counts = {
        {"onehot", paper_trials}, {"sqrt", square ? paper_trials : 0}};
    const std::map<std::string, uint64_t> expected_toy_counts = {
        {"onehot", 1}, {"sqrt", square ? 1 : 0}};
    if (cell.paper_count != paper_trials || cell.toy_count != 1 ||
        cell.paper_trials != paper_trials || cell.toy_trials != 1 ||
        cell.paper_counts != expected_paper_counts ||
        cell.toy_counts != expected_toy_counts) {
        RejectSqrt("paper/toy count contract mismatch");
    }
    if (!cell.attributes.empty() || !cell.list_attributes.empty() ||
        !cell.object_attributes.empty()) {
        RejectSqrt("sqrt cell attributes must be empty");
    }

    if (cell.expected_rows.size() != 2u) {
        RejectSqrt("sqrt cells require onehot and sqrt rows");
    }
    const RevisionRow& onehot = cell.expected_rows.at(0);
    if (onehot.row_id != "onehot" || onehot.status != "MEASURED" ||
        onehot.terminal_status != "MEASURED" || onehot.method != "onehot" ||
        !onehot.reason.empty() || !onehot.reason_code.empty() ||
        onehot.measured_count != paper_trials ||
        onehot.paper_measured_count != paper_trials ||
        onehot.toy_measured_count != 1 || !onehot.attributes.empty() ||
        !onehot.list_attributes.empty() || !onehot.timing_contract.empty() ||
        !onehot.raw_timing_contract.empty() || !onehot.phase.empty() ||
        !onehot.pattern.empty() || !onehot.variant.empty() ||
        !onehot.fit_authority.empty()) {
        RejectSqrt("onehot row contract mismatch");
    }

    const RevisionRow& sqrt = cell.expected_rows.at(1);
    const std::string sqrt_status = square ? "MEASURED" : "NOT_APPLICABLE";
    const uint64_t sqrt_count = square ? paper_trials : 0;
    if (sqrt.row_id != "sqrt" || sqrt.status != sqrt_status ||
        sqrt.terminal_status != sqrt_status || sqrt.method != "sqrt" ||
        sqrt.reason != (square ? "" : "sqrt-m-not-perfect-square") ||
        sqrt.reason_code != (square ? "" : "sqrt-m-not-perfect-square") ||
        sqrt.measured_count != sqrt_count ||
        sqrt.paper_measured_count != sqrt_count ||
        sqrt.toy_measured_count != (square ? 1u : 0u) ||
        !sqrt.attributes.empty() || !sqrt.list_attributes.empty() ||
        !sqrt.timing_contract.empty() || !sqrt.raw_timing_contract.empty() ||
        !sqrt.phase.empty() || !sqrt.pattern.empty() ||
        !sqrt.variant.empty() || !sqrt.fit_authority.empty()) {
        RejectSqrt("sqrt row contract mismatch");
    }
}

std::string SqrtProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-std128-t40-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectSqrt("unknown run mode");
}

[[noreturn]] void RejectStd192Encoding(const std::string& reason) {
    throw std::invalid_argument(
        "invalid Piccard STD192 encoding revision cell: " + reason);
}

void ValidateStd192EncodingGeometry(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::piccard_std192_encoding::" + cell.axis +
                            "=" + cell.axis_value ||
        cell.axes.size() != 4u) {
        RejectStd192Encoding("cell ID or axis topology mismatch");
    }

    const uint64_t k = Axis(cell, "k");
    const uint64_t m = Axis(cell, "m");
    const uint64_t n = Axis(cell, "n");
    const uint64_t u = Axis(cell, "u");
    if (cell.axis == "control") {
        if (cell.axis_value != "default") {
            RejectStd192Encoding("control selector is not default");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    if (cell.axis == "k") {
        if (!IsOneOf(k, {16, 32, 64, 128, 256, 512}) ||
            cell.axis_value != std::to_string(k)) {
            RejectStd192Encoding("invalid k selector");
        }
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "m") {
        if (!IsOneOf(m, {16, 32, 64, 128, 256}) ||
            cell.axis_value != std::to_string(m)) {
            RejectStd192Encoding("invalid m selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            RejectStd192Encoding("invalid n selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }
    if (cell.axis == "u") {
        if (!IsOneOf(u, {16384, 65536, 262144, 1048576}) ||
            cell.axis_value != std::to_string(u)) {
            RejectStd192Encoding("invalid u selector");
        }
        RequireControlGeometry(cell, 128, 64, 1000, u);
        return;
    }
    RejectStd192Encoding("unsupported selector axis");
}

void ValidateStd192EncodingCell(const RevisionCell& cell) {
    if (cell.family != "piccard_std192_encoding") {
        RejectStd192Encoding("family must be piccard_std192_encoding");
    }
    if (cell.producer != "bench_review_comparison") {
        RejectStd192Encoding("producer must be bench_review_comparison");
    }
    if (cell.profile != "paper-v1") {
        RejectStd192Encoding("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectStd192Encoding("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "review-encoding-csv-v1") {
        RejectStd192Encoding("unexpected encoding artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectStd192Encoding("cell is not RUN");
    }
    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectStd192Encoding("encoding cell must be diagnostic-only");
    }
    ValidateStd192EncodingGeometry(cell);

    const uint64_t m = Axis(cell, "m");
    const bool square = IsPerfectSquareM(m);
    if (cell.paper_count != 30 || cell.toy_count != 1 ||
        cell.paper_trials != 30 || cell.toy_trials != 1 ||
        cell.paper_counts !=
            std::map<std::string, uint64_t>{{"correctness", 1},
                                             {"encoding", 30}} ||
        cell.toy_counts !=
            std::map<std::string, uint64_t>{{"correctness", 1},
                                             {"encoding", 1}}) {
        RejectStd192Encoding("paper/toy count contract mismatch");
    }
    if (!cell.attributes.empty() || !cell.list_attributes.empty() ||
        !cell.object_attributes.empty()) {
        RejectStd192Encoding("encoding cell attributes must be empty");
    }

    if (cell.expected_rows.size() != 2u) {
        RejectStd192Encoding("encoding cells require two expected rows");
    }
    const auto validate_row = [&](const RevisionRow& row,
                                  const std::string& row_id,
                                  const std::string& status,
                                  const std::string& reason,
                                  uint64_t count) {
        if (row.row_id != row_id || row.status != status ||
            row.terminal_status != status || row.method != row_id ||
            row.reason != reason || row.reason_code != reason ||
            row.measured_count != count || row.paper_measured_count != count ||
            row.toy_measured_count != (count == 0 ? 0u : 1u) ||
            row.attributes !=
                std::map<std::string, std::string>{{"encoding_only", "true"}} ||
            !row.list_attributes.empty() || !row.timing_contract.empty() ||
            !row.raw_timing_contract.empty() || !row.phase.empty() ||
            !row.pattern.empty() || !row.variant.empty() ||
            !row.fit_authority.empty()) {
            RejectStd192Encoding("encoding row contract mismatch");
        }
    };
    validate_row(cell.expected_rows.at(0), "piccard_encode", "DIAGNOSTIC", "",
                 30);
    validate_row(cell.expected_rows.at(1), "piccard_sqrt_encode",
                 square ? "DIAGNOSTIC" : "NOT_APPLICABLE",
                 square ? "" : "sqrt-m-not-perfect-square", square ? 30 : 0);
}

std::string Std192EncodingProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-std192-encoding-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectStd192Encoding("unknown run mode");
}

[[noreturn]] void RejectBcg12(const std::string& reason) {
    throw std::invalid_argument(
        "invalid BCG12 revision invocation cell: " + reason);
}

bool IsBcg12Family(const std::string& family) {
    return family == "bcg12_minhash" || family == "bcg12_exact";
}

void ValidateBcg12Geometry(const RevisionCell& cell) {
    if (!IsBcg12Family(cell.family)) {
        RejectBcg12("family must be bcg12_minhash or bcg12_exact");
    }
    if (cell.cell_id != "paper-v1::" + cell.family + "::" + cell.axis +
                            "=" + cell.axis_value) {
        RejectBcg12("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axes.size() != 4u) {
        RejectBcg12("BCG12 cells require exactly k,m,n,u");
    }

    const uint64_t k = Axis(cell, "k");
    const uint64_t n = Axis(cell, "n");
    if (Axis(cell, "m") != 64u) {
        RejectBcg12("BCG12 m geometry must be 64");
    }

    if (cell.axis == "control") {
        if (cell.axis_value != "default") {
            RejectBcg12("control selector is not default");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }

    if (cell.axis == "k") {
        if (cell.family != "bcg12_minhash" ||
            !IsOneOf(k, {16, 32, 64, 128, 256, 512}) ||
            cell.axis_value != std::to_string(k)) {
            RejectBcg12("invalid BCG12 MinHash k selector");
        }
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }

    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            RejectBcg12("invalid BCG12 n selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }

    RejectBcg12(cell.family == "bcg12_exact"
                    ? "exact BCG12 supports only control and n selectors"
                    : "unsupported BCG12 MinHash selector axis");
}

void ValidateBcg12Cell(const RevisionCell& cell) {
    if (!IsBcg12Family(cell.family)) {
        RejectBcg12("family must be bcg12_minhash or bcg12_exact");
    }
    if (cell.producer != "bench_review_comparison") {
        RejectBcg12("producer must be bench_review_comparison");
    }
    if (cell.profile != "paper-v1") {
        RejectBcg12("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectBcg12("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "review-comparison-csv-v1") {
        RejectBcg12("unexpected BCG12 artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectBcg12("cell is not RUN");
    }

    const bool minhash = cell.family == "bcg12_minhash";
    if (cell.eligibility != (minhash ? "TABLE_ELIGIBLE" : "DIAGNOSTIC_ONLY") ||
        cell.table_eligible != minhash ||
        cell.comparison_eligible != minhash) {
        RejectBcg12("eligibility contract mismatch");
    }
    ValidateBcg12Geometry(cell);

    if (cell.paper_count != 30 || cell.toy_count != 1 ||
        cell.paper_trials != 30 || cell.toy_trials != 1 ||
        cell.paper_counts != std::map<std::string, uint64_t>{{"timing", 30}} ||
        cell.toy_counts != std::map<std::string, uint64_t>{{"timing", 1}}) {
        RejectBcg12("paper/toy count contract mismatch");
    }
    if (!cell.attributes.empty() || !cell.list_attributes.empty() ||
        !cell.object_attributes.empty()) {
        RejectBcg12("BCG12 cell attributes must be empty");
    }

    if (cell.expected_rows.size() != 2u) {
        RejectBcg12("BCG12 cells require two expected rows");
    }
    const std::string expected_status = minhash ? "MEASURED" : "DIAGNOSTIC";
    const std::string first_method =
        minhash ? "bcg12_mh_ec" : "bcg12_exact_ec";
    const std::string second_method =
        minhash ? "bcg12_mh_ff" : "bcg12_exact_ff";
    const auto validate_row = [&](const RevisionRow& row,
                                  const std::string& method) {
        if (row.row_id != method || row.status != expected_status ||
            row.terminal_status != expected_status || row.method != method ||
            !row.reason.empty() || !row.reason_code.empty() ||
            row.measured_count != 30 || row.paper_measured_count != 30 ||
            row.toy_measured_count != 1 || !row.timing_contract.empty() ||
            !row.raw_timing_contract.empty() || !row.phase.empty() ||
            !row.pattern.empty() || !row.variant.empty() ||
            !row.fit_authority.empty() || !row.truth_bases.empty() ||
            !row.field_values.empty() || !row.attributes.empty() ||
            !row.list_attributes.empty()) {
            RejectBcg12("BCG12 expected row contract mismatch");
        }
    };
    validate_row(cell.expected_rows.at(0), first_method);
    validate_row(cell.expected_rows.at(1), second_method);
}

std::string Bcg12ProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectBcg12("unknown run mode");
}

[[noreturn]] void RejectThreshold(const std::string& reason) {
    throw std::invalid_argument(
        "invalid threshold FHE revision invocation cell: " + reason);
}

bool IsThresholdFheFamily(const std::string& family) {
    return family == "threshold_timing" || family == "threshold_spec" ||
           family == "threshold_agreement";
}

std::string ThresholdCellKind(const RevisionCell& cell) {
    if (cell.family == "threshold_timing") return "timing";
    if (cell.family == "threshold_spec") return "spec";
    if (cell.family == "threshold_agreement") return "agreement";
    RejectThreshold("unsupported threshold family");
}

void ValidateThresholdFheCell(const RevisionCell& cell) {
    if (!IsThresholdFheFamily(cell.family)) {
        RejectThreshold("family must be threshold_timing/spec/agreement");
    }
    if (cell.producer != "bench_threshold") {
        RejectThreshold("producer must be bench_threshold");
    }
    if (cell.profile != "paper-v1") {
        RejectThreshold("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectThreshold("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "threshold-csv-v1") {
        RejectThreshold("unexpected threshold artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectThreshold("cell is not RUN");
    }

    const std::string kind = ThresholdCellKind(cell);
    if (cell.cell_id != "paper-v1::" + cell.family + "::k=" +
                            cell.axis_value ||
        cell.axis != "k" || cell.axes.size() != 4u) {
        RejectThreshold("cell ID/selector/axis topology mismatch");
    }
    const uint64_t k = Axis(cell, "k");
    if (!IsOneOf(k, {16, 32, 64, 128, 256}) ||
        cell.axis_value != std::to_string(k)) {
        RejectThreshold("invalid k selector");
    }
    RequireAxisValue(cell, "m", 64);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);

    const uint64_t paper_trials = kind == "timing" ? 30 :
                                  (kind == "spec" ? 0 : 50);
    const std::string expected_eligibility = kind == "spec"
                                                 ? "DIAGNOSTIC_ONLY"
                                                 : "TABLE_ELIGIBLE";
    const bool eligible = kind != "spec";
    if (cell.eligibility != expected_eligibility ||
        cell.table_eligible != eligible || cell.comparison_eligible != eligible) {
        RejectThreshold("eligibility contract mismatch");
    }
    if (cell.paper_count != paper_trials || cell.toy_count != 1 ||
        cell.paper_trials != paper_trials || cell.toy_trials != 1 ||
        cell.paper_counts != std::map<std::string, uint64_t>{{kind, paper_trials}} ||
        cell.toy_counts != std::map<std::string, uint64_t>{{kind, 1}}) {
        RejectThreshold("paper/toy count contract mismatch");
    }
    const auto cell_k = cell.attributes.find("k");
    if (cell.attributes.size() != 1u || cell_k == cell.attributes.end() ||
        cell_k->second != std::to_string(k) ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectThreshold("threshold cell attribute contract mismatch");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectThreshold("threshold cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    const std::string expected_status = kind == "spec" ? "DIAGNOSTIC" : "MEASURED";
    const auto row_k = row.attributes.find("k");
    if (row.row_id != kind || row.status != expected_status ||
        row.terminal_status != expected_status || row.method != kind ||
        !row.reason.empty() || !row.reason_code.empty() ||
        row.measured_count != paper_trials ||
        row.paper_measured_count != paper_trials ||
        row.toy_measured_count != 1 || row.attributes.size() != 1u ||
        row_k == row.attributes.end() || row_k->second != std::to_string(k) ||
        !row.list_attributes.empty()) {
        RejectThreshold("expected threshold row contract mismatch");
    }
}

void ValidateThresholdSyntheticCell(const RevisionCell& cell) {
    if (cell.family != "threshold_synthetic_fpfn") {
        RejectThreshold("family must be threshold_synthetic_fpfn");
    }
    if (cell.producer != "bench_threshold") {
        RejectThreshold("producer must be bench_threshold");
    }
    if (cell.profile != "paper-v1") {
        RejectThreshold("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectThreshold("dataset must be synthetic");
    }
    if (cell.expected_artifact_schema != "threshold-fpfn-csv-v1") {
        RejectThreshold("unexpected threshold FPFN artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectThreshold("cell is not RUN");
    }
    if (cell.timeout_class != "standard") {
        RejectThreshold("unexpected threshold FPFN timeout class");
    }

    if (cell.axis != "point" || cell.axes.size() != 5u) {
        RejectThreshold("synthetic threshold cells require point/k/grid/m/n/u");
    }
    const uint64_t k = Axis(cell, "k");
    const int64_t grid_index = SignedAxis(cell, "grid_index");
    if (!IsOneOf(k, {64, 128, 256, 512})) {
        RejectThreshold("invalid synthetic threshold point k");
    }
    if (grid_index < -10 || grid_index > 10) {
        RejectThreshold("synthetic threshold grid index is outside -10..10");
    }
    const std::string point = "k" + std::to_string(k) + "_j" +
                              std::to_string(grid_index);
    if (cell.axis_value != point ||
        cell.cell_id != "paper-v1::threshold_synthetic_fpfn::point=" + point) {
        RejectThreshold("synthetic threshold point identity mismatch");
    }
    RequireAxisValue(cell, "m", 64);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);

    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectThreshold("synthetic threshold cells must be diagnostic-only");
    }
    if (cell.paper_count != 1000 || cell.toy_count != 1 ||
        cell.paper_trials != 1000 || cell.toy_trials != 1 ||
        cell.paper_counts != std::map<std::string, uint64_t>{{"trials", 1000}} ||
        cell.toy_counts != std::map<std::string, uint64_t>{{"trials", 1}}) {
        RejectThreshold("synthetic threshold paper/toy count contract mismatch");
    }
    const auto point_k = cell.attributes.find("point_k");
    const auto cell_grid = cell.attributes.find("grid_index");
    if (cell.attributes.size() != 2u || point_k == cell.attributes.end() ||
        point_k->second != std::to_string(k) ||
        cell_grid == cell.attributes.end() ||
        cell_grid->second != std::to_string(grid_index) ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectThreshold("synthetic threshold cell attributes mismatch");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectThreshold("synthetic threshold cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    const auto row_point_k = row.attributes.find("point_k");
    const auto row_grid = row.attributes.find("grid_index");
    const auto row_trials = row.attributes.find("trials");
    if (row.row_id != "synthetic_fpfn" || row.status != "DIAGNOSTIC" ||
        row.terminal_status != "DIAGNOSTIC" || row.method != "synthetic_fpfn" ||
        !row.reason.empty() || !row.reason_code.empty() ||
        row.measured_count != 1000 || row.paper_measured_count != 1000 ||
        row.toy_measured_count != 1 || row.attributes.size() != 3u ||
        row_point_k == row.attributes.end() ||
        row_point_k->second != std::to_string(k) ||
        row_grid == row.attributes.end() ||
        row_grid->second != std::to_string(grid_index) ||
        row_trials == row.attributes.end() || row_trials->second != "1000" ||
        !row.list_attributes.empty() || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        !row.pattern.empty() || !row.variant.empty() ||
        !row.fit_authority.empty()) {
        RejectThreshold("synthetic threshold expected row contract mismatch");
    }
}

void ValidateRealThresholdCell(const RevisionCell& cell) {
    if (cell.family != "threshold_dblp_fpfn") {
        RejectThreshold("family must be threshold_dblp_fpfn");
    }
    if (cell.producer != "bench_real_datasets") {
        RejectThreshold("producer must be bench_real_datasets");
    }
    if (cell.profile != "paper-v1") {
        RejectThreshold("matrix profile must be paper-v1");
    }
    if (cell.dataset != "dblp_acm") {
        RejectThreshold("dataset must be dblp_acm");
    }
    if (cell.expected_artifact_schema != "real-threshold-csv-v1") {
        RejectThreshold("unexpected real threshold artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectThreshold("cell is not RUN");
    }
    if (cell.timeout_class != "standard") {
        RejectThreshold("unexpected real threshold timeout class");
    }

    if (cell.axis != "control" || cell.axis_value != "default" ||
        cell.axes.size() != 5u ||
        cell.cell_id !=
            "paper-v1::threshold_dblp_fpfn::control=default") {
        RejectThreshold("real threshold control identity mismatch");
    }
    RequireAxisValue(cell, "k", 128);
    RequireAxisValue(cell, "m", 64);
    RequireAxisValue(cell, "n", 1000);
    RequireAxisValue(cell, "u", 65536);
    const auto variant_axis = cell.axes.find("variant");
    if (variant_axis == cell.axes.end() ||
        variant_axis->second != "dblp_acm_u65536") {
        RejectThreshold("real threshold variant axis mismatch");
    }

    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectThreshold("real threshold cell must be diagnostic-only");
    }
    if (cell.paper_count != 50 || cell.toy_count != 1 ||
        cell.paper_trials != 50 || cell.toy_trials != 1 ||
        cell.paper_counts != std::map<std::string, uint64_t>{{"held_out", 50}} ||
        cell.toy_counts != std::map<std::string, uint64_t>{{"held_out", 1}}) {
        RejectThreshold("real threshold paper/toy count contract mismatch");
    }
    const std::map<std::string, std::vector<std::string>> truth_bases = {
        {"truth_bases", {"label", "exact_jaccard"}}};
    const auto variant = cell.attributes.find("variant");
    if (cell.attributes.size() != 1u || variant == cell.attributes.end() ||
        variant->second != "dblp_acm_u65536" ||
        cell.list_attributes != truth_bases ||
        !cell.object_attributes.empty()) {
        RejectThreshold("real threshold cell attributes mismatch");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectThreshold("real threshold cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    if (row.row_id != "dblp_held_out" || row.status != "DIAGNOSTIC" ||
        row.terminal_status != "DIAGNOSTIC" || row.method != "dblp_held_out" ||
        !row.reason.empty() || !row.reason_code.empty() ||
        row.measured_count != 50 || row.paper_measured_count != 50 ||
        row.toy_measured_count != 1 || !row.attributes.empty() ||
        row.list_attributes != truth_bases || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        !row.pattern.empty() || !row.variant.empty() ||
        !row.fit_authority.empty()) {
        RejectThreshold("real threshold expected row contract mismatch");
    }
}

std::string ThresholdProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectThreshold("unknown run mode");
}

}  // namespace

namespace {
bool IsSj16Extrapolated(const RevisionCell& cell);
void ValidateSj16Cell(const RevisionCell& cell);
std::string Sj16ProfileForMode(RevisionRunMode mode);
}  // namespace

RevisionInvocationPlan PlanPiccardRevisionCell(const RevisionCell& cell,
                                               RevisionRunMode mode) {
    ValidateCell(cell);

    const std::string profile = ProfileForMode(mode);
    const bool toy = IsToyMode(mode);
    const auto& k = cell.axes.at("k");
    const auto& m = cell.axes.at("m");
    const auto& n = cell.axes.at("n");
    const auto& u = cell.axes.at("u");

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--mode=combined",
        "--evidence_point",
        std::string("--security=") + (toy ? "TOY" : "STD128"),
        "--k=" + k,
        "--m=" + m,
        "--set_size=" + n,
        "--universe=" + u,
        std::string("--trials=") + (toy ? "1" : "30"),
        std::string("--accuracy_trials=") + (toy ? "1" : "50"),
        "--seed={seed}",
        "--raw_timing_dir={output}",
    };

    plan.expected_rows = cell.expected_rows;
    if (toy) {
        for (auto& row : plan.expected_rows) row.measured_count = row.toy_measured_count;
    } else {
        for (auto& row : plan.expected_rows) row.measured_count = row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanFheIndRevisionCell(const RevisionCell& cell,
                                              RevisionRunMode mode) {
    ValidateFheIndCell(cell);

    const bool toy = IsToyMode(mode);
    const std::string profile = FheIndProfileForMode(mode);
    const auto& n = cell.axes.at("n");
    const auto& u = cell.axes.at("u");

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--mode=e2e",
        "--cell-id=" + cell.cell_id,
        std::string("--security=") + (toy ? "TOY" : "STD128"),
        "--n=" + n,
        "--universe=" + u,
        std::string("--trials=") + (toy ? "1" : "30"),
        "--raw-timing-out={output}/raw",
        "--raw-timing-profile=" + profile,
        "--seed={seed}",
    };

    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanEstimatorRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode) {
    ValidateEstimatorCell(cell);

    const bool toy = IsToyMode(mode);
    const std::string profile = EstimatorProfileForMode(mode);
    const bool j_cell = cell.axis == "j";
    const uint64_t paper_trials = j_cell ? 50 : 500;

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        std::string("--cell=") + (j_cell ? "estimator-j" : "estimator-k"),
        "--k=" + cell.axes.at("k"),
        "--m=64",
        "--set_size=1000",
        "--universe=65536",
        std::string("--trials=") +
            (toy ? "1" : std::to_string(paper_trials)),
        j_cell ? "--jaccard-grid=" + cell.axis_value
               : "--jaccard-grid=0.5",
        "--seed={seed}",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanDeletionRevisionCell(const RevisionCell& cell,
                                                RevisionRunMode mode) {
    ValidateDeletionCell(cell);

    const bool exact = cell.family == "deletion_exact";
    const bool toy = IsToyMode(mode);
    const std::string profile = DeletionProfileForMode(mode);
    const std::string trials =
        exact ? "0" : (toy ? "1" : "1000");

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        std::string("--cell=") + (exact ? "exact" : "monte-carlo"),
        "--k=128",
        "--m=64",
        "--set_size=1000",
        "--universe=65536",
        "--trials=" + trials,
        "--seed={seed}",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanSqrtRevisionCell(const RevisionCell& cell,
                                            RevisionRunMode mode) {
    ValidateSqrtCell(cell);

    const bool toy = IsToyMode(mode);
    const std::string profile = SqrtProfileForMode(mode);
    const std::string& axis = cell.axis;
    const uint64_t paper_trials = SqrtPaperTrials(axis);

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--cell=" + axis,
        "--mode=" + SqrtMode(axis),
        std::string("--security=") + (toy ? "TOY" : "STD128"),
        "--k=128",
        "--m=" + cell.axes.at("m"),
        "--set_size=1000",
        "--universe=65536",
        std::string("--trials=") +
            (toy ? "1" : std::to_string(paper_trials)),
        "--seed={seed}",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanStd192EncodingRevisionCell(
    const RevisionCell& cell, RevisionRunMode mode) {
    ValidateStd192EncodingCell(cell);

    const bool toy = IsToyMode(mode);
    const std::string profile = Std192EncodingProfileForMode(mode);

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--suite=encoding",
        "--methods=piccard_encode,piccard_sqrt_encode",
        "--security=STD192",
        "--k=" + cell.axes.at("k"),
        "--m=" + cell.axes.at("m"),
        "--n=" + cell.axes.at("n"),
        "--universe=" + cell.axes.at("u"),
        std::string("--encoding-iters=") + (toy ? "1" : "30"),
        "--correctness-trials=1",
        "--seed={seed}",
        "--output={output}/encoding.csv",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanBcg12RevisionCell(const RevisionCell& cell,
                                             RevisionRunMode mode) {
    ValidateBcg12Cell(cell);

    const bool toy = IsToyMode(mode);
    const bool minhash = cell.family == "bcg12_minhash";
    const std::string profile = Bcg12ProfileForMode(mode);

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        std::string("--suite=") + (minhash ? "bcg12-minhash" : "bcg12-exact"),
        std::string("--methods=") +
            (minhash ? "bcg12_mh_ec,bcg12_mh_ff"
                     : "bcg12_exact_ec,bcg12_exact_ff"),
        "--k=" + cell.axes.at("k"),
        "--m=64",
        "--n=" + cell.axes.at("n"),
        "--universe=" + cell.axes.at("u"),
        std::string("--trials=") + (toy ? "1" : "30"),
        "--seed={seed}",
        "--output={output}/comparison.csv",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanSj16RevisionCell(const RevisionCell& cell,
                                            RevisionRunMode mode) {
    ValidateSj16Cell(cell);

    const bool toy = IsToyMode(mode);
    const bool fit = cell.axis == "fit";
    const bool per_element = fit && cell.axis_value == "per_element";
    const bool precomputed = fit && cell.axis_value == "precomputed";
    const bool extrapolated = !fit && IsSj16Extrapolated(cell);
    const std::string profile = Sj16ProfileForMode(mode);

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }

    if (extrapolated) return plan;

    if (per_element) {
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--profile=" + profile,
            "--cell=fit-per-element",
            "--key-bits=3072",
            "--sizes=4096,8192,16384",
            "--held-out=32768",
            "--threads=2",
            "--precomputed=false",
            std::string("--query-trials=") + (toy ? "1" : "30"),
            std::string("--enc-iters=") + (toy ? "1" : "30"),
            "--warmup=1",
            "--seed={seed}",
            "--output={output}/calibration.csv",
        };
        return plan;
    }

    if (precomputed) {
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--profile=" + profile,
            "--cell=sj16-fit-precomputed",
            "--method=sj16_precomputed",
            "--k=128",
            "--m=64",
            "--n=1000",
            "--universe=65536",
            "--key-bits=3072",
            "--threads=2",
            std::string("--trials=") + (toy ? "1" : "30"),
            "--warmup=1",
            "--seed={seed}",
            "--output={output}/comparison.csv",
        };
        return plan;
    }

    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--suite=sj16",
        "--method=sj16",
        "--k=128",
        "--m=64",
        "--n=" + cell.axes.at("n"),
        "--universe=" + cell.axes.at("u"),
        "--key-bits=3072",
        "--threads=2",
        std::string("--trials=") + (toy ? "1" : "30"),
        "--seed={seed}",
        "--output={output}/comparison.csv",
    };
    return plan;
}

namespace {

[[noreturn]] void RejectSj16(const std::string& reason) {
    throw std::invalid_argument(
        "invalid SJ16 revision invocation cell: " + reason);
}

bool IsSj16Extrapolated(const RevisionCell& cell) {
    if (cell.axis == "n" && cell.axis_value == "100000") return true;
    const auto it = cell.axes.find("u");
    return it != cell.axes.end() &&
           (it->second == "262144" || it->second == "1048576");
}

void ValidateSj16Geometry(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::sj16::" + cell.axis + "=" +
                            cell.axis_value) {
        RejectSj16("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axes.size() != 4u) {
        RejectSj16("SJ16 cells require exactly k,m,n,u");
    }
    RequireAxisValue(cell, "k", 128);
    RequireAxisValue(cell, "m", 64);
    const uint64_t n = Axis(cell, "n");
    const uint64_t u = Axis(cell, "u");

    if (cell.axis == "control") {
        if (cell.axis_value != "default") {
            RejectSj16("control selector is not default");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            RejectSj16("invalid SJ16 n selector");
        }
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }
    if (cell.axis == "u") {
        if (!IsOneOf(u, {16384, 65536, 262144, 1048576}) ||
            cell.axis_value != std::to_string(u)) {
            RejectSj16("invalid SJ16 u selector");
        }
        RequireAxisValue(cell, "n", 1000);
        return;
    }
    if (cell.axis == "fit") {
        if (cell.axis_value != "per_element" &&
            cell.axis_value != "precomputed") {
            RejectSj16("invalid SJ16 fit selector");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    RejectSj16("unsupported SJ16 selector axis");
}

void ValidateSj16RowBase(const RevisionRow& row, const std::string& row_id,
                         const std::string& status, const std::string& method,
                         const std::string& reason, uint64_t paper_count,
                         uint64_t toy_count) {
    if (row.row_id != row_id) RejectSj16("SJ16 row ID mismatch");
    if (row.status != status || row.terminal_status != status) {
        RejectSj16("SJ16 row status mismatch");
    }
    if (row.method != method) RejectSj16("SJ16 row method mismatch");
    if (row.reason != reason || row.reason_code != reason) {
        RejectSj16("SJ16 row reason mismatch");
    }
    if (row.measured_count != paper_count ||
        row.paper_measured_count != paper_count ||
        row.toy_measured_count != toy_count) {
        RejectSj16("SJ16 row count mismatch");
    }
    if (!row.timing_contract.empty() || !row.raw_timing_contract.empty() ||
        !row.phase.empty() || !row.pattern.empty() || !row.variant.empty() ||
        !row.field_values.empty()) {
        RejectSj16("SJ16 row optional field mismatch");
    }
}

void ValidateSj16Cell(const RevisionCell& cell) {
    if (cell.family != "sj16") RejectSj16("family must be sj16");
    if (cell.profile != "paper-v1") {
        RejectSj16("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectSj16("dataset must be synthetic");
    }
    if (cell.timeout_class != "standard") {
        RejectSj16("timeout class must be standard");
    }
    ValidateSj16Geometry(cell);

    const bool fit = cell.axis == "fit";
    const bool per_element = fit && cell.axis_value == "per_element";
    const bool precomputed = fit && cell.axis_value == "precomputed";
    const bool extrapolated = !fit && IsSj16Extrapolated(cell);

    const std::string expected_producer =
        per_element ? "bench_sj16_calibrate" : "bench_review_comparison";
    if (cell.producer != expected_producer) {
        RejectSj16("producer does not match SJ16 cell branch");
    }
    const std::string expected_schema =
        per_element ? "sj16-calibration-v1" : "review-comparison-csv-v1";
    if (cell.expected_artifact_schema != expected_schema) {
        RejectSj16("unexpected SJ16 artifact schema");
    }

    const std::string expected_eligibility =
        (fit || extrapolated) ? "DIAGNOSTIC_ONLY" : "TABLE_ELIGIBLE";
    const bool eligible = !fit && !extrapolated;
    const std::string expected_status = extrapolated ? "NO_SPAWN" : "RUN";
    if (cell.eligibility != expected_eligibility ||
        cell.table_eligible != eligible ||
        cell.comparison_eligible != eligible ||
        cell.invocation_status != expected_status) {
        RejectSj16("SJ16 eligibility/status contract mismatch");
    }

    const std::map<std::string, std::string> regular_attributes = {
        {"key_bits", "3072"}, {"threads", "2"}};
    const std::map<std::string, std::string> per_element_attributes = {
        {"fit_authority", "true"}, {"held_out", "32768"},
        {"key_bits", "3072"}, {"precomputed", "false"},
        {"threads", "2"}};
    const std::map<std::string, std::string> precomputed_attributes = {
        {"fit_authority", "false"}, {"k", "128"}, {"key_bits", "3072"},
        {"m", "64"}, {"n", "1000"}, {"precomputed", "true"},
        {"threads", "2"}, {"u", "65536"}};
    const std::map<std::string, std::vector<std::string>> per_element_sizes = {
        {"sizes", {"4096", "8192", "16384"}}};

    if (per_element) {
        if (cell.attributes != per_element_attributes ||
            cell.list_attributes != per_element_sizes ||
            !cell.object_attributes.empty()) {
            RejectSj16("SJ16 per-element cell metadata mismatch");
        }
    } else if (precomputed) {
        if (cell.attributes != precomputed_attributes ||
            !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
            RejectSj16("SJ16 precomputed cell metadata mismatch");
        }
    } else if (cell.attributes != regular_attributes ||
               !cell.list_attributes.empty() ||
               !cell.object_attributes.empty()) {
        RejectSj16("SJ16 comparison cell metadata mismatch");
    }

    uint64_t paper_count = 30;
    uint64_t toy_count = 1;
    std::map<std::string, uint64_t> paper_counts;
    std::map<std::string, uint64_t> toy_counts;
    if (per_element) {
        paper_counts = {{"enc_iters", 30}, {"query_trials", 30}};
        toy_counts = {{"enc_iters", 1}, {"query_trials", 1}};
    } else if (extrapolated && cell.axis != "n") {
        paper_count = 0;
        toy_count = 0;
        paper_counts = {{"timing", 0}};
        toy_counts = {{"timing", 0}};
    } else if (extrapolated) {
        paper_counts = {{"timing", 30}};
        toy_counts = {{"timing", 1}};
    } else {
        paper_counts = {{"timing", 30}};
        toy_counts = {{"timing", 1}};
    }
    if (cell.paper_count != paper_count || cell.toy_count != toy_count ||
        cell.paper_trials != paper_count || cell.toy_trials != toy_count ||
        cell.paper_counts != paper_counts || cell.toy_counts != toy_counts) {
        RejectSj16("SJ16 paper/toy count contract mismatch");
    }

    if (cell.expected_rows.size() != 1u) {
        RejectSj16("SJ16 cells require one expected row");
    }
    const RevisionRow& row = cell.expected_rows.front();
    if (per_element) {
        ValidateSj16RowBase(row, "sj16_fit_per_element", "DIAGNOSTIC",
                             "bench_sj16_calibrate", "", 30, 1);
        const std::map<std::string, std::string> row_attributes = {
            {"held_out", "32768"}, {"key_bits", "3072"},
            {"precomputed", "false"}, {"threads", "2"},
            {"warmup_calls", "1"}};
        if (row.attributes != row_attributes ||
            row.list_attributes != per_element_sizes ||
            !row.fit_authority.empty()) {
            RejectSj16("SJ16 per-element row metadata mismatch");
        }
        return;
    }
    if (precomputed) {
        ValidateSj16RowBase(row, "sj16_fit_precomputed", "DIAGNOSTIC",
                             "bench_review_comparison", "", 30, 1);
        const std::map<std::string, std::string> row_attributes = {
            {"k", "128"}, {"key_bits", "3072"}, {"m", "64"},
            {"n", "1000"}, {"precomputed", "true"}, {"threads", "2"},
            {"u", "65536"}, {"warmup_calls", "1"}};
        if (row.attributes != row_attributes ||
            !row.list_attributes.empty() || !row.fit_authority.empty()) {
            RejectSj16("SJ16 precomputed row metadata mismatch");
        }
        return;
    }

    if (extrapolated) {
        ValidateSj16RowBase(row, "sj16", "EXTRAPOLATED", "sj16",
                             "sj16-paillier3072-calibration-bound-v1",
                             0, 0);
        if (row.fit_authority != "per_element" ||
            row.attributes != regular_attributes ||
            !row.list_attributes.empty()) {
            RejectSj16("SJ16 extrapolated row metadata mismatch");
        }
        return;
    }

    ValidateSj16RowBase(row, "sj16", "MEASURED", "sj16", "", 30, 1);
    if (!row.fit_authority.empty() || row.attributes != regular_attributes ||
        !row.list_attributes.empty()) {
        RejectSj16("SJ16 measured row metadata mismatch");
    }
}

std::string Sj16ProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectSj16("unknown run mode");
}

}  // namespace

namespace {

[[noreturn]] void RejectDynamic(const std::string& reason) {
    throw std::invalid_argument(
        "invalid dynamic revision invocation cell: " + reason);
}

bool IsDynamicFamily(const std::string& family) {
    return family == "dynamic_timing" || family == "dynamic_accuracy" ||
           family == "dynamic_refresh";
}

bool IsDynamicRefresh(const RevisionCell& cell) {
    return cell.family == "dynamic_refresh";
}

bool IsDynamicAccuracy(const RevisionCell& cell) {
    return cell.family == "dynamic_accuracy";
}

std::string DynamicKind(const RevisionCell& cell) {
    if (cell.family == "dynamic_timing") return "timing";
    if (cell.family == "dynamic_accuracy") return "accuracy";
    if (cell.family == "dynamic_refresh") return "refresh";
    RejectDynamic("unsupported dynamic family");
}

void ValidateDynamicGeometry(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::" + cell.family + "::" + cell.axis +
                            "=" + cell.axis_value) {
        RejectDynamic("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axes.size() != 4u) {
        RejectDynamic("dynamic cells require exactly k,m,n,u");
    }

    const uint64_t k = Axis(cell, "k");
    const uint64_t m = Axis(cell, "m");
    const uint64_t n = Axis(cell, "n");
    if (IsDynamicRefresh(cell)) {
        if (cell.axis != "control" || cell.axis_value != "default") {
            RejectDynamic("refresh supports only the control selector");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }

    if (cell.axis == "control") {
        if (cell.axis_value != "default") {
            RejectDynamic("control selector is not default");
        }
        RequireControlGeometry(cell, 128, 64, 1000, 65536);
        return;
    }
    if (cell.axis == "k") {
        if (!IsOneOf(k, {16, 32, 64, 128, 256, 512}) ||
            cell.axis_value != std::to_string(k)) {
            RejectDynamic("invalid dynamic k selector");
        }
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "m") {
        if (!IsOneOf(m, {16, 32, 64, 128, 256}) ||
            cell.axis_value != std::to_string(m)) {
            RejectDynamic("invalid dynamic m selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "n", 1000);
        RequireAxisValue(cell, "u", 65536);
        return;
    }
    if (cell.axis == "n") {
        if (!IsOneOf(n, {100, 1000, 10000, 100000}) ||
            cell.axis_value != std::to_string(n)) {
            RejectDynamic("invalid dynamic n selector");
        }
        RequireAxisValue(cell, "k", 128);
        RequireAxisValue(cell, "m", 64);
        RequireAxisValue(cell, "u", n == 100000 ? 262144 : 65536);
        return;
    }
    RejectDynamic("unsupported dynamic selector axis");
}

void ValidateDynamicRow(const RevisionRow& row, const std::string& row_id,
                        const std::string& phase, const std::string& method,
                        uint64_t paper_count) {
    if (row.row_id != row_id || row.status != "MEASURED" ||
        row.terminal_status != "MEASURED" || row.reason != "" ||
        row.reason_code != "" || row.measured_count != paper_count ||
        row.paper_measured_count != paper_count ||
        row.toy_measured_count != 1 || row.phase != phase ||
        row.method != method || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.pattern.empty() ||
        !row.variant.empty() || !row.fit_authority.empty() ||
        !row.truth_bases.empty() || !row.field_values.empty() ||
        !row.list_attributes.empty()) {
        RejectDynamic("dynamic expected row contract mismatch");
    }
}

void ValidateDynamicCell(const RevisionCell& cell) {
    if (!IsDynamicFamily(cell.family)) {
        RejectDynamic("family must be dynamic_timing, dynamic_accuracy, or "
                      "dynamic_refresh");
    }
    if (cell.producer != "bench_dynamic") {
        RejectDynamic("producer must be bench_dynamic");
    }
    if (cell.profile != "paper-v1") {
        RejectDynamic("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectDynamic("dataset must be synthetic");
    }
    if (cell.timeout_class != "standard") {
        RejectDynamic("timeout class must be standard");
    }
    if (cell.expected_artifact_schema != "dynamic-benchmark-csv-v1") {
        RejectDynamic("unexpected dynamic artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectDynamic("cell is not RUN");
    }
    if (cell.eligibility != "TABLE_ELIGIBLE" || !cell.table_eligible ||
        !cell.comparison_eligible) {
        RejectDynamic("dynamic cell must be table/comparison eligible");
    }
    ValidateDynamicGeometry(cell);

    const bool refresh = IsDynamicRefresh(cell);
    const bool accuracy = IsDynamicAccuracy(cell);
    const uint64_t paper_trials = accuracy ? 50 : 30;
    if (cell.paper_count != paper_trials || cell.toy_count != 1 ||
        cell.paper_trials != paper_trials || cell.toy_trials != 1) {
        RejectDynamic("paper/toy trial counts do not match dynamic contract");
    }

    if (refresh) {
        if (cell.paper_counts !=
                std::map<std::string, uint64_t>{{"refresh", 30}} ||
            cell.toy_counts !=
                std::map<std::string, uint64_t>{{"refresh", 1}}) {
            RejectDynamic("refresh per-kind counts do not match contract");
        }
        if (cell.attributes !=
                std::map<std::string, std::string>{{"updates", "1"}} ||
            !cell.list_attributes.empty() ||
            cell.object_attributes !=
                std::map<std::string,
                         std::map<std::string, std::string>>{
                    {"refresh_axes",
                     {{"k", "128"}, {"m", "64"}, {"n", "1000"}}}}) {
            RejectDynamic("refresh cell attributes do not match contract");
        }
        if (cell.expected_rows.size() != 1u) {
            RejectDynamic("refresh requires one expected row");
        }
        const RevisionRow& row = cell.expected_rows.front();
        ValidateDynamicRow(row, "refresh", "", "refresh", 30);
        if (row.attributes !=
            std::map<std::string, std::string>{{"k", "128"},
                                                {"m", "64"},
                                                {"n", "1000"},
                                                {"updates", "1"}}) {
            RejectDynamic("refresh row attributes do not match contract");
        }
        return;
    }

    const std::map<std::string, uint64_t> expected_paper_counts = {
        {"delete", paper_trials}, {"insert", paper_trials}};
    const std::map<std::string, uint64_t> expected_toy_counts = {
        {"delete", 1}, {"insert", 1}};
    if (cell.paper_counts != expected_paper_counts ||
        cell.toy_counts != expected_toy_counts) {
        RejectDynamic("dynamic per-kind counts do not match contract");
    }
    if (cell.attributes !=
            std::map<std::string, std::string>{{"updates", "1"}} ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectDynamic("dynamic cell attributes do not match contract");
    }
    if (cell.expected_rows.size() != 2u) {
        RejectDynamic("dynamic timing/accuracy cells require two rows");
    }
    const std::string first_id = accuracy ? "insert_correctness" : "insert";
    const std::string second_id = accuracy ? "delete_correctness" : "delete";
    ValidateDynamicRow(cell.expected_rows.at(0), first_id, "insert", "",
                      paper_trials);
    ValidateDynamicRow(cell.expected_rows.at(1), second_id, "delete", "",
                      paper_trials);
    const std::map<std::string, std::string> row_attributes = {
        {"updates", "1"}};
    if (cell.expected_rows.at(0).attributes != row_attributes ||
        cell.expected_rows.at(1).attributes != row_attributes) {
        RejectDynamic("dynamic row attributes do not match contract");
    }
}

std::string DynamicProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-std128-t40-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectDynamic("unknown run mode");
}

}  // namespace

RevisionInvocationPlan PlanDynamicRevisionCell(const RevisionCell& cell,
                                               RevisionRunMode mode) {
    ValidateDynamicCell(cell);

    const bool toy = IsToyMode(mode);
    const bool accuracy = IsDynamicAccuracy(cell);
    const bool raw_timing = !accuracy;
    const std::string profile = DynamicProfileForMode(mode);
    const std::string kind = DynamicKind(cell);
    const uint64_t paper_trials = accuracy ? 50 : 30;

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--cell=" + kind,
        "--mode=" + kind,
        "--evidence_point",
        std::string("--security=") + (toy ? "TOY" : "STD128"),
        "--k=" + cell.axes.at("k"),
        "--m=" + cell.axes.at("m"),
        "--set_size=" + cell.axes.at("n"),
        "--universe=" + cell.axes.at("u"),
        std::string("--trials=") +
            (toy ? "1" : std::to_string(paper_trials)),
        "--updates=1",
        "--seed={seed}",
    };
    if (raw_timing) {
        plan.argv.push_back("--raw-timing-dir={output}/raw");
        plan.argv.push_back(
            std::string("--raw-timing-profile=") +
            (toy ? "readiness-toy-v1" : "paper-v1"));
    }

    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

namespace {

[[noreturn]] void RejectFlooding(const std::string& reason) {
    throw std::invalid_argument(
        "invalid flooding revision invocation cell: " + reason);
}

bool IsFloodingProfile(const std::string& profile) {
    return profile == "primary40" || profile == "sensitivity64" ||
           profile == "feasibility128";
}

void ValidateFloodingGeometry(const RevisionCell& cell) {
    if (cell.cell_id != "paper-v1::flooding::profile=" + cell.axis_value) {
        RejectFlooding("cell ID does not bind profile, family, axis, and value");
    }
    if (cell.axis != "profile" || !IsFloodingProfile(cell.axis_value)) {
        RejectFlooding("axis must select primary40, sensitivity64, or feasibility128");
    }
    if (cell.axes.size() != 4u) {
        RejectFlooding("flooding cells require exactly k,m,n,u");
    }
    RequireControlGeometry(cell, 128, 64, 1000, 65536);
}

void ValidateFloodingRow(const RevisionRow& row, const char* pattern) {
    if (row.row_id != pattern || row.status != "DIAGNOSTIC" ||
        row.reason != "" || row.reason_code != "" ||
        row.terminal_status != "DIAGNOSTIC" || !row.method.empty() ||
        row.timing_contract != "NOT_APPLICABLE" ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        row.pattern != pattern || !row.variant.empty() ||
        !row.fit_authority.empty() || !row.truth_bases.empty() ||
        !row.field_values.empty() || !row.attributes.empty() ||
        !row.list_attributes.empty() || row.measured_count != 5 ||
        row.paper_measured_count != 5 || row.toy_measured_count != 1) {
        RejectFlooding("flooding expected row contract mismatch");
    }
}

void ValidateFloodingCell(const RevisionCell& cell) {
    if (cell.family != "flooding") {
        RejectFlooding("family must be flooding");
    }
    if (cell.producer != "bench_noise") {
        RejectFlooding("producer must be bench_noise");
    }
    if (cell.profile != "paper-v1") {
        RejectFlooding("matrix profile must be paper-v1");
    }
    if (cell.dataset != "synthetic") {
        RejectFlooding("dataset must be synthetic");
    }
    if (cell.timeout_class != "standard") {
        RejectFlooding("timeout class must be standard");
    }
    if (cell.expected_artifact_schema != "noise-profile-v1") {
        RejectFlooding("unexpected noise-profile artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectFlooding("cell is not RUN");
    }
    if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.table_eligible ||
        cell.comparison_eligible) {
        RejectFlooding("flooding cells must be diagnostic-only");
    }
    if (cell.attributes !=
            std::map<std::string, std::string>{
                {"noise_profile", cell.axis_value},
                {"timing_contract", "NOT_APPLICABLE"}} ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectFlooding("flooding cell metadata mismatch");
    }
    ValidateFloodingGeometry(cell);

    if (cell.paper_count != 5 || cell.toy_count != 1 ||
        cell.paper_trials != 5 || cell.toy_trials != 1 ||
        cell.paper_counts !=
            std::map<std::string, uint64_t>{{"repetitions_per_pattern", 5}} ||
        cell.toy_counts !=
            std::map<std::string, uint64_t>{{"repetitions_per_pattern", 1}}) {
        RejectFlooding("flooding paper/toy repetitions do not match contract");
    }
    if (cell.expected_rows.size() != 3u) {
        RejectFlooding("flooding cells require zero, random, and adversarial rows");
    }
    const char* patterns[] = {"zero", "random", "adversarial"};
    for (size_t index = 0; index < 3u; ++index) {
        ValidateFloodingRow(cell.expected_rows.at(index), patterns[index]);
    }
}

std::string FloodingProfileForMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::DryRun:
            return "paper-v1";
        case RevisionRunMode::Toy:
            return "readiness-toy-v1";
    }
    RejectFlooding("unknown run mode");
}

}  // namespace

RevisionInvocationPlan PlanFloodingRevisionCell(const RevisionCell& cell,
                                                RevisionRunMode mode) {
    ValidateFloodingCell(cell);

    const std::string profile = FloodingProfileForMode(mode);
    const bool toy = IsToyMode(mode);
    if (toy && cell.axis_value != "primary40") {
        RejectFlooding("Toy planning supports only the primary40 profile");
    }

    RevisionInvocationPlan plan = MakePlan(cell, mode, cell.profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--run-profile=" + profile,
        "--profile=" + cell.axis_value,
        std::string("--repetitions=") +
            (toy ? std::to_string(cell.toy_count)
                 : std::to_string(cell.paper_count)),
        "--results-root={output}",
        "--seed={seed}",
        "--threads={threads}",
    };
    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

namespace {

[[noreturn]] void RejectRealDataset(const std::string& reason) {
    throw std::invalid_argument(
        "invalid real-dataset revision invocation cell: " + reason);
}

std::string RealDatasetVariant(const RevisionCell& cell) {
    const auto it = cell.axes.find("variant");
    if (it == cell.axes.end()) {
        RejectRealDataset("missing variant axis");
    }
    if (it->second != "dblp_acm_u65536" &&
        it->second != "enron_u65536" &&
        it->second != "enron_u1048576") {
        RejectRealDataset("unsupported dataset variant");
    }
    return it->second;
}

void ValidateRealDatasetRow(const RevisionRow& row,
                            const std::string& artifact,
                            const std::string& variant,
                            uint64_t paper_count,
                            bool diagnostic) {
    const std::string expected_status = diagnostic ? "DIAGNOSTIC" : "MEASURED";
    if (row.row_id != artifact || row.status != expected_status ||
        row.reason != "" || row.reason_code != "" ||
        row.terminal_status != expected_status || row.method != artifact ||
        row.variant != variant || !row.timing_contract.empty() ||
        !row.raw_timing_contract.empty() || !row.phase.empty() ||
        !row.pattern.empty() || !row.fit_authority.empty() ||
        !row.truth_bases.empty() || !row.field_values.empty() ||
        !row.attributes.empty() || !row.list_attributes.empty() ||
        row.measured_count != paper_count ||
        row.paper_measured_count != paper_count ||
        row.toy_measured_count != 1) {
        RejectRealDataset("real-dataset expected row contract mismatch");
    }
}

void ValidateRealDatasetCell(const RevisionCell& cell) {
    if (cell.family != "real_dataset") {
        RejectRealDataset("family must be real_dataset");
    }

    const std::string variant = RealDatasetVariant(cell);
    const bool dblp = variant == "dblp_acm_u65536";
    const std::string expected_dataset = dblp ? "dblp_acm" : "enron";
    const std::string expected_universe =
        variant == "enron_u1048576" ? "1048576" : "65536";
    const std::string artifact = cell.axis_value;
    if (artifact != "accuracy" && artifact != "summary" &&
        artifact != "std128_timing" && artifact != "std192_encoding") {
        RejectRealDataset(
            "only accuracy, summary, std128_timing, and std192_encoding "
            "artifacts are supported");
    }
    const bool encoding = artifact == "std192_encoding";

    const std::string expected_producer =
        artifact == "summary" ? "summarize_real_datasets.py"
                               : "bench_real_datasets";
    if (cell.producer != expected_producer) {
        RejectRealDataset("producer does not match artifact");
    }
    if (cell.profile != "paper-v1") {
        RejectRealDataset("matrix profile must be paper-v1");
    }
    if (cell.dataset != expected_dataset) {
        RejectRealDataset("dataset does not match variant");
    }
    if (cell.axis != variant + "_artifact" ||
        cell.cell_id != "paper-v1::real_dataset::" + cell.axis + "=" +
                            artifact) {
        RejectRealDataset("cell ID or artifact axis does not bind variant");
    }
    if (cell.expected_artifact_schema != "real-dataset-csv-v1") {
        RejectRealDataset("unexpected real-dataset artifact schema");
    }
    if (cell.invocation_status != "RUN") {
        RejectRealDataset("cell is not RUN");
    }
    if (cell.timeout_class != "standard") {
        RejectRealDataset("timeout class must be standard");
    }
    const std::string expected_eligibility =
        encoding ? "DIAGNOSTIC_ONLY" : "TABLE_ELIGIBLE";
    const bool expected_table_eligible = !encoding;
    const bool expected_comparison_eligible = !encoding;
    if (cell.eligibility != expected_eligibility ||
        cell.table_eligible != expected_table_eligible ||
        cell.comparison_eligible != expected_comparison_eligible) {
        RejectRealDataset("real-dataset eligibility does not match artifact");
    }

    const std::map<std::string, std::string> expected_axes = {
        {"artifact", artifact}, {"k", "128"}, {"m", "64"},
        {"n", "1000"}, {"u", expected_universe}, {"variant", variant}};
    if (cell.axes != expected_axes) {
        RejectRealDataset("real-dataset axes do not match variant contract");
    }
    const std::map<std::string, std::string> expected_attributes = {
        {"artifact_kind", artifact},
        {"threshold_forbidden", dblp ? "false" : "true"},
        {"variant", variant}};
    if (cell.attributes != expected_attributes ||
        !cell.list_attributes.empty() || !cell.object_attributes.empty()) {
        RejectRealDataset("real-dataset cell attributes do not match contract");
    }

    const uint64_t paper_count =
        artifact == "std128_timing" || encoding ? 30 : 1;
    std::map<std::string, uint64_t> expected_paper_counts = {
        {artifact, paper_count}};
    std::map<std::string, uint64_t> expected_toy_counts = {
        {artifact, 1}};
    if (encoding) {
        expected_paper_counts.emplace("correctness", 1);
        expected_toy_counts.emplace("correctness", 1);
    }
    if (cell.paper_count != paper_count || cell.toy_count != 1 ||
        cell.paper_trials != paper_count || cell.toy_trials != 1 ||
        cell.paper_counts != expected_paper_counts ||
        cell.toy_counts != expected_toy_counts) {
        RejectRealDataset("real-dataset paper/toy counts do not match contract");
    }
    if (cell.expected_rows.size() != 1u) {
        RejectRealDataset("real-dataset cells require one expected row");
    }
    ValidateRealDatasetRow(cell.expected_rows.front(), artifact, variant,
                            paper_count, encoding);
}

void ValidateRealDatasetMode(RevisionRunMode mode) {
    switch (mode) {
        case RevisionRunMode::Paper:
        case RevisionRunMode::Toy:
        case RevisionRunMode::DryRun:
            return;
    }
    RejectRealDataset("unknown run mode");
}

}  // namespace

RevisionInvocationPlan PlanRealDatasetRevisionCell(const RevisionCell& cell,
                                                   RevisionRunMode mode) {
    ValidateRealDatasetCell(cell);
    ValidateRealDatasetMode(mode);

    const std::string variant = cell.axes.at("variant");
    const bool accuracy = cell.axis_value == "accuracy";
    const bool timing = cell.axis_value == "std128_timing";
    const bool encoding = cell.axis_value == "std192_encoding";
    const bool toy = mode == RevisionRunMode::Toy;

    RevisionInvocationPlan plan = MakePlan(cell, mode, cell.profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.invocation_status = cell.invocation_status;
    if (timing) {
        const std::string profile =
            toy ? "readiness-toy-v1" : "paper-std128-t40-v1";
        plan.concrete_profile = profile;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--mode=timing",
            "--dataset-manifest={variant_manifest}",
            "--profile=" + profile,
            std::string("--security=") + (toy ? "TOY" : "STD128"),
            "--k=128",
            "--m=64",
            std::string("--trials=") + (toy ? "1" : "30"),
            "--seed={seed}",
            "--raw-timing-dir={output}/raw",
            std::string("--raw-timing-profile=") +
                (toy ? "readiness-toy-v1" : "paper-v1"),
            "--csv={output}/timing.csv",
            "--workload-manifest-out={output}/timing.manifest.tsv",
        };
    } else if (encoding) {
        const std::string profile =
            toy ? "readiness-toy-v1" : "paper-std192-encoding-v1";
        plan.concrete_profile = profile;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--mode=encoding",
            "--dataset-manifest={variant_manifest}",
            "--profile=" + profile,
            "--methods=onehot,sqrt",
            "--k=128",
            "--m=64",
            std::string("--encoding-iters=") + (toy ? "1" : "30"),
            "--correctness-trials=1",
            "--seed={seed}",
            "--csv={output}/encoding.csv",
            "--workload-manifest-out={output}/encoding.manifest.tsv",
        };
    } else if (accuracy) {
        plan.concrete_profile = cell.profile;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--mode=accuracy",
            "--dataset-manifest={variant_manifest}",
            "--max-pairs={max_pairs}",
            "--seed={seed}",
            "--csv={output}/accuracy.csv",
            "--workload-manifest-out={output}/accuracy.manifest.tsv",
            "--workload-rows-out={output}/accuracy.rows.tsv",
        };
    } else {
        plan.concrete_profile = cell.profile;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--accuracy-csv={output}/accuracy.csv",
            "--output={output}/summary.csv",
            "--variant=" + variant,
        };
    }

    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanThresholdRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode) {
    if (cell.family == "threshold_dblp_fpfn") {
        ValidateRealThresholdCell(cell);

        const bool toy = IsToyMode(mode);
        const std::string profile = ThresholdProfileForMode(mode);

        RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
        plan.cell_id = cell.cell_id;
        plan.producer = cell.producer;
        plan.concrete_profile = profile;
        plan.invocation_status = cell.invocation_status;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--mode=threshold",
            "--dataset-manifest={dblp_acm_u65536_manifest}",
            "--k=128",
            "--m=64",
            std::string("--threshold-trials=") + (toy ? "1" : "50"),
            "--seed={seed}",
            "--hash_randomness=resampled",
            "--csv={output}/threshold.csv",
            "--workload-manifest-out={output}/threshold.manifest.tsv",
            "--workload-rows-out={output}/threshold.rows.tsv",
        };
        plan.expected_rows = cell.expected_rows;
        for (auto& row : plan.expected_rows) {
            row.measured_count = toy ? row.toy_measured_count
                                     : row.paper_measured_count;
        }
        return plan;
    }

    if (cell.family == "threshold_synthetic_fpfn") {
        ValidateThresholdSyntheticCell(cell);

        const bool toy = IsToyMode(mode);
        const std::string profile = ThresholdProfileForMode(mode);
        const auto& point_k = cell.axes.at("k");
        const auto& grid_index = cell.axes.at("grid_index");

        RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
        plan.cell_id = cell.cell_id;
        plan.producer = cell.producer;
        plan.concrete_profile = profile;
        plan.invocation_status = cell.invocation_status;
        plan.argv = {
            "--revision-cell=" + cell.cell_id,
            "--profile=" + profile,
            "--mode=fpfn",
            "--point-k=" + point_k,
            "--grid-index=" + grid_index,
            "--m=64",
            "--set_size=1000",
            std::string("--trials=") + (toy ? "1" : "1000"),
            "--seed={seed}",
            "--hash_randomness=resampled",
        };
        plan.expected_rows = cell.expected_rows;
        for (auto& row : plan.expected_rows) {
            row.measured_count = toy ? row.toy_measured_count
                                     : row.paper_measured_count;
        }
        return plan;
    }

    ValidateThresholdFheCell(cell);

    const bool toy = IsToyMode(mode);
    const std::string profile = ThresholdProfileForMode(mode);
    const std::string kind = ThresholdCellKind(cell);
    const auto& k = cell.axes.at("k");
    const std::string trials =
        toy ? "1" : (kind == "timing" ? "30" :
                     (kind == "spec" ? "0" : "50"));

    RevisionInvocationPlan plan = MakePlan(cell, mode, profile);
    plan.cell_id = cell.cell_id;
    plan.producer = cell.producer;
    plan.concrete_profile = profile;
    plan.invocation_status = cell.invocation_status;
    plan.argv = {
        "--revision-cell=" + cell.cell_id,
        "--profile=" + profile,
        "--mode=" + (kind == "agreement" ? "accuracy" : kind),
        "--cell=" + kind,
        std::string("--security=") + (toy ? "TOY" : "STD128"),
        "--k=" + k,
        "--m=64",
        "--set_size=1000",
        "--trials=" + trials,
        "--seed={seed}",
    };

    plan.expected_rows = cell.expected_rows;
    for (auto& row : plan.expected_rows) {
        row.measured_count = toy ? row.toy_measured_count
                                 : row.paper_measured_count;
    }
    return plan;
}

RevisionInvocationPlan PlanRevisionCell(const RevisionCell& cell,
                                        RevisionRunMode mode) {
    if (cell.family == "piccard_std128") {
        return PlanPiccardRevisionCell(cell, mode);
    }
    if (cell.family == "fhe_ind") {
        return PlanFheIndRevisionCell(cell, mode);
    }
    if (cell.family == "estimator_accuracy") {
        return PlanEstimatorRevisionCell(cell, mode);
    }
    if (cell.family == "deletion_exact" || cell.family == "deletion_mc") {
        return PlanDeletionRevisionCell(cell, mode);
    }
    if (cell.family == "sqrt_comparison") {
        return PlanSqrtRevisionCell(cell, mode);
    }
    if (cell.family == "piccard_std192_encoding") {
        return PlanStd192EncodingRevisionCell(cell, mode);
    }
    if (cell.family == "bcg12_minhash" || cell.family == "bcg12_exact") {
        return PlanBcg12RevisionCell(cell, mode);
    }
    if (cell.family == "sj16") {
        return PlanSj16RevisionCell(cell, mode);
    }
    if (cell.family == "dynamic_timing" ||
        cell.family == "dynamic_accuracy" ||
        cell.family == "dynamic_refresh") {
        return PlanDynamicRevisionCell(cell, mode);
    }
    if (cell.family == "flooding") {
        return PlanFloodingRevisionCell(cell, mode);
    }
    if (cell.family == "real_dataset") {
        return PlanRealDatasetRevisionCell(cell, mode);
    }
    if (cell.family == "threshold_timing" || cell.family == "threshold_spec" ||
        cell.family == "threshold_agreement" ||
        cell.family == "threshold_synthetic_fpfn" ||
        cell.family == "threshold_dblp_fpfn") {
        return PlanThresholdRevisionCell(cell, mode);
    }
    throw std::invalid_argument(
        "invalid revision invocation family: " + cell.family);
}

}  // namespace piccard::benchmark
