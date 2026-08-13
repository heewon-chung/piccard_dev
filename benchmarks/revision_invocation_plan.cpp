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

RevisionInvocationPlan PlanPiccardRevisionCell(const RevisionCell& cell,
                                               RevisionRunMode mode) {
    ValidateCell(cell);

    const std::string profile = ProfileForMode(mode);
    const bool toy = IsToyMode(mode);
    const auto& k = cell.axes.at("k");
    const auto& m = cell.axes.at("m");
    const auto& n = cell.axes.at("n");
    const auto& u = cell.axes.at("u");

    RevisionInvocationPlan plan;
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

    RevisionInvocationPlan plan;
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

    RevisionInvocationPlan plan;
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

    RevisionInvocationPlan plan;
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

RevisionInvocationPlan PlanThresholdRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode) {
    if (cell.family == "threshold_dblp_fpfn") {
        ValidateRealThresholdCell(cell);

        const bool toy = IsToyMode(mode);
        const std::string profile = ThresholdProfileForMode(mode);

        RevisionInvocationPlan plan;
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

        RevisionInvocationPlan plan;
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

    RevisionInvocationPlan plan;
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

}  // namespace piccard::benchmark
