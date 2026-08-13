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

uint64_t Axis(const RevisionCell& cell, const char* name) {
    const auto it = cell.axes.find(name);
    if (it == cell.axes.end()) Reject(std::string("missing axis ") + name);
    return ParseUnsigned(it->second, name);
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

}  // namespace piccard::benchmark
