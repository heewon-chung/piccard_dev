#pragma once

/**
 * @file revision_matrix.h
 * @brief Typed reader and fail-closed validator for the Phase 9 matrix.
 *
 * The checked-in JSON is the only matrix source of truth.  This small parser
 * intentionally has no OpenFHE dependency: configuration and topology tests
 * must be able to run without constructing a crypto context or invoking a
 * benchmark producer.
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief One terminal row expected from a single producer invocation. */
struct RevisionRow {
    std::string row_id;
    std::string status;
    std::string reason;
    uint64_t measured_count = 0;
    uint64_t paper_measured_count = 0;
    uint64_t toy_measured_count = 0;
};

/** @brief One invocation cell in the canonical paper matrix. */
struct RevisionCell {
    std::string cell_id;
    std::string family;
    std::string producer;
    std::string profile;
    std::string dataset;
    std::map<std::string, std::string> axes;
    std::string axis;
    std::string axis_value;
    uint64_t paper_count = 0;
    uint64_t toy_count = 0;
    uint64_t paper_trials = 0;
    uint64_t toy_trials = 0;
    std::string eligibility;
    bool table_eligible = false;
    bool comparison_eligible = false;
    std::string timeout_class;
    std::string expected_artifact_schema;
    std::string invocation_status;
    std::vector<RevisionRow> expected_rows;
};

/** @brief Parsed canonical matrix document. */
struct RevisionMatrix {
    std::string schema;
    uint32_t version = 0;
    std::string id_grammar;
    uint64_t cell_count = 0;
    std::map<std::string, uint64_t> family_counts;
    std::vector<RevisionCell> cells;
};

/** @brief Parse a matrix JSON file without applying producer side effects. */
RevisionMatrix LoadRevisionMatrix(const std::filesystem::path& path);

/** @brief Validate schema, cardinalities, IDs, rows, and frozen literals. */
void ValidateRevisionMatrix(const RevisionMatrix& matrix);

/** @brief Parse and validate one matrix file in a single call. */
RevisionMatrix LoadAndValidateRevisionMatrix(
    const std::filesystem::path& path);

/** @brief Return cell IDs in canonical sorted order. */
std::vector<std::string> RevisionMatrixCellIds(
    const RevisionMatrix& matrix);

}  // namespace benchmark
}  // namespace piccard
