#include "benchmark_estimator_provenance.h"
#include "dynamic_refresh_benchmark.h"
#include "protocol/dynamic_piccard.h"
#include "util/params.h"

#include <cmath>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace piccard::benchmark {
namespace {

std::vector<std::string> SplitComma(const std::string& line) {
    std::vector<std::string> cells;
    std::stringstream stream(line);
    std::string cell;
    while (std::getline(stream, cell, ',')) cells.push_back(cell);
    if (!cells.empty() && !cells.back().empty() && cells.back().back() == '\n') {
        cells.back().pop_back();
    }
    return cells;
}

size_t Column(const std::vector<std::string>& header, const std::string& name) {
    for (size_t index = 0; index < header.size(); ++index) {
        if (header[index] == name) return index;
    }
    throw std::runtime_error("missing column: " + name);
}

TEST(DynamicRefreshBenchmarkTest, SerializesAllRefreshFieldsByName) {
    DynamicResult row;
    row.label = "refresh";
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = NotApplicableSanitizerMetadata();
    row.provenance = MakeAheBenchmarkProvenance();
    row.dynamic_scenario = "refresh";
    row.refresh_owner_set_id = "owner-a";
    row.refresh_updates = 1;
    row.refresh_epoch_before = 0;
    row.refresh_epoch_after = 1;
    row.refresh_status = "applied";
    row.phase_refresh_update_ms = 1;
    row.phase_refresh_signature_ms = 2;
    row.phase_refresh_encode_ms = 3;
    row.phase_refresh_encrypt_ms = 4;
    row.phase_refresh_serialize_ms = 5;
    row.phase_cloud_replace_ms = 6;
    row.refresh_total_ms = 21;
    row.refresh_upload_bytes = 99;
    row.refresh_ciphertexts_uploaded = 1;
    row.refresh_context_fingerprint = "context";
    row.refresh_public_key_fingerprint = "public-key";

    const auto header = SplitComma(SerializeDynamicHeader());
    const auto cells = SplitComma(SerializeDynamicRow(row, row.provenance));
    EXPECT_EQ(cells[Column(header, "dynamic_scenario")], "refresh");
    EXPECT_EQ(cells[Column(header, "refresh_owner_set_id")], "owner-a");
    EXPECT_EQ(cells[Column(header, "refresh_updates")], "1");
    EXPECT_EQ(cells[Column(header, "refresh_epoch_before")], "0");
    EXPECT_EQ(cells[Column(header, "refresh_epoch_after")], "1");
    EXPECT_EQ(cells[Column(header, "refresh_status")], "applied");
    EXPECT_EQ(cells[Column(header, "phase_refresh_update_ms")], "1.000");
    EXPECT_EQ(cells[Column(header, "phase_refresh_signature_ms")], "2.000");
    EXPECT_EQ(cells[Column(header, "phase_refresh_encode_ms")], "3.000");
    EXPECT_EQ(cells[Column(header, "phase_refresh_encrypt_ms")], "4.000");
    EXPECT_EQ(cells[Column(header, "phase_refresh_serialize_ms")], "5.000");
    EXPECT_EQ(cells[Column(header, "phase_cloud_replace_ms")], "6.000");
    EXPECT_EQ(cells[Column(header, "refresh_total_ms")], "21.000");
    EXPECT_EQ(cells[Column(header, "refresh_upload_bytes")], "99");
    EXPECT_EQ(cells[Column(header, "refresh_ciphertexts_uploaded")], "1");
    EXPECT_EQ(cells[Column(header, "refresh_context_fingerprint")], "context");
    EXPECT_EQ(cells[Column(header, "refresh_public_key_fingerprint")], "public-key");
}

TEST(DynamicRefreshBenchmarkTest, MeasuresExactlyOneOwnerZeroToOne) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.bottom_depth = 5;
    params.hash_seed = 7;
    params.security = SecurityLevel::TOY;
    params.Validate();
    DynamicPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> a;
    std::vector<uint64_t> b;
    for (uint64_t value = 0; value < 100; ++value) a.push_back(value);
    for (uint64_t value = 50; value < 150; ++value) b.push_back(value);

    const DynamicResult row = RunSingleOwnerRefresh(engine, a, b, 5, 1);
    EXPECT_EQ(row.dynamic_scenario, "refresh");
    EXPECT_EQ(row.refresh_owner_set_id, "owner-a");
    EXPECT_EQ(row.refresh_updates, 1u);
    EXPECT_EQ(row.refresh_epoch_before, 0u);
    EXPECT_EQ(row.refresh_epoch_after, 1u);
    EXPECT_EQ(row.refresh_status, "applied");
    EXPECT_EQ(row.refresh_ciphertexts_uploaded, 1u);
    ASSERT_TRUE(row.refresh_upload_bytes.has_value());
    EXPECT_GT(*row.refresh_upload_bytes, 0u);
    ASSERT_TRUE(row.refresh_total_ms.has_value());
    EXPECT_DOUBLE_EQ(row.total_ms, *row.refresh_total_ms);
    EXPECT_DOUBLE_EQ(row.total_ms_median, row.total_ms);
    EXPECT_DOUBLE_EQ(row.total_ms_sd, -1.0);
    EXPECT_DOUBLE_EQ(row.phase_insert_ms, *row.phase_refresh_update_ms);
    EXPECT_DOUBLE_EQ(row.phase_signature_ms, *row.phase_refresh_signature_ms);
    EXPECT_DOUBLE_EQ(row.phase_encode_ms, *row.phase_refresh_encode_ms);
    EXPECT_DOUBLE_EQ(row.phase_encrypt_ms, *row.phase_refresh_encrypt_ms);
    EXPECT_DOUBLE_EQ(row.phase_insert_ms_median, row.phase_insert_ms);
    EXPECT_DOUBLE_EQ(row.phase_signature_ms_median, row.phase_signature_ms);
    EXPECT_DOUBLE_EQ(row.phase_encode_ms_median, row.phase_encode_ms);
    EXPECT_DOUBLE_EQ(row.phase_encrypt_ms_median, row.phase_encrypt_ms);
    EXPECT_EQ(row.ct_size_bytes, *row.refresh_upload_bytes);
    EXPECT_DOUBLE_EQ(row.jaccard_error, std::abs(row.jaccard_computed - row.jaccard_expected));
    ASSERT_GT(row.jaccard_expected, 0.0);
    EXPECT_DOUBLE_EQ(row.jaccard_rel_error, row.jaccard_error / row.jaccard_expected);
    EXPECT_EQ(row.rel_error_eligible_n, 1u);
    EXPECT_EQ(row.trials, 1u);
}

TEST(DynamicRefreshBenchmarkTest, RejectsRefreshValueSpaceOverflowBeforeTiming) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.bottom_depth = 5;
    params.hash_seed = 7;
    params.security = SecurityLevel::TOY;
    params.Validate();
    DynamicPiccard engine(params);
    engine.KeyGen();

    const std::vector<uint64_t> a{std::numeric_limits<uint64_t>::max()};
    const std::vector<uint64_t> b{0};
    EXPECT_THROW(RunSingleOwnerRefresh(engine, a, b, 5, 1),
                 std::invalid_argument);
}

}  // namespace
}  // namespace piccard::benchmark
