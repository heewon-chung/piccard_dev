#include "comparison_workload.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

#ifndef PICCARD_STD_EVIDENCE_BINARY
#error "CMake must bind the integration test to bench_std_security_evidence"
#endif

std::string Quote(const std::string& value) {
    std::string quoted = "'";
    for (const char ch : value) {
        if (ch == '\'') quoted += "'\\''";
        else quoted.push_back(ch);
    }
    quoted.push_back('\'');
    return quoted;
}

int RunCommand(const std::string& command) {
    return std::system(command.c_str());
}

std::string Read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

std::vector<std::string> SplitCsv(const std::string& line) {
    std::vector<std::string> fields;
    size_t begin = 0;
    for (size_t index = 0; index <= line.size(); ++index) {
        if (index == line.size() || line[index] == ',') {
            fields.push_back(line.substr(begin, index - begin));
            begin = index + 1;
        }
    }
    return fields;
}

std::vector<std::string> CsvRows(const std::filesystem::path& path) {
    std::istringstream input(Read(path));
    std::string line;
    std::vector<std::string> rows;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) rows.push_back(line);
    }
    return rows;
}

std::map<std::string, size_t> HeaderMap(const std::vector<std::string>& fields) {
    std::map<std::string, size_t> result;
    for (size_t index = 0; index < fields.size(); ++index) {
        result.emplace(fields[index], index);
    }
    return result;
}

void ExpectOneMeasuredCsv(const std::filesystem::path& path,
                          const std::string& expected_circuit) {
    const auto rows = CsvRows(path);
    ASSERT_EQ(rows.size(), 2u);
    const auto header = HeaderMap(SplitCsv(rows[0]));
    const auto fields = SplitCsv(rows[1]);
    ASSERT_EQ(fields.size(), header.size());
    ASSERT_EQ(fields[header.at("circuit")], expected_circuit);
    EXPECT_EQ(fields[header.at("trials")], "1");
    EXPECT_EQ(fields[header.at("status")], "MEASURED");
    EXPECT_FALSE(fields[header.at("context_tuple_sha256")].empty());
    EXPECT_FALSE(fields[header.at("calibration_artifact_sha256")].empty());
    EXPECT_FALSE(fields[header.at("workload_manifest_sha256")].empty());

    const double minhash = std::stod(fields[header.at("phase_minhash_ms")]);
    const double encode = std::stod(fields[header.at("phase_encode_ms")]);
    const double encrypt = std::stod(fields[header.at("phase_encrypt_ms")]);
    const double evaluate = std::stod(fields[header.at("phase_evaluate_ms")]);
    const double flood = std::stod(fields[header.at("phase_flood_ms")]);
    const double decrypt = std::stod(fields[header.at("phase_decrypt_ms")]);
    const double online = std::stod(fields[header.at("online_e2e_ms")]);
    const double context = std::stod(fields[header.at("setup_context_ms")]);
    const double keygen = std::stod(fields[header.at("setup_keygen_ms")]);
    const double full = std::stod(fields[header.at("full_e2e_ms")]);
    EXPECT_NEAR(online, minhash + encode + encrypt + evaluate + flood + decrypt,
                1e-6);
    EXPECT_NEAR(full, context + keygen + online, 1e-6);
    const int match_count = std::stoi(fields[header.at("match_count")]);
    EXPECT_GE(match_count, 0);
    EXPECT_LE(match_count, 16);
}

struct TempFiles {
    std::vector<std::filesystem::path> paths;
    ~TempFiles() {
        for (const auto& path : paths) std::filesystem::remove(path);
    }
};

}  // namespace

TEST(StdSecurityEvidenceE2E, SharedTimingWorkloadAndSingleRunCsv) {
    const auto root = std::filesystem::path("/tmp") /
                      ("piccard-std-evidence-e2e-" +
                       std::to_string(static_cast<long long>(getpid())));
    std::filesystem::create_directories(root);
    TempFiles files{{root / "workload.json", root / "onehot-calibration.json",
                     root / "sqrt-calibration.json", root / "onehot.csv",
                     root / "sqrt.csv", root / "threshold.log",
                     root / "mismatch.log"}};
    const std::string binary = Quote(PICCARD_STD_EVIDENCE_BINARY);
    const std::string workload = Quote(files.paths[0].string());
    ASSERT_EQ(RunCommand(binary + " --mode=workload --output=" + workload), 0);

    const auto generated = piccard::benchmark::ComparisonWorkload::Generate({
        "toy-smoke", "toy-smoke", 7, 16, 16, 10, 64, {1, 2},
        {"piccard", "piccard_sqrt", "bcg12_mh_ec", "bcg12_exact_ec", "sj16"},
        1, 1});
    EXPECT_FALSE(generated.ManifestSha256Hex().empty());
    ASSERT_EQ(generated.Records().size(), 3u);
    EXPECT_EQ(generated.Records()[0].kind,
              piccard::benchmark::TrialKind::Warmup);
    EXPECT_EQ(generated.Records()[1].kind,
              piccard::benchmark::TrialKind::Timing);
    EXPECT_EQ(generated.Records()[1].index, 0u);
    EXPECT_EQ(generated.Records()[2].kind,
              piccard::benchmark::TrialKind::Accuracy);
    EXPECT_EQ(generated.Records()[2].index, 0u);

    const std::string onehot_calibration = Quote(files.paths[1].string());
    const std::string sqrt_calibration = Quote(files.paths[2].string());
    ASSERT_EQ(RunCommand(binary +
                  " --mode=calibrate --circuit=onehot --security=STD128"
                  " --depth=3 --scaling-mod-size=45 --output=" +
                  onehot_calibration),
              0);
    ASSERT_EQ(RunCommand(binary +
                  " --mode=calibrate --circuit=sqrt --security=STD128"
                  " --depth=4 --scaling-mod-size=40 --output=" +
                  sqrt_calibration),
              0);

    ASSERT_EQ(RunCommand(binary + " --mode=e2e --calibration=" + onehot_calibration +
                  " --workload=" + workload + " --format=csv --output=" +
                  Quote(files.paths[3].string())),
              0);
    ASSERT_EQ(RunCommand(binary + " --mode=e2e --calibration=" + sqrt_calibration +
                  " --workload=" + workload + " --format=csv --output=" +
                  Quote(files.paths[4].string())),
              0);
    ExpectOneMeasuredCsv(files.paths[3], "onehot");
    ExpectOneMeasuredCsv(files.paths[4], "sqrt");

    const auto onehot_fields = SplitCsv(CsvRows(files.paths[3])[1]);
    const auto sqrt_fields = SplitCsv(CsvRows(files.paths[4])[1]);
    const auto header = HeaderMap(SplitCsv(CsvRows(files.paths[3])[0]));
    EXPECT_EQ(onehot_fields[header.at("workload_manifest_sha256")],
              sqrt_fields[header.at("workload_manifest_sha256")]);
    EXPECT_EQ(onehot_fields[header.at("timing_hash_seed")],
              sqrt_fields[header.at("timing_hash_seed")]);
    EXPECT_EQ(onehot_fields[header.at("match_count")],
              sqrt_fields[header.at("match_count")]);
    EXPECT_NE(onehot_fields[header.at("context_tuple_sha256")],
              sqrt_fields[header.at("context_tuple_sha256")]);

    EXPECT_NE(RunCommand(binary + " --mode=e2e --calibration=" + onehot_calibration +
                  " --workload=" + workload + " --format=csv --circuit=threshold"
                  " >/dev/null 2>" + Quote(files.paths[5].string())),
              0);
    EXPECT_NE(RunCommand(binary + " --mode=e2e --calibration=" + onehot_calibration +
                  " --workload=" + workload + " --format=csv --security=STD192"
                  " >/dev/null 2>" + Quote(files.paths[6].string())),
              0);
}
