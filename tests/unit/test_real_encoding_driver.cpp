#include "real_encoding_driver.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using piccard::bench::RealEncodingCliArgs;
using piccard::bench::RunRealEncodingMode;
namespace fs = std::filesystem;

std::vector<std::string> SplitCsvLine(const std::string& line) {
    std::vector<std::string> fields;
    size_t begin = 0;
    while (true) {
        const size_t comma = line.find(',', begin);
        if (comma == std::string::npos) {
            fields.push_back(line.substr(begin));
            break;
        }
        fields.push_back(line.substr(begin, comma - begin));
        begin = comma + 1;
    }
    return fields;
}

std::vector<std::string> ReadLines(const fs::path& path) {
    std::ifstream input(path);
    EXPECT_TRUE(input.good());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

class TemporaryOutputDirectory {
  public:
    TemporaryOutputDirectory() {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("piccard-real-encoding-driver-" + std::to_string(nonce));
        if (!fs::create_directory(path_)) {
            throw std::runtime_error("cannot create temporary encoding output directory");
        }
    }

    ~TemporaryOutputDirectory() { std::error_code ignored; fs::remove_all(path_, ignored); }

    const fs::path& path() const { return path_; }

  private:
    fs::path path_;
};

TEST(RealEncodingDriver,
     RevisionEncodingExecutesBothLocalArmsAndEmitsToyPairMetadata) {
    TemporaryOutputDirectory output;
    RealEncodingCliArgs args;
    args.dataset_manifest_path = PICCARD_REAL_DATASET_QUICK_MANIFEST;
    args.profile_id = "readiness-toy-v1";
    args.methods = {"piccard_encode", "piccard_sqrt_encode"};
    args.revision_methods = true;
    args.k = 128;
    args.m = 64;
    args.trials = 1;
    args.encoding_iters = 1;
    args.correctness_trials = 1;
    args.timing_pair = "median";
    args.root_seed = 7;
    args.csv_path = (output.path() / "encoding.csv").string();
    args.workload_manifest_out_path =
        (output.path() / "encoding.manifest.tsv").string();

    EXPECT_EQ(RunRealEncodingMode(args), 0);

    const auto lines = ReadLines(args.csv_path);
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_NE(lines[0].find("timed_encoder_pairs"), std::string::npos);
    EXPECT_EQ(lines[0].find("ciphertext"), std::string::npos);
    const auto onehot = SplitCsvLine(lines[1]);
    const auto sqrt = SplitCsvLine(lines[2]);
    ASSERT_EQ(onehot.size(), 38u);
    ASSERT_EQ(sqrt.size(), 38u);
    EXPECT_EQ(onehot[22], "piccard_encode");
    EXPECT_EQ(sqrt[22], "piccard_sqrt_encode");
    EXPECT_EQ(onehot[23], "1");
    EXPECT_EQ(sqrt[23], "1");
    EXPECT_EQ(onehot[28], "1");
    EXPECT_EQ(sqrt[28], "1");
    EXPECT_EQ(onehot[29], "1");
    EXPECT_EQ(sqrt[29], "1");
    EXPECT_EQ(onehot[25], "7");
    EXPECT_EQ(sqrt[25], "7");
    EXPECT_EQ(onehot[36], "PASS");
    EXPECT_EQ(sqrt[36], "PASS");

    const auto workload = ReadLines(args.workload_manifest_out_path);
    ASSERT_FALSE(workload.empty());
    EXPECT_NE(std::find(workload.begin(), workload.end(),
                        "methods\tpiccard_encode,piccard_sqrt_encode"),
              workload.end());
    EXPECT_NE(std::find(workload.begin(), workload.end(), "timed_encoder_pairs\t1"),
              workload.end());
}

}  // namespace
