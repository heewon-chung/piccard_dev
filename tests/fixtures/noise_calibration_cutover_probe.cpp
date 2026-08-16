#include "util/params.h"
#include "util/params_calibration.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <tuple>
#include <vector>

using piccard::Circuit;
using piccard::PiccardParams;
using piccard::PreThresholdCalibrationRequest;
using piccard::SecurityLevel;

namespace {

struct ProbeEntry {
    PreThresholdCalibrationRequest key;
    uint32_t k;
    uint32_t m;
    bool accepted_infeasible;
};

std::vector<ProbeEntry> CanonicalMatrix() {
    return {

        {{"feasibility128", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 8192, 1, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, false},
        {{"feasibility128", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 16384, 1, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, true},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 8192, 1, "cb51c8b1903a4935a7ea7f75e958faa75cc30e9c9cf2a944b06b5991093ffdbb", "1.5.0"}, 16, 64, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 16384, 1, "2904c359723542ab4017b6f229f229c8ce78f5cf6ec15089c56b728b938309ff", "1.5.0"}, 64, 256, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 32768, 1, "d968642db19cc6236ffdefaf473f1118cda80a3be15373a090229b4427498e26", "1.5.0"}, 32, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 65536, 1, "e00422a411632406f826100f5bd784dc4e3126dfa5d17b7909ee7cd66d15af8e", "1.5.0"}, 64, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 131072, 1, "96270d9a505be9f5ae0f845312929f3420a09fcdcb2405be8ba46cb1c059224b", "1.5.0"}, 128, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 262144, 1, "d5e19cbee700409a26972847e400babf579eb2fc6dc3fb2e07266036e26de54c", "1.5.0"}, 256, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 524288, 1, "83e964976cc8f1acaca9ca5551e73de68eb535d7b2423bc2439d633384db1a68", "1.5.0"}, 512, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 16384, 1, "7dfa68774daa7d9f43487157ef298b9fbb09659ac271a6fc6c5b7437da55542b", "1.5.0"}, 16, 64, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 32768, 1, "d968642db19cc6236ffdefaf473f1118cda80a3be15373a090229b4427498e26", "1.5.0"}, 32, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 65536, 1, "e00422a411632406f826100f5bd784dc4e3126dfa5d17b7909ee7cd66d15af8e", "1.5.0"}, 64, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 131072, 1, "96270d9a505be9f5ae0f845312929f3420a09fcdcb2405be8ba46cb1c059224b", "1.5.0"}, 128, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 262144, 1, "d5e19cbee700409a26972847e400babf579eb2fc6dc3fb2e07266036e26de54c", "1.5.0"}, 256, 1024, false},
        {{"primary40", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 524288, 1, "83e964976cc8f1acaca9ca5551e73de68eb535d7b2423bc2439d633384db1a68", "1.5.0"}, 512, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b16-v1", SecurityLevel::STD128, 8192, 3, "2017a4b9f39b93a88da375d6301ed811e01b8d6014b3d0136d89df69afda8e30", "1.5.0"}, 32, 256, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b16-v1", SecurityLevel::STD128, 16384, 3, "8c894da754850ffc42ddae06bfde8ef7077d49b3ec46b5d4f31352727c5f0ade", "1.5.0"}, 512, 256, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b16-v1", SecurityLevel::STD192, 16384, 3, "d6e6e19d668edc9aa8da10247863e580639772e78da3aec73b810f1c1a7c0bac", "1.5.0"}, 32, 256, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b2-v1", SecurityLevel::STD128, 8192, 3, "a3abd82bbd7155f77f50af4ab82cd8424fb985a3ca54792020cd9d0e2ae27ce5", "1.5.0"}, 32, 4, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b2-v1", SecurityLevel::STD192, 16384, 3, "a3abd82bbd7155f77f50af4ab82cd8424fb985a3ca54792020cd9d0e2ae27ce5", "1.5.0"}, 32, 4, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b32-v1", SecurityLevel::STD128, 8192, 3, "945aa1c13c085cd81586a382a648246491cb63ba00429e94f32e79f21bc426ae", "1.5.0"}, 32, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b32-v1", SecurityLevel::STD128, 16384, 3, "d5e19cbee700409a26972847e400babf579eb2fc6dc3fb2e07266036e26de54c", "1.5.0"}, 256, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b32-v1", SecurityLevel::STD128, 32768, 3, "83e964976cc8f1acaca9ca5551e73de68eb535d7b2423bc2439d633384db1a68", "1.5.0"}, 512, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b32-v1", SecurityLevel::STD192, 16384, 3, "03affad837c694d07b2f5b1f7f7f8cd140546eac8b3076f5ae47f6390915f08d", "1.5.0"}, 32, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b32-v1", SecurityLevel::STD192, 32768, 3, "83e964976cc8f1acaca9ca5551e73de68eb535d7b2423bc2439d633384db1a68", "1.5.0"}, 512, 1024, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b4-v1", SecurityLevel::STD128, 8192, 3, "7388ce7b987f89ed240b125603b09fae9b3d782886af736d84a16719bec37a11", "1.5.0"}, 32, 16, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b4-v1", SecurityLevel::STD192, 16384, 3, "7388ce7b987f89ed240b125603b09fae9b3d782886af736d84a16719bec37a11", "1.5.0"}, 32, 16, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b8-v1", SecurityLevel::STD128, 8192, 3, "a707f1ffc5b11768f88c942308be718cd1af6438f31fc45e7023019b41996c0e", "1.5.0"}, 16, 64, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b8-v1", SecurityLevel::STD128, 16384, 3, "80ff8b73e5df41a83100dd365fb0ba734469281aafd6203a96c98a040042227e", "1.5.0"}, 1024, 64, false},
        {{"primary40", Circuit::Sqrt, "sqrt-b8-v1", SecurityLevel::STD192, 16384, 3, "c05e6b46b537fbdfabc0344298996fb8a9887d498f4d9b2e1b8813ab16788b12", "1.5.0"}, 16, 64, false},
        {{"sensitivity64", Circuit::OneHot, "onehot-v1", SecurityLevel::STD128, 8192, 1, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, false},
        {{"sensitivity64", Circuit::OneHot, "onehot-v1", SecurityLevel::STD192, 16384, 1, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, false},
        {{"sensitivity64", Circuit::Sqrt, "sqrt-b8-v1", SecurityLevel::STD128, 8192, 3, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, false},
        {{"sensitivity64", Circuit::Sqrt, "sqrt-b8-v1", SecurityLevel::STD192, 16384, 3, "e59fafc3fced2f9d9e1a8a31e9e79b23d53c7894179a6e7261a206cdff997db7", "1.5.0"}, 128, 64, false},

    };
}

std::vector<piccard::LegacyCalibrationSelectionKey> FrozenLegacyKeys() {
    using Key = piccard::LegacyCalibrationSelectionKey;
    return {
        Key{Circuit::OneHot, SecurityLevel::TOY, 1024, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 2048, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 4096, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 8192, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 16384, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 32768, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 65536, 1},
        Key{Circuit::OneHot, SecurityLevel::TOY, 131072, 1},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 1024, 3},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 2048, 3},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 4096, 3},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 8192, 3},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 16384, 3},
        Key{Circuit::Sqrt, SecurityLevel::TOY, 32768, 3},
        Key{Circuit::Threshold, SecurityLevel::TOY, 1024, 4},
        Key{Circuit::Threshold, SecurityLevel::TOY, 1024, 5},
        Key{Circuit::Threshold, SecurityLevel::TOY, 1024, 7},
        Key{Circuit::Threshold, SecurityLevel::TOY, 1024, 9},
        Key{Circuit::Threshold, SecurityLevel::TOY, 1024, 12},
        Key{Circuit::Threshold, SecurityLevel::TOY, 2048, 9},
        Key{Circuit::Threshold, SecurityLevel::TOY, 2048, 15},
        Key{Circuit::Threshold, SecurityLevel::TOY, 4096, 12},
        Key{Circuit::Threshold, SecurityLevel::TOY, 4096, 15},
        Key{Circuit::Threshold, SecurityLevel::TOY, 8192, 15},
        Key{Circuit::Threshold, SecurityLevel::TOY, 16384, 15},
        Key{Circuit::Threshold, SecurityLevel::TOY, 32768, 15},
        Key{Circuit::Threshold, SecurityLevel::STD128, 8192, 7},
        Key{Circuit::Threshold, SecurityLevel::STD128, 8192, 9},
        Key{Circuit::Threshold, SecurityLevel::STD128, 8192, 12},
        Key{Circuit::Threshold, SecurityLevel::STD128, 8192, 15},
        Key{Circuit::Threshold, SecurityLevel::STD128, 16384, 15},
        // k=256 measurement probe (feature_dim 16384 -> Paterson-Stockmeyer
        // natural depth 21); see the threshold row added for the paper run.
        Key{Circuit::Threshold, SecurityLevel::STD128, 16384, 21},
        Key{Circuit::Threshold, SecurityLevel::STD128, 32768, 15},
    };
}

auto LegacyKeyTuple(
    const piccard::LegacyCalibrationSelectionKey& key) {
    return std::make_tuple(
        key.circuit, key.security, key.requested_ring_dim,
        key.natural_depth);
}

uint32_t TranscriptBits(const std::string& profile_id) {
    if (profile_id == "primary40") return 40;
    if (profile_id == "sensitivity64") return 64;
    if (profile_id == "feasibility128") return 128;
    throw std::runtime_error("unknown fixture profile");
}

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

}  // namespace

int main() {
    try {
#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2
        const auto matrix = CanonicalMatrix();
        std::vector<PreThresholdCalibrationRequest> required;
        for (const auto& entry : matrix) {
            required.push_back(entry.key);
        }
        const auto discovery =
            piccard::InspectPreThresholdCalibrationCoverage(
                required, {});
        std::vector<PreThresholdCalibrationRequest> infeasible;
        for (const auto& entry : matrix) {
            const bool selected = std::any_of(
                discovery.selected_keys.begin(),
                discovery.selected_keys.end(),
                [&](const auto& key) { return key == entry.key; });
            if (!selected) {
                Require(entry.key.profile_id == "feasibility128",
                        "non-feasibility key is absent");
                infeasible.push_back(entry.key);
            }
        }
        const auto coverage =
            piccard::InspectPreThresholdCalibrationCoverage(
                required, infeasible);
        Require(coverage.active, "schema-v2 coverage is inactive");
        Require(coverage.required == 34, "wrong canonical key count");
        Require(coverage.selected >= 32 && coverage.selected <= 34,
                "wrong selected key count");
        Require(coverage.infeasible == 34 - coverage.selected,
                "wrong infeasible key count");
        Require(coverage.missing_required == 0, "missing required key");

        const auto compiled_rows =
            piccard::InspectPreThresholdCalibrationRows();
        for (const auto& row : compiled_rows) {
            Require(
                std::any_of(
                    matrix.begin(), matrix.end(),
                    [&](const auto& entry) { return entry.key == row.key; }),
                "compiled row is outside the canonical matrix");
        }
        for (const auto& entry : matrix) {
            const bool accepted_infeasible = std::any_of(
                infeasible.begin(), infeasible.end(),
                [&](const auto& key) { return key == entry.key; });
            if (accepted_infeasible) continue;
            PiccardParams params;
            params.k = entry.k;
            params.m = entry.m;
            params.security = entry.key.security;
            params.transcript_stat_bits = TranscriptBits(entry.key.profile_id);
            try {
                if (entry.key.circuit == Circuit::Sqrt) {
                    params.ValidateSqrt();
                } else {
                    params.Validate();
                }
            } catch (const std::exception& error) {
                throw std::runtime_error(
                    entry.key.profile_id + "/" + entry.key.shape_id + "/" +
                    std::to_string(entry.key.requested_ring_dim) + ": " +
                    error.what());
            }
            Require(params.UsesPreThresholdCalibration(),
                    "expanded row was not selected");
            const auto& selected = params.SelectedPreThresholdCalibration();
            Require(selected.key == entry.key, "selected full key mismatch");
            std::vector<piccard::PreThresholdCalibrationRow> matching;
            for (const auto& row : compiled_rows) {
                if (row.key == entry.key) matching.push_back(row);
            }
            Require(!matching.empty(), "compiled key has no rows");
            const auto cost = [](const auto& row) {
                return std::make_tuple(
                    row.ring_dim_calibrated, row.log_q, row.ct_bytes,
                    row.provisioned_depth, row.scaling_mod_size);
            };
            const auto cheapest = std::min_element(
                matching.begin(), matching.end(),
                [&](const auto& left, const auto& right) {
                    return cost(left) < cost(right);
                });
            Require(cost(selected) == cost(*cheapest),
                    "compiled deterministic cost winner mismatch");
            const uint32_t growth =
                selected.ring_dim_calibrated / selected.natural_ring_dim;
            const uint32_t maximum =
                entry.key.profile_id == "feasibility128" ? 4 : 2;
            Require(
                selected.ring_dim_calibrated % selected.natural_ring_dim == 0
                && (growth == 1 || growth == 2 || growth == 4)
                && growth <= maximum,
                "compiled ring growth violates profile policy");
            Require(selected.key.openfhe_version == "1.5.0",
                    "fixture OpenFHE version mismatch");
        }
        {
            PiccardParams profile;
            profile.k = 16;
            profile.m = 64;
            profile.security = SecurityLevel::STD128;
            profile.transcript_stat_bits = 40;
            piccard::CalibrationAccess::Derive(profile);
            const auto key = matrix[2].key;
            auto cheap = *std::find_if(
                compiled_rows.begin(), compiled_rows.end(),
                [&](const auto& row) { return row.key == key; });
            auto expensive = cheap;
            expensive.ring_dim_calibrated *= 2;
            expensive.plaintext_mod = 786433;
            expensive.log_delta =
                expensive.log_q - 19.5849643352016;
            expensive.coefficient_stat_bits += 1;
            expensive.flood_noise_bits += 1;
            const auto first = piccard::SelectPreThresholdCalibration(
                profile, key, {expensive, cheap});
            const auto second = piccard::SelectPreThresholdCalibration(
                profile, key, {cheap, expensive});
            Require(
                first.SelectedPreThresholdCalibration().ring_dim_calibrated
                    == cheap.ring_dim_calibrated
                && second.SelectedPreThresholdCalibration()
                       .ring_dim_calibrated == cheap.ring_dim_calibrated,
                "two-row deterministic selector probe failed");
        }
        std::cout
            << "V2 required=34 selected=" << coverage.selected
            << " infeasible=" << coverage.infeasible
            << " missing=0\n";
#else
        const auto inactive =
            piccard::InspectPreThresholdCalibrationCoverage({}, {});
        Require(!inactive.active, "legacy build reported schema-v2 active");
        const auto legacy =
            piccard::InspectLegacyCalibrationTableCoverage();
        Require(legacy.rows == 304, "legacy row scope is incomplete");
        Require(
            legacy.distinct_selection_keys == 33,
            "legacy selection-key scope is incomplete");
        Require(
            legacy.toy_rows == 254 && legacy.threshold_rows == 133,
            "legacy role scope is incomplete");
        Require(
            legacy.invalid_role_rows == 0,
            "legacy table contains a pre-threshold STD role");
        auto actual_keys = legacy.selection_keys;
        auto expected_keys = FrozenLegacyKeys();
        const auto less = [](const auto& left, const auto& right) {
            return LegacyKeyTuple(left) < LegacyKeyTuple(right);
        };
        std::sort(actual_keys.begin(), actual_keys.end(), less);
        std::sort(expected_keys.begin(), expected_keys.end(), less);
        Require(
            actual_keys.size() == expected_keys.size(),
            "legacy selection-key set size mismatch");
        for (std::size_t index = 0; index < actual_keys.size(); ++index) {
            Require(
                LegacyKeyTuple(actual_keys[index])
                    == LegacyKeyTuple(expected_keys[index]),
                "legacy selection-key set mismatch");
        }

        PiccardParams onehot;
        onehot.k = 16;
        onehot.m = 64;
        onehot.security = SecurityLevel::TOY;
        onehot.Validate();
        Require(!onehot.UsesPreThresholdCalibration(),
                "TOY unexpectedly selected expanded row");

        PiccardParams threshold;
        threshold.k = 4;
        threshold.m = 8;
        threshold.security = SecurityLevel::TOY;
        threshold.threshold_mode = true;
        threshold.threshold_tau = 2;
        threshold.Validate();
        Require(!threshold.UsesPreThresholdCalibration(),
                "Threshold unexpectedly selected expanded row");
        std::cout
            << "current V2 table coverage inactive; legacy paths pass "
            << "rows=303 keys=32\n";
#endif
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
