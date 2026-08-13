#include "noise_calibration_schema.h"

#include "util/noise_profile_matrix.h"
#include "util/params_calibration.h"
#include "util/security_profile.h"

#include "version.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>

#ifndef PICCARD_SOURCE_COMMIT
#define PICCARD_SOURCE_COMMIT "unknown"
#endif
#ifndef PICCARD_OPENFHE_VERSION
#define PICCARD_OPENFHE_VERSION "unknown"
#endif

namespace piccard {
namespace benchmark {
namespace noise_calibration {
namespace {

constexpr uint64_t kMaxQueries = UINT64_C(1) << 63;

bool StartsWith(const std::string& value, const std::string& prefix) {
    return value.compare(0, prefix.size(), prefix) == 0;
}

std::string OptionValue(
    const std::vector<std::string>& args,
    size_t* index,
    const std::string& option) {
    const std::string& arg = args[*index];
    const std::string equals_prefix = option + "=";
    if (StartsWith(arg, equals_prefix)) {
        const std::string value = arg.substr(equals_prefix.size());
        if (value.empty()) {
            throw std::invalid_argument(option + " requires a value");
        }
        return value;
    }
    if (arg == option) {
        if (*index + 1 >= args.size() || StartsWith(args[*index + 1], "--")) {
            throw std::invalid_argument(option + " requires a value");
        }
        ++*index;
        return args[*index];
    }
    return {};
}

uint64_t ParseUnsigned(const std::string& text, const std::string& option) {
    if (text.empty() ||
        !std::all_of(text.begin(), text.end(), [](char ch) {
            return ch >= '0' && ch <= '9';
        })) {
        throw std::invalid_argument(option + " requires an unsigned integer");
    }
    size_t consumed = 0;
    try {
        const uint64_t value = std::stoull(text, &consumed, 10);
        if (consumed != text.size()) {
            throw std::invalid_argument(
                option + " requires an unsigned integer");
        }
        return value;
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(option + " is out of range");
    }
}

uint32_t ParseUint32(const std::string& text, const std::string& option) {
    const uint64_t value = ParseUnsigned(text, option);
    if (value > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(option + " is out of range");
    }
    return static_cast<uint32_t>(value);
}

std::vector<uint32_t> ParseUint32List(
    const std::string& text,
    const std::string& option,
    bool require_power_of_two) {
    std::vector<uint32_t> values;
    size_t begin = 0;
    while (begin <= text.size()) {
        const size_t comma = text.find(',', begin);
        const std::string token = text.substr(
            begin,
            comma == std::string::npos ? std::string::npos : comma - begin);
        const uint32_t value = ParseUint32(token, option);
        if (value == 0) {
            throw std::invalid_argument(option + " values must be positive");
        }
        if (require_power_of_two && (value & (value - 1)) != 0) {
            throw std::invalid_argument(
                option + " values must be powers of two");
        }
        if (std::find(values.begin(), values.end(), value) != values.end()) {
            throw std::invalid_argument(option + " contains a duplicate value");
        }
        values.push_back(value);
        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }
    return values;
}

void Require(
    bool condition,
    const std::string& message) {
    if (!condition) {
        throw std::invalid_argument(message);
    }
}

std::string CsvEscape(const std::string& field) {
    if (field.find_first_of(",\"\r\n") == std::string::npos) {
        return field;
    }
    std::string escaped = "\"";
    for (char ch : field) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }
    escaped += '"';
    return escaped;
}

template <typename T>
std::string Number(const T& value) {
    std::ostringstream stream;
    if constexpr (std::is_floating_point<T>::value) {
        stream << std::setprecision(std::numeric_limits<T>::max_digits10);
    }
    stream << value;
    return stream.str();
}

template <typename T>
std::string OptionalNumber(const std::optional<T>& value) {
    return value ? Number(*value) : "";
}

std::string JoinCsv(const std::vector<std::string>& fields) {
    std::ostringstream stream;
    for (size_t index = 0; index < fields.size(); ++index) {
        if (index != 0) {
            stream << ',';
        }
        stream << CsvEscape(fields[index]);
    }
    return stream.str();
}

std::string EffectiveOpenFHEVersion(const DetailRow& row) {
    return row.openfhe_version.empty()
        ? CurrentOpenFHEVersion()
        : row.openfhe_version;
}

std::string EffectiveSourceCommit(const DetailRow& row) {
    return row.source_commit.empty()
        ? EmbeddedSourceCommit()
        : row.source_commit;
}

bool SameCandidateContext(
    const DetailRow& left,
    const DetailRow& right) {
    return std::tie(
               left.profile,
               left.key_id,
               left.candidate_id,
               left.circuit,
               left.shape_id,
               left.security,
               left.requested_ring_dim,
               left.natural_ring_dim,
               left.ring_dim_calibrated,
               left.realized_ring_dim,
               left.ring_growth_factor,
               left.natural_depth,
               left.provisioned_depth,
               left.scaling_mod_size,
               left.num_limbs,
               left.plaintext_mod,
               left.log_q,
               left.log_delta,
               left.max_queries,
               left.query_stat_bits,
               left.coefficient_stat_bits,
               left.flood_margin_bits) ==
               std::tie(
                   right.profile,
                   right.key_id,
                   right.candidate_id,
                   right.circuit,
                   right.shape_id,
                   right.security,
                   right.requested_ring_dim,
                   right.natural_ring_dim,
                   right.ring_dim_calibrated,
                   right.realized_ring_dim,
                   right.ring_growth_factor,
                   right.natural_depth,
                   right.provisioned_depth,
                   right.scaling_mod_size,
                   right.num_limbs,
                   right.plaintext_mod,
                   right.log_q,
                   right.log_delta,
                   right.max_queries,
                   right.query_stat_bits,
                   right.coefficient_stat_bits,
                   right.flood_margin_bits) &&
           EffectiveOpenFHEVersion(left) ==
               EffectiveOpenFHEVersion(right) &&
           EffectiveSourceCommit(left) ==
               EffectiveSourceCommit(right);
}

int StatusRank(StatusCode status) {
    switch (status) {
        case StatusCode::Ok:
            return 0;
        case StatusCode::Saturated:
            return 1;
        case StatusCode::DecryptFail:
            return 2;
        case StatusCode::ContextError:
            return 3;
        case StatusCode::Timeout:
            return 4;
        case StatusCode::ProcessError:
            return 5;
    }
    return 5;
}

StatusCode WorseStatus(StatusCode left, StatusCode right) {
    return StatusRank(left) >= StatusRank(right) ? left : right;
}

StatusCode EffectiveStatus(const DetailRow& row) {
    StatusCode status = row.status_code;
    if (row.saturated) {
        status = WorseStatus(status, StatusCode::Saturated);
    }
    if (!row.decrypt_ok) {
        status = WorseStatus(status, StatusCode::DecryptFail);
    }
    return status;
}

struct ConsumerReduction {
    uint32_t k = 0;
    uint32_t m = 0;
    std::optional<double> eval_noise_bits;
    std::optional<double> headroom_bits;
    bool decrypt_ok = true;
    bool saturated = false;
    std::optional<uint64_t> ct_bytes;
    StatusCode status = StatusCode::Ok;
};

void Accumulate(ConsumerReduction* reduction, const DetailRow& row) {
    if (row.eval_noise_bits &&
        (!reduction->eval_noise_bits ||
         *row.eval_noise_bits > *reduction->eval_noise_bits)) {
        reduction->eval_noise_bits = row.eval_noise_bits;
    }
    if (row.headroom_bits &&
        (!reduction->headroom_bits ||
         *row.headroom_bits < *reduction->headroom_bits)) {
        reduction->headroom_bits = row.headroom_bits;
    }
    reduction->decrypt_ok = reduction->decrypt_ok && row.decrypt_ok;
    reduction->saturated = reduction->saturated || row.saturated;
    if (row.ct_bytes &&
        (!reduction->ct_bytes || *row.ct_bytes > *reduction->ct_bytes)) {
        reduction->ct_bytes = row.ct_bytes;
    }
    reduction->status =
        WorseStatus(reduction->status, EffectiveStatus(row));
}

std::string ConsumerResultsSha256(
    const std::map<std::pair<uint32_t, uint32_t>, ConsumerReduction>&
        reductions) {
    std::ostringstream canonical;
    for (const auto& [consumer, reduction] : reductions) {
        canonical << consumer.first << ',' << consumer.second << ','
                  << OptionalNumber(reduction.eval_noise_bits) << ','
                  << OptionalNumber(reduction.headroom_bits) << ','
                  << (reduction.decrypt_ok ? 1 : 0) << ','
                  << (reduction.saturated ? 1 : 0) << ','
                  << OptionalNumber(reduction.ct_bytes) << ','
                  << StatusName(reduction.status) << '\n';
    }
    return Sha256Hex(canonical.str());
}

}  // namespace

EvidenceOptions ParseEvidenceOptions(const std::vector<std::string>& args) {
    EvidenceOptions options;
    options.command = args;
    options.pre_threshold =
        std::find(args.begin(), args.end(), "--pre_threshold") != args.end();
    if (!options.pre_threshold) {
        return options;
    }

    bool saw_profile_manifest = false;
    bool saw_profile = false;
    bool saw_key_id = false;
    bool saw_circuit = false;
    bool saw_shape_id = false;
    bool saw_security = false;
    bool saw_requested_ring_dim = false;
    bool saw_natural_depth = false;
    bool saw_consumer_points = false;
    bool saw_consumer_set_sha256 = false;
    bool saw_openfhe_version = false;
    bool saw_source_commit = false;
    bool saw_aggregate_csv = false;
    bool saw_detail_dir = false;
    bool saw_candidate_manifest = false;
    bool saw_scaling_grid = false;
    bool saw_depth_delta = false;
    bool saw_ring_candidates = false;
    bool saw_timeout = false;
    bool saw_transcript = false;
    bool saw_max_queries = false;
    bool saw_margin = false;
    bool saw_reps = false;
    bool saw_seed = false;
    bool saw_revision_pattern_taxonomy = false;

    for (size_t index = 0; index < args.size(); ++index) {
        const std::string& arg = args[index];
        if (arg == "--pre_threshold") {
            continue;
        }
        if (arg == "--coverage") {
            options.coverage = true;
            continue;
        }
        if (arg == "--smoke") {
            options.smoke = true;
            continue;
        }
        if (arg == "--revision_pattern_taxonomy") {
            Require(
                !saw_revision_pattern_taxonomy,
                "duplicate --revision_pattern_taxonomy");
            saw_revision_pattern_taxonomy = true;
            options.revision_pattern_taxonomy = true;
            continue;
        }
        if (arg == "--preflight_context") {
            options.preflight_context = true;
            continue;
        }

        std::string value;
        if (!(value = OptionValue(
                  args, &index, "--profile_manifest")).empty()) {
            Require(!saw_profile_manifest, "duplicate --profile_manifest");
            saw_profile_manifest = true;
            options.profile_manifest = value;
        } else if (!(value = OptionValue(
                         args, &index, "--profile")).empty()) {
            Require(!saw_profile, "duplicate --profile");
            saw_profile = true;
            options.profile = value;
        } else if (!(value = OptionValue(
                         args, &index, "--key_id")).empty()) {
            Require(!saw_key_id, "duplicate --key_id");
            saw_key_id = true;
            options.key_id = value;
        } else if (!(value = OptionValue(
                         args, &index, "--circuit")).empty()) {
            Require(!saw_circuit, "duplicate --circuit");
            saw_circuit = true;
            options.circuit = value;
        } else if (!(value = OptionValue(
                         args, &index, "--shape_id")).empty()) {
            Require(!saw_shape_id, "duplicate --shape_id");
            saw_shape_id = true;
            options.shape_id = value;
        } else if (!(value = OptionValue(
                         args, &index, "--security")).empty()) {
            Require(!saw_security, "duplicate --security");
            saw_security = true;
            options.security = value;
        } else if (!(value = OptionValue(
                         args, &index, "--requested_ring_dim")).empty()) {
            Require(
                !saw_requested_ring_dim,
                "duplicate --requested_ring_dim");
            saw_requested_ring_dim = true;
            options.requested_ring_dim =
                ParseUint32(value, "--requested_ring_dim");
        } else if (!(value = OptionValue(
                         args, &index, "--natural_depth")).empty()) {
            Require(!saw_natural_depth, "duplicate --natural_depth");
            saw_natural_depth = true;
            options.natural_depth =
                ParseUint32(value, "--natural_depth");
        } else if (!(value = OptionValue(
                         args, &index, "--consumer_points")).empty()) {
            Require(!saw_consumer_points, "duplicate --consumer_points");
            saw_consumer_points = true;
            options.consumer_points = ParseConsumerPoints(value);
        } else if (!(value = OptionValue(
                         args, &index, "--consumer_set_sha256")).empty()) {
            Require(
                !saw_consumer_set_sha256,
                "duplicate --consumer_set_sha256");
            saw_consumer_set_sha256 = true;
            options.consumer_set_sha256 = value;
        } else if (!(value = OptionValue(
                         args, &index, "--openfhe_version")).empty()) {
            Require(!saw_openfhe_version, "duplicate --openfhe_version");
            saw_openfhe_version = true;
            options.openfhe_version = value;
        } else if (!(value = OptionValue(
                         args, &index, "--source_commit")).empty()) {
            Require(!saw_source_commit, "duplicate --source_commit");
            saw_source_commit = true;
            options.source_commit = value;
        } else if (!(value = OptionValue(
                         args, &index, "--aggregate_csv")).empty()) {
            Require(!saw_aggregate_csv, "duplicate --aggregate_csv");
            saw_aggregate_csv = true;
            options.aggregate_csv = value;
        } else if (!(value = OptionValue(
                         args, &index, "--detail_dir")).empty()) {
            Require(!saw_detail_dir, "duplicate --detail_dir");
            saw_detail_dir = true;
            options.detail_dir = value;
        } else if (!(value = OptionValue(
                         args, &index, "--candidate_manifest")).empty()) {
            Require(
                !saw_candidate_manifest,
                "duplicate --candidate_manifest");
            saw_candidate_manifest = true;
            options.candidate_manifest = value;
        } else if (!(value = OptionValue(
                         args, &index, "--scaling_mod_grid")).empty()) {
            Require(!saw_scaling_grid, "duplicate --scaling_mod_grid");
            saw_scaling_grid = true;
            options.scaling_mod_grid =
                ParseUint32List(value, "--scaling_mod_grid", false);
        } else if (!(value = OptionValue(
                         args, &index, "--max_depth_delta")).empty()) {
            Require(!saw_depth_delta, "duplicate --max_depth_delta");
            saw_depth_delta = true;
            options.max_depth_delta =
                ParseUint32(value, "--max_depth_delta");
        } else if (!(value = OptionValue(
                         args, &index, "--ring_candidates")).empty()) {
            Require(!saw_ring_candidates, "duplicate --ring_candidates");
            saw_ring_candidates = true;
            options.ring_candidates =
                ParseUint32List(value, "--ring_candidates", true);
        } else if (!(value = OptionValue(
                         args, &index, "--timeout_seconds")).empty()) {
            Require(!saw_timeout, "duplicate --timeout_seconds");
            saw_timeout = true;
            options.timeout_seconds =
                ParseUint32(value, "--timeout_seconds");
        } else if (!(value = OptionValue(
                         args, &index, "--transcript_stat_bits")).empty()) {
            Require(!saw_transcript, "duplicate --transcript_stat_bits");
            saw_transcript = true;
            options.transcript_stat_bits =
                ParseUint32(value, "--transcript_stat_bits");
        } else if (!(value = OptionValue(
                         args, &index, "--max_queries")).empty()) {
            Require(!saw_max_queries, "duplicate --max_queries");
            saw_max_queries = true;
            options.max_queries = ParseUnsigned(value, "--max_queries");
        } else if (!(value = OptionValue(
                         args, &index, "--margin")).empty()) {
            Require(!saw_margin, "duplicate --margin");
            saw_margin = true;
            options.margin = ParseUint32(value, "--margin");
        } else if (!(value = OptionValue(
                         args, &index, "--reps")).empty()) {
            Require(!saw_reps, "duplicate --reps");
            saw_reps = true;
            options.reps = ParseUint32(value, "--reps");
        } else if (!(value = OptionValue(
                         args, &index, "--seed")).empty()) {
            Require(!saw_seed, "duplicate --seed");
            saw_seed = true;
            options.seed = ParseUnsigned(value, "--seed");
        } else {
            throw std::invalid_argument(
                "unsupported pre-threshold argument: " + arg);
        }
    }

    if (options.coverage) {
        Require(
            !saw_circuit ||
                options.circuit == "onehot" ||
                options.circuit == "sqrt",
            "--pre_threshold accepts only --circuit=onehot|sqrt");
        Require(
            !saw_security ||
                options.security == "STD128" ||
                options.security == "STD192",
            "--pre_threshold accepts only --security=STD128|STD192");
        return options;
    }

    Require(saw_profile_manifest, "--profile_manifest is required");
    Require(saw_profile, "--profile is required");
    Require(saw_key_id, "--key_id is required");
    Require(saw_circuit, "--circuit is required");
    Require(saw_security, "--security is required");
    Require(saw_scaling_grid, "--scaling_mod_grid is required");
    Require(saw_depth_delta, "--max_depth_delta is required");
    Require(saw_ring_candidates, "--ring_candidates is required");
    Require(saw_timeout, "--timeout_seconds is required");
    Require(saw_transcript, "--transcript_stat_bits is required");
    Require(saw_max_queries, "--max_queries is required");
    Require(saw_margin, "--margin is required");
    Require(saw_reps, "--reps is required");
    Require(saw_seed, "--seed is required");

    const bool strict_phase3 =
        options.preflight_context || saw_consumer_points ||
        saw_aggregate_csv || saw_detail_dir || saw_candidate_manifest;
    if (strict_phase3) {
        Require(saw_shape_id, "--shape_id is required");
        Require(
            saw_requested_ring_dim,
            "--requested_ring_dim is required");
        Require(saw_natural_depth, "--natural_depth is required");
        Require(saw_consumer_points, "--consumer_points is required");
        Require(
            saw_consumer_set_sha256,
            "--consumer_set_sha256 is required");
        Require(
            saw_openfhe_version,
            "--openfhe_version is required");
        Require(saw_source_commit, "--source_commit is required");
        if (!options.preflight_context) {
            Require(saw_aggregate_csv, "--aggregate_csv is required");
            Require(saw_detail_dir, "--detail_dir is required");
            Require(
                saw_candidate_manifest,
                "--candidate_manifest is required");
        }
    }

    Require(
        options.circuit == "onehot" || options.circuit == "sqrt",
        "--pre_threshold accepts only --circuit=onehot|sqrt");
    Require(
        options.security == "STD128" || options.security == "STD192",
        "--pre_threshold accepts only --security=STD128|STD192");
    Require(
        options.timeout_seconds > 0,
        "--timeout_seconds must be positive");
    Require(
        options.transcript_stat_bits == 40 ||
            options.transcript_stat_bits == 64 ||
            options.transcript_stat_bits == 128,
        "--transcript_stat_bits must be exactly 40, 64, or 128");
    Require(
        options.max_queries >= 1 && options.max_queries <= kMaxQueries,
        "--max_queries must be in the inclusive range 1..2^63");
    ValidatePreThresholdProfilePolicy(
        options.profile,
        options.transcript_stat_bits,
        options.max_queries,
        options.margin);
    Require(options.reps > 0, "--reps must be positive");
    Require(
        options.smoke || options.reps >= 5,
        "--reps must be at least 5 for evidence (use --smoke to override)");

    return options;
}

std::vector<CoverageEntry> PreThresholdCoverageMatrix() {
    return {
        {"onehot", "STD128"},
        {"onehot", "STD192"},
        {"sqrt", "STD128"},
        {"sqrt", "STD192"},
    };
}

std::vector<noise_profile::ConsumerPoint> ParseConsumerPoints(
    const std::string& text) {
    if (text.empty()) {
        throw std::invalid_argument("--consumer_points requires a value");
    }
    std::vector<noise_profile::ConsumerPoint> consumers;
    size_t begin = 0;
    while (begin <= text.size()) {
        const size_t comma = text.find(',', begin);
        const std::string token = text.substr(
            begin,
            comma == std::string::npos ? std::string::npos : comma - begin);
        const size_t colon = token.find(':');
        if (colon == std::string::npos ||
            colon == 0 ||
            colon + 1 == token.size() ||
            token.find(':', colon + 1) != std::string::npos) {
            throw std::invalid_argument(
                "--consumer_points requires canonical k:m entries");
        }
        const noise_profile::ConsumerPoint consumer{
            ParseUint32(token.substr(0, colon), "--consumer_points"),
            ParseUint32(token.substr(colon + 1), "--consumer_points"),
        };
        if (consumer.k == 0 || consumer.m == 0) {
            throw std::invalid_argument(
                "--consumer_points values must be positive");
        }
        if (std::find(consumers.begin(), consumers.end(), consumer) !=
            consumers.end()) {
            throw std::invalid_argument(
                "--consumer_points contains a duplicate");
        }
        consumers.push_back(consumer);
        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }
    if (!std::is_sorted(consumers.begin(), consumers.end())) {
        throw std::invalid_argument(
            "--consumer_points must be in canonical sorted order");
    }
    return consumers;
}

noise_profile::ProfilePartition ValidateEvidenceIdentity(
    const EvidenceIdentity& identity,
    const std::string& manifest_bytes) {
    std::string expected_manifest =
        noise_profile::CanonicalManifestJson();
    const std::string sentinel = "runtime-source-commit";
    const size_t source_position = expected_manifest.find(sentinel);
    if (source_position == std::string::npos) {
        throw std::logic_error(
            "canonical profile manifest has no runtime source sentinel");
    }
    expected_manifest.replace(
        source_position, sentinel.size(), identity.source_commit);
    if (manifest_bytes != expected_manifest) {
        throw std::invalid_argument(
            "profile manifest is malformed, stale, or manually modified");
    }
    if (identity.source_commit != EmbeddedSourceCommit()) {
        throw std::invalid_argument(
            "evidence source commit does not match the compiled binary");
    }
    if (identity.openfhe_version != CurrentOpenFHEVersion()) {
        throw std::invalid_argument(
            "evidence OpenFHE version does not match the compiled binary");
    }

    const auto matrix = noise_profile::CompileMatrix(
        CurrentOpenFHEVersion(), EmbeddedSourceCommit());
    const auto found = std::find_if(
        matrix.begin(),
        matrix.end(),
        [&](const noise_profile::ProfilePartition& partition) {
            return partition.key_id == identity.key_id;
        });
    if (found == matrix.end()) {
        throw std::invalid_argument("unknown evidence key_id");
    }
    const std::string expected_circuit =
        noise_profile::CircuitName(found->circuit);
    if (identity.profile_id != found->profile_id ||
        identity.circuit != expected_circuit ||
        identity.shape_id != found->shape_id ||
        identity.security != found->security ||
        identity.requested_ring_dim != found->requested_ring_dim ||
        identity.natural_depth != found->natural_depth ||
        identity.consumer_points != found->consumer_points ||
        identity.consumer_set_sha256 != found->consumer_set_sha256 ||
        identity.openfhe_version != found->openfhe_version) {
        throw std::invalid_argument(
            "evidence identity does not match the full logical key");
    }
    return *found;
}

uint64_t DeriveEvidenceSeed(
    uint64_t root_seed,
    const std::string& key_id,
    const std::string& candidate_id,
    uint32_t consumer_k,
    uint32_t consumer_m,
    const std::string& pattern,
    uint32_t rep_index) {
    std::ostringstream canonical;
    canonical << root_seed << '\n'
              << key_id << '\n'
              << candidate_id << '\n'
              << consumer_k << ':' << consumer_m << '\n'
              << pattern << '\n'
              << rep_index << '\n';
    const std::string digest = Sha256Hex(canonical.str());
    return std::stoull(digest.substr(0, 16), nullptr, 16);
}

const std::string& AggregateCsvHeader() {
    static const std::string header =
        "profile,circuit,shape_id,security,consumer_count,"
        "consumer_set_sha256,worst_consumer_k,worst_consumer_m,pattern_count,"
        "repetitions_per_pattern,detail_row_count,detail_sha256,seed,"
        "requested_ring_dim,natural_ring_dim,realized_ring_dim,"
        "ring_growth_factor,ring_dim_calibrated,natural_depth,"
        "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,"
        "log_delta,eval_noise_bits,headroom_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,flood_noise_bits,decrypt_ok,"
        "saturated,ct_bytes,openfhe_version,source_commit,status_code,"
        "error_message,consumer_results_sha256";
    return header;
}

const std::string& DetailCsvHeader() {
    static const std::string header =
        "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,"
        "consumer_m,pattern,rep_index,rep_seed,requested_ring_dim,"
        "natural_ring_dim,ring_dim_calibrated,realized_ring_dim,"
        "ring_growth_factor,natural_depth,provisioned_depth,scaling_mod_size,"
        "num_limbs,plaintext_mod,log_q,log_delta,eval_noise_bits,"
        "headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
        "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,"
        "openfhe_version,source_commit,status_code,error_message";
    return header;
}

std::string SerializeAggregateCsvRow(const AggregateRow& row) {
    return JoinCsv({
        row.profile,
        row.circuit,
        row.shape_id,
        row.security,
        Number(row.consumer_count),
        row.consumer_set_sha256,
        OptionalNumber(row.worst_consumer_k),
        OptionalNumber(row.worst_consumer_m),
        Number(row.pattern_count),
        Number(row.repetitions_per_pattern),
        Number(row.detail_row_count),
        row.detail_sha256,
        Number(row.seed),
        OptionalNumber(row.requested_ring_dim),
        OptionalNumber(row.natural_ring_dim),
        OptionalNumber(row.realized_ring_dim),
        OptionalNumber(row.ring_growth_factor),
        OptionalNumber(row.ring_dim_calibrated),
        OptionalNumber(row.natural_depth),
        OptionalNumber(row.provisioned_depth),
        OptionalNumber(row.scaling_mod_size),
        OptionalNumber(row.num_limbs),
        OptionalNumber(row.plaintext_mod),
        OptionalNumber(row.log_q),
        OptionalNumber(row.log_delta),
        OptionalNumber(row.eval_noise_bits),
        OptionalNumber(row.headroom_bits),
        OptionalNumber(row.max_queries),
        OptionalNumber(row.query_stat_bits),
        OptionalNumber(row.coefficient_stat_bits),
        OptionalNumber(row.flood_margin_bits),
        OptionalNumber(row.flood_noise_bits),
        row.decrypt_ok ? "1" : "0",
        row.saturated ? "1" : "0",
        OptionalNumber(row.ct_bytes),
        row.openfhe_version.empty()
            ? CurrentOpenFHEVersion()
            : row.openfhe_version,
        row.source_commit.empty()
            ? EmbeddedSourceCommit()
            : row.source_commit,
        StatusName(row.status_code),
        row.error_message,
        row.consumer_results_sha256,
    });
}

std::string SerializeDetailCsvRow(const DetailRow& row) {
    return JoinCsv({
        row.profile,
        row.key_id,
        row.candidate_id,
        row.circuit,
        row.shape_id,
        row.security,
        Number(row.consumer_k),
        Number(row.consumer_m),
        row.pattern,
        Number(row.rep_index),
        Number(row.rep_seed),
        OptionalNumber(row.requested_ring_dim),
        OptionalNumber(row.natural_ring_dim),
        OptionalNumber(row.ring_dim_calibrated),
        OptionalNumber(row.realized_ring_dim),
        OptionalNumber(row.ring_growth_factor),
        OptionalNumber(row.natural_depth),
        OptionalNumber(row.provisioned_depth),
        OptionalNumber(row.scaling_mod_size),
        OptionalNumber(row.num_limbs),
        OptionalNumber(row.plaintext_mod),
        OptionalNumber(row.log_q),
        OptionalNumber(row.log_delta),
        OptionalNumber(row.eval_noise_bits),
        OptionalNumber(row.headroom_bits),
        OptionalNumber(row.max_queries),
        OptionalNumber(row.query_stat_bits),
        OptionalNumber(row.coefficient_stat_bits),
        OptionalNumber(row.flood_margin_bits),
        OptionalNumber(row.flood_noise_bits),
        row.decrypt_ok ? "1" : "0",
        row.saturated ? "1" : "0",
        OptionalNumber(row.ct_bytes),
        row.openfhe_version.empty()
            ? CurrentOpenFHEVersion()
            : row.openfhe_version,
        row.source_commit.empty()
            ? EmbeddedSourceCommit()
            : row.source_commit,
        StatusName(row.status_code),
        row.error_message,
    });
}

std::vector<DetailRow> CanonicalizeDetailRows(std::vector<DetailRow> rows) {
    const bool revision_pattern_taxonomy =
        std::all_of(
            rows.begin(),
            rows.end(),
            [](const DetailRow& row) {
                return row.pattern == "zero" ||
                       row.pattern == "random" ||
                       row.pattern == "adversarial";
            }) &&
        std::any_of(
            rows.begin(),
            rows.end(),
            [](const DetailRow& row) { return row.pattern == "zero"; }) &&
        std::any_of(
            rows.begin(),
            rows.end(),
            [](const DetailRow& row) {
                return row.pattern == "adversarial";
            });
    const auto pattern_key = [revision_pattern_taxonomy](
                                  const std::string& pattern) {
        if (!revision_pattern_taxonomy) {
            return std::pair<int, std::string>{0, pattern};
        }
        const int rank = pattern == "zero"
            ? 0
            : pattern == "random"
                ? 1
                : 2;
        return std::pair<int, std::string>{rank, {}};
    };
    std::sort(
        rows.begin(),
        rows.end(),
        [&pattern_key](const DetailRow& left, const DetailRow& right) {
            return std::make_tuple(
                       left.key_id,
                       left.candidate_id,
                       left.consumer_k,
                       left.consumer_m,
                       pattern_key(left.pattern),
                       left.rep_index) <
                   std::make_tuple(
                       right.key_id,
                       right.candidate_id,
                       right.consumer_k,
                       right.consumer_m,
                       pattern_key(right.pattern),
                       right.rep_index);
        });
    return rows;
}

std::string Sha256Hex(const std::string& bytes) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("failed to allocate SHA-256 context");
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    const bool ok =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(context, digest, &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || digest_size != 32) {
        throw std::runtime_error("failed to compute SHA-256");
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digest_size; ++index) {
        hex << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return hex.str();
}

std::string DetailSha256(const std::vector<DetailRow>& rows) {
    std::ostringstream canonical;
    canonical << DetailCsvHeader() << '\n';
    for (const DetailRow& row : CanonicalizeDetailRows(rows)) {
        canonical << SerializeDetailCsvRow(row) << '\n';
    }
    return Sha256Hex(canonical.str());
}

AggregateRow ReduceCandidate(
    AggregateRow aggregate,
    const std::vector<DetailRow>& details,
    uint32_t transcript_stat_bits) {
    if (details.empty()) {
        throw std::invalid_argument(
            "candidate reduction requires at least one detail row");
    }

    const std::vector<DetailRow> canonical =
        CanonicalizeDetailRows(details);
    for (size_t index = 1; index < canonical.size(); ++index) {
        if (!SameCandidateContext(canonical.front(), canonical[index])) {
            throw std::invalid_argument(
                "candidate detail rows have mixed context or provenance");
        }
    }
    aggregate.detail_row_count = canonical.size();
    aggregate.detail_sha256 = DetailSha256(canonical);

    std::set<std::string> patterns;
    std::map<
        std::tuple<uint32_t, uint32_t, std::string>,
        uint32_t>
        repetitions;
    std::map<std::pair<uint32_t, uint32_t>, ConsumerReduction>
        consumers;
    StatusCode aggregate_status = StatusCode::Ok;
    std::string aggregate_error;

    for (const DetailRow& row : canonical) {
        patterns.insert(row.pattern);
        ++repetitions[{row.consumer_k, row.consumer_m, row.pattern}];

        auto& consumer = consumers[{row.consumer_k, row.consumer_m}];
        consumer.k = row.consumer_k;
        consumer.m = row.consumer_m;
        Accumulate(&consumer, row);

        const StatusCode effective_status = EffectiveStatus(row);
        if (StatusRank(effective_status) > StatusRank(aggregate_status)) {
            aggregate_status = effective_status;
            aggregate_error = row.error_message;
        }
    }

    if (aggregate.consumer_count == 0) {
        aggregate.consumer_count =
            static_cast<uint32_t>(consumers.size());
    }
    aggregate.pattern_count =
        static_cast<uint32_t>(patterns.size());
    aggregate.repetitions_per_pattern = 0;
    for (const auto& [cell, count] : repetitions) {
        (void)cell;
        aggregate.repetitions_per_pattern =
            std::max(aggregate.repetitions_per_pattern, count);
    }

    ConsumerReduction overall;
    for (const auto& [consumer_key, reduction] : consumers) {
        (void)consumer_key;
        if (reduction.eval_noise_bits &&
            (!overall.eval_noise_bits ||
             *reduction.eval_noise_bits > *overall.eval_noise_bits)) {
            overall.eval_noise_bits = reduction.eval_noise_bits;
            aggregate.worst_consumer_k = reduction.k;
            aggregate.worst_consumer_m = reduction.m;
        }
        if (reduction.headroom_bits &&
            (!overall.headroom_bits ||
             *reduction.headroom_bits < *overall.headroom_bits)) {
            overall.headroom_bits = reduction.headroom_bits;
        }
        overall.decrypt_ok =
            overall.decrypt_ok && reduction.decrypt_ok;
        overall.saturated =
            overall.saturated || reduction.saturated;
        if (reduction.ct_bytes &&
            (!overall.ct_bytes ||
             *reduction.ct_bytes > *overall.ct_bytes)) {
            overall.ct_bytes = reduction.ct_bytes;
        }
    }

    aggregate.eval_noise_bits = overall.eval_noise_bits;
    aggregate.headroom_bits = overall.headroom_bits;
    aggregate.decrypt_ok = overall.decrypt_ok;
    aggregate.saturated = overall.saturated;
    aggregate.ct_bytes = overall.ct_bytes;
    aggregate.status_code = aggregate_status;
    aggregate.error_message = aggregate_error;
    aggregate.consumer_results_sha256 =
        ConsumerResultsSha256(consumers);

    if (aggregate.max_queries &&
        aggregate.realized_ring_dim &&
        aggregate.eval_noise_bits &&
        aggregate.flood_margin_bits) {
        const SanitizerProfile profile = DeriveSanitizerProfile(
            transcript_stat_bits,
            *aggregate.max_queries,
            *aggregate.realized_ring_dim,
            static_cast<uint32_t>(
                std::ceil(*aggregate.eval_noise_bits)),
            *aggregate.flood_margin_bits);
        aggregate.query_stat_bits = profile.query_stat_bits;
        aggregate.coefficient_stat_bits =
            profile.coefficient_stat_bits;
        aggregate.flood_noise_bits = profile.flood_noise_bits;
    }

    return aggregate;
}

uint64_t ExpectedDetailRowCount(
    uint32_t consumer_count,
    uint32_t pattern_count,
    uint32_t repetitions_per_pattern) {
    const uint64_t consumer_patterns =
        static_cast<uint64_t>(consumer_count) * pattern_count;
    if (repetitions_per_pattern != 0 &&
        consumer_patterns >
            std::numeric_limits<uint64_t>::max() /
                repetitions_per_pattern) {
        throw std::overflow_error("detail row count overflow");
    }
    return consumer_patterns * repetitions_per_pattern;
}

bool HasCompleteEvidence(const AggregateRow& row) {
    return row.pattern_count == 3 &&
           row.repetitions_per_pattern == 5 &&
           row.detail_row_count ==
               ExpectedDetailRowCount(row.consumer_count, 3, 5);
}

const char* StatusName(StatusCode status) {
    switch (status) {
        case StatusCode::Ok:
            return "OK";
        case StatusCode::Saturated:
            return "SATURATED";
        case StatusCode::DecryptFail:
            return "DECRYPT_FAIL";
        case StatusCode::ContextError:
            return "CONTEXT_ERROR";
        case StatusCode::Timeout:
            return "TIMEOUT";
        case StatusCode::ProcessError:
            return "PROCESS_ERROR";
    }
    return "PROCESS_ERROR";
}

std::string CurrentOpenFHEVersion() {
    return PICCARD_OPENFHE_VERSION;
}

std::string EmbeddedSourceCommit() {
    return PICCARD_SOURCE_COMMIT;
}

}  // namespace noise_calibration
}  // namespace benchmark
}  // namespace piccard

namespace piccard {
namespace noise_profile {
namespace {

using BaseKey = std::tuple<
    std::string,
    Circuit,
    std::string,
    std::string,
    uint32_t,
    uint32_t,
    std::string>;

std::string SecurityName(SecurityLevel security) {
    switch (security) {
        case SecurityLevel::STD128:
            return "STD128";
        case SecurityLevel::STD192:
            return "STD192";
        case SecurityLevel::TOY:
            return "TOY";
        case SecurityLevel::STD256:
            return "STD256";
    }
    throw std::logic_error("unknown security level");
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (ch < 0x20) {
                    out << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<unsigned int>(ch)
                        << std::dec;
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    return out.str();
}

std::string ConsumerSerialization(
    const std::vector<ConsumerPoint>& consumers) {
    std::ostringstream out;
    for (const auto& consumer : consumers) {
        out << consumer.k << ':' << consumer.m << '\n';
    }
    return out.str();
}

std::string FullKeySerialization(
    const ProfilePartition& partition) {
    std::ostringstream out;
    out << partition.profile_id << '\n'
        << CircuitName(partition.circuit) << '\n'
        << partition.shape_id << '\n'
        << partition.security << '\n'
        << partition.requested_ring_dim << '\n'
        << partition.natural_depth << '\n'
        << partition.consumer_set_sha256 << '\n'
        << partition.openfhe_version << '\n';
    return out.str();
}

struct DerivedConsumer {
    uint32_t requested_ring_dim;
    uint32_t natural_depth;
    std::string shape_id;
};

DerivedConsumer Derive(
    Circuit circuit,
    SecurityLevel security,
    const ConsumerPoint& consumer) {
    PiccardParams params;
    params.k = consumer.k;
    params.m = consumer.m;
    params.security = security;
    if (circuit == Circuit::Sqrt) {
        CalibrationAccess::DeriveSqrt(params);
    } else if (circuit == Circuit::OneHot) {
        CalibrationAccess::Derive(params);
    } else {
        throw std::invalid_argument(
            "noise profile matrix accepts only OneHot and Sqrt");
    }
    return {
        params.ring_dim,
        params.natural_mult_depth,
        circuit == Circuit::OneHot
            ? "onehot-v1"
            : "sqrt-b" + std::to_string(params.sqrt_base) + "-v1",
    };
}

void AddProfile(
    std::map<BaseKey, std::vector<ConsumerPoint>>* grouped,
    const std::string& profile_id,
    Circuit circuit,
    SecurityLevel security,
    const std::vector<ConsumerPoint>& consumers,
    const std::string& openfhe_version) {
    for (const auto& consumer : consumers) {
        const auto derived = Derive(circuit, security, consumer);
        (*grouped)[{
            profile_id,
            circuit,
            derived.shape_id,
            SecurityName(security),
            derived.requested_ring_dim,
            derived.natural_depth,
            openfhe_version,
        }].push_back(consumer);
    }
}

}  // namespace

const char* CircuitName(Circuit circuit) {
    switch (circuit) {
        case Circuit::OneHot:
            return "onehot";
        case Circuit::Sqrt:
            return "sqrt";
        case Circuit::Threshold:
            return "threshold";
    }
    return "unknown";
}

std::vector<ProfilePolicy> ProfilePolicies() {
    return {
        {"feasibility128", 128, UINT64_C(1) << 20, 8, 5, 4},
        {"primary40", 40, UINT64_C(1) << 20, 8, 5, 2},
        {"sensitivity64", 64, UINT64_C(1) << 20, 8, 5, 2},
    };
}

std::vector<ConsumerPoint> PrimaryConsumerDeclarations(Circuit circuit) {
    if (circuit != Circuit::OneHot && circuit != Circuit::Sqrt) {
        throw std::invalid_argument(
            "primary declarations accept only OneHot and Sqrt");
    }
    std::set<ConsumerPoint> canonical;
    for (uint32_t k : kKSweep) {
        canonical.insert({k, 64});
    }
    if (circuit == Circuit::OneHot) {
        for (uint32_t m : kOneHotMSweep) {
            canonical.insert({128, m});
        }
    } else {
        for (uint32_t m : kSqrtMSweep) {
            canonical.insert({128, m});
        }
    }
    for (uint32_t k : kCrossoverK) {
        for (uint32_t m : kCrossoverM) {
            canonical.insert({k, m});
        }
    }
    canonical.insert(kSqrtComparison.begin(), kSqrtComparison.end());
    return {canonical.begin(), canonical.end()};
}

std::vector<ProfilePartition> CompileMatrix(
    const std::string& openfhe_version,
    const std::string& source_commit) {
    if (openfhe_version.empty() || source_commit.empty()) {
        throw std::invalid_argument(
            "matrix provenance values must be non-empty");
    }

    std::map<BaseKey, std::vector<ConsumerPoint>> grouped;
    for (SecurityLevel security :
         {SecurityLevel::STD128, SecurityLevel::STD192}) {
        AddProfile(
            &grouped,
            "primary40",
            Circuit::OneHot,
            security,
            PrimaryConsumerDeclarations(Circuit::OneHot),
            openfhe_version);
        AddProfile(
            &grouped,
            "primary40",
            Circuit::Sqrt,
            security,
            PrimaryConsumerDeclarations(Circuit::Sqrt),
            openfhe_version);
        AddProfile(
            &grouped,
            "sensitivity64",
            Circuit::OneHot,
            security,
            {{128, 64}},
            openfhe_version);
        AddProfile(
            &grouped,
            "sensitivity64",
            Circuit::Sqrt,
            security,
            {{128, 64}},
            openfhe_version);
        AddProfile(
            &grouped,
            "feasibility128",
            Circuit::OneHot,
            security,
            {{128, 64}},
            openfhe_version);
    }

    std::vector<ProfilePartition> matrix;
    matrix.reserve(grouped.size());
    for (auto& [key, consumers] : grouped) {
        std::sort(consumers.begin(), consumers.end());
        consumers.erase(
            std::unique(consumers.begin(), consumers.end()),
            consumers.end());
        ProfilePartition partition;
        partition.profile_id = std::get<0>(key);
        partition.circuit = std::get<1>(key);
        partition.shape_id = std::get<2>(key);
        partition.security = std::get<3>(key);
        partition.requested_ring_dim = std::get<4>(key);
        partition.natural_depth = std::get<5>(key);
        partition.openfhe_version = std::get<6>(key);
        partition.consumer_points = std::move(consumers);
        partition.consumer_set_sha256 =
            benchmark::noise_calibration::Sha256Hex(
                ConsumerSerialization(partition.consumer_points));
        partition.candidate_count_cap =
            partition.profile_id == "feasibility128" ? 147 : 98;
        partition.key_id =
            "key-" + benchmark::noise_calibration::Sha256Hex(
                         FullKeySerialization(partition));
        matrix.push_back(std::move(partition));
    }
    return matrix;
}

std::string CanonicalManifestJson() {
    const std::string openfhe_version =
        benchmark::noise_calibration::CurrentOpenFHEVersion();
    const std::string source_commit = "runtime-source-commit";
    const auto policies = ProfilePolicies();
    const auto matrix = CompileMatrix(openfhe_version, source_commit);

    std::ostringstream out;
    out << "{\n"
        << "  \"schema\":\"piccard-noise-profile-matrix\",\n"
        << "  \"version\":1,\n"
        << "  \"source_commit\":\"" << JsonEscape(source_commit) << "\",\n"
        << "  \"openfhe_version\":\"" << JsonEscape(openfhe_version)
        << "\",\n"
        << "  \"root_seed\":20260729,\n"
        << "  \"patterns\":[\"all_match\",\"no_match\",\"random\"],\n"
        << "  \"search\":{\"scaling_mod_grid\":[40,45,50,52,54,58,60],"
           "\"depth_delta_min\":0,\"depth_delta_max\":6,"
           "\"absolute_ring_dim_cap\":1048576,"
           "\"timeouts\":[[32768,2700],[65536,7200],[131072,21600],"
           "[262144,43200],[1048576,86400]]},\n"
        << "  \"profiles\":[\n";
    for (size_t index = 0; index < policies.size(); ++index) {
        const auto& policy = policies[index];
        out << "    {\"profile_id\":\"" << policy.profile_id
            << "\",\"transcript_stat_bits\":" << policy.transcript_stat_bits
            << ",\"max_queries\":" << policy.max_queries
            << ",\"flood_margin_bits\":" << policy.flood_margin_bits
            << ",\"repetitions\":" << policy.repetitions
            << ",\"max_ring_growth\":" << policy.max_ring_growth << "}";
        out << (index + 1 == policies.size() ? "\n" : ",\n");
    }
    out << "  ],\n"
        << "  \"partitions\":[\n";
    for (size_t index = 0; index < matrix.size(); ++index) {
        const auto& partition = matrix[index];
        out << "    {\"key_id\":\"" << partition.key_id
            << "\",\"profile_id\":\"" << partition.profile_id
            << "\",\"circuit\":\"" << CircuitName(partition.circuit)
            << "\",\"shape_id\":\"" << partition.shape_id
            << "\",\"security\":\"" << partition.security
            << "\",\"requested_ring_dim\":"
            << partition.requested_ring_dim
            << ",\"natural_depth\":" << partition.natural_depth
            << ",\"consumer_set_sha256\":\""
            << partition.consumer_set_sha256
            << "\",\"openfhe_version\":\""
            << JsonEscape(partition.openfhe_version)
            << "\",\"candidate_count_cap\":"
            << partition.candidate_count_cap
            << ",\"consumer_points\":[";
        for (size_t consumer_index = 0;
             consumer_index < partition.consumer_points.size();
             ++consumer_index) {
            const auto& consumer =
                partition.consumer_points[consumer_index];
            out << "{\"k\":" << consumer.k << ",\"m\":" << consumer.m
                << "}";
            if (consumer_index + 1 != partition.consumer_points.size()) {
                out << ',';
            }
        }
        out << "]}";
        out << (index + 1 == matrix.size() ? "\n" : ",\n");
    }
    out << "  ]\n"
        << "}\n";
    return out.str();
}

}  // namespace noise_profile
}  // namespace piccard
