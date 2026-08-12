#include "threshold_fpfn_schema.h"

namespace piccard {
namespace benchmark {

std::string ThresholdFpfnCSVHeader() {
    return
        "schema_version,profile,security,estimator_model,hash_randomness,"
        "root_seed,k,m,set_size,tau_count,j_tau,grid_index,target_j,"
        "signed_delta,absolute_delta,alpha,realized_intersection,"
        "realized_union,realized_j,trial_index,row_seed,match_count,decision,"
        "exact_j_truth,outcome,predicted_decision_probability,"
        "predicted_error_probability,gaussian_error_approx\n";
}

}  // namespace benchmark
}  // namespace piccard
