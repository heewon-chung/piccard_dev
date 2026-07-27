#pragma once
#include "baselines/pjs_baseline.h"
#include "baselines/group.h"
#include <memory>
namespace piccard { class MinHasher; }               // fwd decl

namespace piccard { namespace baselines {

enum class Bcg12Mode    { Exact, MinHash };
enum class Bcg12Backend { FF, EC };

struct Bcg12Params {
    Bcg12Mode    mode    = Bcg12Mode::MinHash;
    Bcg12Backend backend = Bcg12Backend::FF;
    uint32_t     k       = 128;
    uint64_t     minhash_seed = 42;                   // PUBLIC CRS — benchmark sets it from
                                                      // PiccardParams{}.hash_seed for parity
};

class BCG12 : public PJSBaseline {
public:
    explicit BCG12(const Bcg12Params& p);
    ~BCG12() override;
    const char*   Name() const override;              // per-variant, see below
    SecurityClass Security() const override;          // AHE_NoLeakage
    void          Setup() override;                   // build group + MinHasher (excl. from query cost)
    QueryCost     RunQuery(const std::vector<uint64_t>& set_x,
                           const std::vector<uint64_t>& set_y) override;
    const Bcg12Params& GetParams() const { return params_; }
private:
    Bcg12Params params_;
    std::unique_ptr<Group> group_;
    std::unique_ptr<piccard::MinHasher> hasher_;      // built in Setup() (MinHash mode)
};

}} // namespace
