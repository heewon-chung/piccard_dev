/**
 * @file group_ec.cpp
 * @brief NIST P-256 group backend (OpenSSL-backed). 128-bit security
 *        (FIPS 186-4); the modern/fastest-reasonable secondary backend
 *        alongside the FF group (see group_ff.cpp).
 */

#include "baselines/group_ec.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <array>
#include <atomic>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace piccard {
namespace baselines {

namespace {

constexpr size_t kElementBytes = 33;  // compressed P-256 point
constexpr size_t kExponentBytes = 32;

void AppendBE32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// GroupElement wrapping an owned EC_POINT*.
struct EcElement : public GroupElement {
    EC_POINT* point;
    explicit EcElement(EC_POINT* pt) : point(pt) {}
    ~EcElement() override { EC_POINT_free(point); }
    EcElement(const EcElement&) = delete;
    EcElement& operator=(const EcElement&) = delete;
};

EC_POINT* AsPoint(const ElementPtr& e) {
    return static_cast<const EcElement*>(e.get())->point;
}

ElementPtr WrapPoint(EC_POINT* pt) { return std::make_shared<EcElement>(pt); }

class EcGroup : public Group {
public:
    EcGroup() {
        group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group_) {
            throw std::runtime_error("EcGroup: EC_GROUP_new_by_curve_name failed");
        }

        // 13-1a: one BN_CTX per thread the OpenMP runtime reports as available
        // right now, all allocated eagerly (never lazily -- lazy allocation
        // would need a lock on the common path, and that lock would eat the
        // parallel gain this task exists to unlock). BN_CTX is an OpenSSL
        // scratch stack and is NOT thread-safe, so a single shared context
        // (the pre-13-1 design) races the instant `RunDgt12` parallelizes its
        // `Group::Exp`/`ExpInverse`/... loops -- silently wrong cryptographic
        // results, not just a crash.
#ifdef _OPENMP
        const size_t n_threads = static_cast<size_t>(omp_get_max_threads());
#else
        const size_t n_threads = 1;
#endif
        ctxs_.assign(n_threads > 0 ? n_threads : 1, nullptr);
        bool ctxs_ok = true;
        for (BN_CTX*& c : ctxs_) {
            c = BN_CTX_new();
            if (!c) {
                ctxs_ok = false;
                break;
            }
        }
        if (!ctxs_ok) {
            for (BN_CTX* c : ctxs_) {
                if (c) BN_CTX_free(c);
            }
            EC_GROUP_free(group_);
            throw std::runtime_error("EcGroup: BN_CTX_new failed");
        }

        order_ = BN_new();
        p_ = BN_new();
        BIGNUM* a = BN_new();
        BIGNUM* b = BN_new();
        // Constructor-time reads happen before any parallel region exists, so
        // this is single-threaded by construction -- ctxs_[0] (always present,
        // since ctxs_ is sized >= 1 above) is the only slot in play here.
        if (!order_ || !p_ || !a || !b ||
            EC_GROUP_get_order(group_, order_, ctxs_[0]) != 1 ||
            EC_GROUP_get_curve(group_, p_, a, b, ctxs_[0]) != 1) {
            BN_free(a);
            BN_free(b);
            BN_free(order_);
            BN_free(p_);
            for (BN_CTX* c : ctxs_) BN_CTX_free(c);
            EC_GROUP_free(group_);
            throw std::runtime_error("EcGroup: failed to read curve parameters");
        }
        BN_free(a);
        BN_free(b);
    }

    ~EcGroup() override {
        BN_free(order_);
        BN_free(p_);
        for (BN_CTX* c : ctxs_) BN_CTX_free(c);
        if (overflow_ctx_) BN_CTX_free(overflow_ctx_);
        if (ctx_overflow_.load(std::memory_order_relaxed)) {
            // D1: the overflow flag was set (see Ctx() below) but no later
            // call from outside a parallel region ever observed and threw
            // for it (CheckOverflow() runs on every public entry point, but
            // this object was destroyed before the next one happened). We
            // cannot throw from a destructor, so this is the last chance to
            // make the condition visible instead of staying silent about it.
            // Results computed while the flag was set are still correct --
            // they used the mutex-serialized fallback context below, not a
            // race -- but this indicates omp_get_max_threads() grew after
            // this EcGroup was constructed, which the caller should fix.
            std::cerr << "[EcGroup] WARNING: BN_CTX pool overflow (D1) was detected "
                         "but never surfaced as an exception before destruction -- "
                         "thread count exceeded the pool size fixed at construction. "
                         "Timing/results from the affected run should be treated with "
                         "suspicion; see Branch_Prompts/13_measurement-symmetry.md D1."
                      << std::endl;
        }
        EC_GROUP_free(group_);
    }

    const char* Name() const override { return "EC-P256"; }

    std::vector<uint8_t> RandomExponent() const override {
        CheckOverflow();
        BIGNUM* bn = BN_new();
        if (!bn) throw std::runtime_error("EcGroup::RandomExponent: BN_new failed");
        while (true) {
            if (BN_priv_rand_range(bn, order_) != 1) {
                BN_free(bn);
                throw std::runtime_error("EcGroup::RandomExponent: BN_priv_rand_range failed");
            }
            if (!BN_is_zero(bn)) break;
        }
        std::vector<uint8_t> out(kExponentBytes);
        BN_bn2binpad(bn, out.data(), static_cast<int>(kExponentBytes));
        BN_free(bn);
        return out;
    }

    ElementPtr HashToGroup(const std::vector<uint8_t>& msg,
                            size_t* out_hash_exps) const override {
        CheckOverflow();
        // Try-and-increment, with x and the sign bit derived INDEPENDENTLY
        // from a single wide (SHA-512) digest per attempt:
        //   wide = SHA512(0x11 || msg || be32(ctr))            // 64 bytes
        //   x    = OS2IP(wide[0..47]) mod p                     // 384-bit
        //          reduced mod the ~256-bit p -> bias ~2^-128
        //   sign = wide[48] & 1                                 // independent
        //          byte, uncorrelated with x, so both square roots are
        //          reached with equal probability instead of being tied to
        //          x's own parity.
        // P-256's cofactor is 1, so any on-curve, non-infinity point is a
        // valid group element -- no cofactor exponentiation, hence
        // out_hash_exps is left untouched (EC contributes 0 to hash_exps).
        uint32_t ctr = 0;
        CtxLease ctx = Ctx();
        while (true) {
            std::vector<uint8_t> input;
            input.reserve(msg.size() + 5);
            input.push_back(0x11);  // domain separation tag: EC hash-to-group
            input.insert(input.end(), msg.begin(), msg.end());
            AppendBE32(input, ctr);

            std::array<uint8_t, SHA512_DIGEST_LENGTH> wide{};
            SHA512(input.data(), input.size(), wide.data());

            BIGNUM* x = BN_bin2bn(wide.data(), 48, nullptr);  // wide[0..47]: 384 bits
            if (!x) {
                throw std::runtime_error("EcGroup::HashToGroup: BN_bin2bn failed");
            }
            if (BN_mod(x, x, p_, ctx) != 1) {
                BN_free(x);
                throw std::runtime_error("EcGroup::HashToGroup: BN_mod failed");
            }
            int y_bit = wide[48] & 1;  // independent byte for the sign bit

            EC_POINT* pt = EC_POINT_new(group_);
            if (!pt) {
                BN_free(x);
                throw std::runtime_error("EcGroup::HashToGroup: EC_POINT_new failed");
            }
            int ok = EC_POINT_set_compressed_coordinates(group_, pt, x, y_bit, ctx);
            BN_free(x);

            if (ok == 1 && !EC_POINT_is_at_infinity(group_, pt) &&
                EC_POINT_is_on_curve(group_, pt, ctx) == 1) {
                (void)out_hash_exps;  // unchanged: no cofactor exponentiation for EC
                return WrapPoint(pt);
            }
            EC_POINT_free(pt);
            ++ctr;
        }
    }

    ElementPtr Exp(const ElementPtr& base, const std::vector<uint8_t>& exp) const override {
        CheckOverflow();
        BIGNUM* e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
        if (!e) {
            throw std::runtime_error("EcGroup::Exp: BN_bin2bn failed");
        }
        EC_POINT* result = EC_POINT_new(group_);
        if (!result) {
            BN_free(e);
            throw std::runtime_error("EcGroup::Exp: EC_POINT_new failed");
        }
        CtxLease ctx = Ctx();
        // group_ (EC_GROUP*) stays a single shared object across threads.
        // EC_POINT_mul(group_, r, nullptr, base, e, ctx) passes nullptr for
        // the generator-scalar argument, so this call never takes the path
        // that lazily computes/caches generator precomputation data inside
        // EC_GROUP (that path only triggers when the generator itself is
        // being scaled, i.e. a non-null 3rd argument). With no such path
        // taken, EC_GROUP's internal state is never mutated post-construction,
        // so concurrent EC_POINT_mul calls against the same group_ (each with
        // its own per-thread BN_CTX from Ctx()) are safe. Verified empirically
        // by ThreadEquivalence + TSan (13-1c).
        if (EC_POINT_mul(group_, result, nullptr, AsPoint(base), e, ctx) != 1) {
            BN_free(e);
            EC_POINT_free(result);
            throw std::runtime_error("EcGroup::Exp: EC_POINT_mul failed");
        }
        BN_free(e);
        return WrapPoint(result);
    }

    ElementPtr ExpInverse(const ElementPtr& base,
                           const std::vector<uint8_t>& exp) const override {
        CheckOverflow();
        BIGNUM* e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
        if (!e) {
            throw std::runtime_error("EcGroup::ExpInverse: BN_bin2bn failed");
        }
        BIGNUM* inv = BN_new();
        if (!inv) {
            BN_free(e);
            throw std::runtime_error("EcGroup::ExpInverse: BN_new failed");
        }
        CtxLease ctx = Ctx();
        if (!BN_mod_inverse(inv, e, order_, ctx)) {
            BN_free(e);
            BN_free(inv);
            throw std::runtime_error("EcGroup::ExpInverse: exponent not invertible mod order");
        }
        EC_POINT* result = EC_POINT_new(group_);
        if (!result) {
            BN_free(e);
            BN_free(inv);
            throw std::runtime_error("EcGroup::ExpInverse: EC_POINT_new failed");
        }
        // See the comment in Exp(): nullptr generator-scalar -> no EC_GROUP
        // precomputation path taken -> safe to share group_ across threads.
        if (EC_POINT_mul(group_, result, nullptr, AsPoint(base), inv, ctx) != 1) {
            BN_free(e);
            BN_free(inv);
            EC_POINT_free(result);
            throw std::runtime_error("EcGroup::ExpInverse: EC_POINT_mul failed");
        }
        BN_free(e);
        BN_free(inv);
        return WrapPoint(result);
    }

    std::vector<uint8_t> Serialize(const ElementPtr& e) const override {
        CheckOverflow();
        std::vector<uint8_t> out(kElementBytes);
        CtxLease ctx = Ctx();
        size_t written = EC_POINT_point2oct(group_, AsPoint(e), POINT_CONVERSION_COMPRESSED,
                                             out.data(), out.size(), ctx);
        if (written != kElementBytes) {
            throw std::runtime_error("EcGroup::Serialize: unexpected compressed point length");
        }
        return out;
    }

    size_t ElementBytes() const override { return kElementBytes; }
    size_t ExponentBytes() const override { return kExponentBytes; }

    bool InSubgroup(const ElementPtr& e) const override {
        CheckOverflow();
        EC_POINT* pt = AsPoint(e);
        if (EC_POINT_is_at_infinity(group_, pt)) return false;  // never identity
        CtxLease ctx = Ctx();
        return EC_POINT_is_on_curve(group_, pt, ctx) == 1;      // cofactor 1: on-curve suffices
    }

private:
    // RAII handle for the BN_CTX to use on this call. Fast path (thread index
    // within the pre-sized pool from the constructor): a bare, unlocked
    // pointer wrapper -- the slot is exclusively owned by this thread, so
    // there is no contention between concurrent EcGroup calls on different
    // threads. Overflow path (see Ctx()): wraps the single shared fallback
    // context and holds a mutex for the lease's entire lifetime, so the
    // fallback is correct (never racy) even though it serializes.
    class CtxLease {
    public:
        CtxLease(BN_CTX* ctx, std::mutex* guard) : ctx_(ctx), guard_(guard) {
            if (guard_) guard_->lock();
        }
        ~CtxLease() {
            if (guard_) guard_->unlock();
        }
        CtxLease(const CtxLease&) = delete;
        CtxLease& operator=(const CtxLease&) = delete;
        operator BN_CTX*() const { return ctx_; }

    private:
        BN_CTX* ctx_;
        std::mutex* guard_;
    };

    // Returns a lease on the calling thread's private BN_CTX (13-1a). Every
    // existing `ctx_` use site is replaced by a local `CtxLease ctx = Ctx();`
    // held for the call's duration.
    CtxLease Ctx() const {
#ifdef _OPENMP
        const size_t tid = static_cast<size_t>(omp_get_thread_num());
#else
        const size_t tid = 0;
#endif
        if (tid < ctxs_.size()) return CtxLease(ctxs_[tid], nullptr);

        // D1 (BN_CTX pool overflow): omp_get_max_threads() reported a smaller
        // value at construction than the thread count actually in use now
        // (e.g. something called omp_set_num_threads() to raise it after this
        // EcGroup was built -- nothing in this codebase does that today, but
        // the pool is sized once at construction, so it is possible in
        // principle). Two things must NOT happen:
        //   (1) throwing here -- Ctx() can run on a worker thread inside a
        //       `#pragma omp parallel for` region, and an exception escaping
        //       a parallel region is undefined behavior (most OpenMP runtimes
        //       call std::terminate);
        //   (2) silently indexing an in-bounds slot without synchronization
        //       -- BN_CTX is a non-thread-safe scratch stack, and handing two
        //       threads the same one races exactly like the shared-ctx_ bug
        //       this task fixes.
        // So: flag the overflow atomically (never throw here) and fall back
        // to a dedicated context serialized by a mutex held for the lease's
        // whole lifetime -- correct, just not parallel for the (expected-
        // unreachable) overflowing threads. CheckOverflow(), called at the
        // top of every public method, turns the flag into a thrown exception
        // the next time a call happens from outside a parallel region -- for
        // RunDgt12 that is always the sequential code between rounds (e.g.
        // RandomExponent() for R_b, called right after Round 1's parallel
        // Exp loop joins).
        ctx_overflow_.store(true, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> init_lock(overflow_mutex_);
            if (!overflow_ctx_) overflow_ctx_ = BN_CTX_new();
        }
        return CtxLease(overflow_ctx_, &overflow_mutex_);
    }

    // See Ctx() and the destructor. Must never throw while
    // `omp_in_parallel()` is true (UB); safe otherwise.
    void CheckOverflow() const {
#ifdef _OPENMP
        if (omp_in_parallel()) return;
#endif
        if (ctx_overflow_.exchange(false, std::memory_order_relaxed)) {
            throw std::runtime_error(
                "EcGroup: BN_CTX pool overflow (D1) -- omp_get_max_threads() grew "
                "after this EcGroup was constructed. Results computed while the "
                "overflow was active used a correct, mutex-serialized fallback "
                "context (no race), but this indicates a thread-count "
                "misconfiguration; investigate before trusting timing numbers "
                "from this run.");
        }
    }

    EC_GROUP* group_;
    mutable std::vector<BN_CTX*> ctxs_;      // one per thread, sized at construction
    mutable std::atomic<bool> ctx_overflow_{false};
    mutable std::mutex overflow_mutex_;
    mutable BN_CTX* overflow_ctx_ = nullptr;  // lazy, D1 fallback only
    BIGNUM* order_;
    BIGNUM* p_;
};

}  // namespace

std::unique_ptr<Group> MakeEcGroup() { return std::make_unique<EcGroup>(); }

}  // namespace baselines
}  // namespace piccard
