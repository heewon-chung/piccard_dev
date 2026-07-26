# Phase 2: Noise Flooding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the server actually perform the noise flooding the security proof claims — add masking noise of magnitude `2^lambda_stat` times the evaluation-noise bound to every ciphertext returned to the receiver, in all four protocol variants.

**Architecture:** One new primitive, `BFVContext::Flood()`, samples a uniform integer per polynomial coefficient and adds it to the `c0` component of a ciphertext. `Piccard::Evaluate` splits into `EvaluateRaw` (unflooded, for callers that stack more homomorphic work on top) and `Evaluate` (= `Flood(EvaluateRaw(...))`, receiver-facing). `BFVContext::Initialize` gains a budget assertion that fails loudly if the realised crypto context cannot carry the flooding term the calibration table promised.

**Tech Stack:** C++17, OpenFHE 1.5.0 (BFV/RNS), GoogleTest, CMake.

## Background for someone with no context

This repository implements *Piccard*, a protocol that computes the Jaccard similarity of two private sets. The receiver encrypts a MinHash sketch, the server multiplies two encrypted sketches and sums the slots homomorphically, and the receiver decrypts a match count.

A BFV ciphertext is a pair `(c0, c1)` over a polynomial ring `R_q = Z_q[X]/(X^N + 1)`, represented in RNS: `q = q_0 * q_1 * ... * q_{L-1}` and each polynomial is stored as `L` independent "limbs", one per `q_i`. Decryption computes `c0 + c1*s` and rounds:

```
c0 + c1*s  =  Delta * m  +  e   (mod q),      Delta = floor(q / t)
```

`m` is the plaintext, `t` the plaintext modulus, and `e` the *noise*. Rounding recovers `m` exactly while `|e| < Delta/2`.

**Why flooding is needed.** `e` grows as the server computes, and its magnitude depends on the inputs. A receiver who inspects `e` learns something about the operands beyond the intended output, so the security proof cannot simulate the receiver's view. The fix (the *smudging* lemma) is for the server to add a fresh uniform noise `f` that is `2^lambda_stat` times larger than any possible `e`; then `e + f` is within statistical distance `2^-lambda_stat` of `f` alone, which carries no information. Phase 0 measured the bound on `e` per configuration and Phase 1 stored it as `PiccardParams::eval_noise_bits`; `PiccardParams::FloodNoiseBits()` returns `eval_noise_bits + flood_margin_bits + lambda_stat`, which is `log2` of the flooding magnitude.

**Why noise is added to `c0` only.** Decryption evaluates `c0 + c1*s`, so a term added to `c0` lands in the decryption noise additively and untouched. Adding to `c1` would be multiplied by the secret key.

## Global Constraints

- **Do not change work owned by other branches.** `benchmarks/bench_threshold.cpp` belongs to `tkde-major/threshold-fpfn` and `benchmarks/baseline_engine.h` to the BCG12/SJ16 branches. Record needs against them in `3_noise-flooding.md` §8; do not edit them.
- **Do not touch `src/protocol/piccard_engine.cpp`.** It is dead code: absent from `CMakeLists.txt` and no longer compiles.
- **Do not change the Paterson–Stockmeyer depth calculation** in `src/util/params.cpp`. `natural_mult_depth` must keep matching `BFVContext::EvalPolyBFV`'s step-size calculation exactly.
- **No changes outside this plan's scope.** If a change appears unavoidable, stop and ask before making it.
- **Every claim of completion must be backed by an actual run.** Build and test output, not inspection.
- Build: `cmake -S . -B build && cmake --build build -j8`. Test: `cd build && ctest --output-on-failure`.
- Baseline before starting: build clean, `ctest` 13/13 passing.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `include/fhe/bfv_context.h` | Modify | Declare `Flood()` |
| `src/fhe/bfv_context.cpp` | Modify | Sample flooding noise; add it to `c0`; assert the modulus budget in `Initialize()` |
| `include/protocol/piccard.h` | Modify | Declare `EvaluateRaw()` alongside `Evaluate()`, documenting which one is receiver-facing |
| `src/protocol/piccard.cpp` | Modify | Rename the existing body to `EvaluateRaw`; add `Evaluate = Flood(EvaluateRaw(...))` |
| `src/protocol/threshold_piccard.cpp` | Modify | Consume `EvaluateRaw`; flood after the polynomial instead |
| `src/protocol/sqrt_piccard.cpp` | Modify | Flood the result of its own `Evaluate` |
| `tests/unit/test_bfv_context.cpp` | Modify | Unit tests for `Flood()` |
| `tests/unit/test_piccard_engine.cpp` | Modify | `EvaluateRaw` vs `Evaluate` contract |
| `benchmarks/bench_noise.cpp` | Modify | Its threshold correctness probe must use `EvaluateRaw`, or it starts measuring flooded noise |

`DynamicPiccard` needs **no change**: it derives from `Piccard` and does not override `Evaluate`, so it inherits the flooded version.

---

## Task 1: Sample and add the flooding noise

**Files:**
- Modify: `include/fhe/bfv_context.h` (after `EvalPolyBFV`, around line 53)
- Modify: `src/fhe/bfv_context.cpp` (anonymous namespace at top; new method at end)
- Test: `tests/unit/test_bfv_context.cpp`

**Interfaces:**
- Consumes: `PiccardParams::FloodNoiseBits()` (throws unless `Validate()` sized the flooding term), `PiccardParams::eval_noise_bits` — both already exist from Phase 1.
- Produces: `lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BFVContext::Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>&) const`

**How the sampler works.** For each of the `N` coefficients we want an integer uniform on `[-2^b, 2^b - 1]` where `b = FloodNoiseBits()`. Draw `b+1` uniform bits as an unsigned value `u`, then the value is `u - 2^b`. `b` reaches 283 for the threshold variant, far beyond any built-in integer type, so never materialise `u`: draw it as 32-bit words `w_0, w_1, ...` (little-endian, `u = sum_j w_j * 2^(32j)`) and reduce per limb using

```
u mod q_i  =  sum_j  w_j * (2^(32j) mod q_i)   (mod q_i)
```

which needs only `NativeInteger` modular arithmetic. Subtract `2^b mod q_i` to centre.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_bfv_context.cpp`:

```cpp
TEST_F(BFVContextTest, FloodPreservesPlaintext) {
    // Flooding must be invisible to the receiver's decryption: the whole point
    // is that it hides the evaluation noise without disturbing the message.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 7;
    values[1] = 3;
    RecordProperty("input_slots_0_1", "[7, 3]");
    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));

    auto ct = ctx->Encrypt(values);
    auto flooded = ctx->Flood(ct);
    auto result = ctx->Decrypt(flooded);

    RecordProperty("output_slots_0_1",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + "]");

    EXPECT_EQ(result[0], 7);
    EXPECT_EQ(result[1], 3);
}

TEST_F(BFVContextTest, FloodDoesNotMutateInput) {
    // Flood() must return a new ciphertext. If it aliased its argument, a
    // caller that floods an intermediate would silently corrupt the value it
    // still intends to compute on.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 5;

    auto ct = ctx->Encrypt(values);
    auto before = ctx->Decrypt(ct);
    auto flooded = ctx->Flood(ct);
    auto after = ctx->Decrypt(ct);

    RecordProperty("input_slot_0", 5);
    RecordProperty("output_original_slot_0", static_cast<int>(after[0]));
    EXPECT_EQ(before[0], after[0]);
    EXPECT_EQ(after[0], 5);
    EXPECT_NE(flooded.get(), ct.get());
}

TEST_F(BFVContextTest, FloodIsRandomised) {
    // Two floods of the same ciphertext must differ. Identical output would
    // mean the mask is deterministic, which hides nothing.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;

    auto ct = ctx->Encrypt(values);
    auto a = ctx->Flood(ct);
    auto b = ctx->Flood(ct);

    const auto& ea = a->GetElements()[0];
    const auto& eb = b->GetElements()[0];
    bool differs = false;
    for (size_t i = 0; i < ea.GetNumOfElements() && !differs; i++) {
        if (ea.GetElementAtIndex(i) != eb.GetElementAtIndex(i)) differs = true;
    }

    RecordProperty("output_two_floods_differ", differs ? "true" : "false");
    EXPECT_TRUE(differs);
}
```

- [ ] **Step 2: Run the tests and confirm they fail to compile**

```bash
cmake --build build --target test_bfv_context -j8
```

Expected: compile error, `no member named 'Flood' in 'piccard::BFVContext'`.

- [ ] **Step 3: Declare `Flood()`**

In `include/fhe/bfv_context.h`, immediately after the `EvalPolyBFV` declaration:

```cpp
    // Add the masking noise the security proof requires, and return the result.
    //
    // The receiver can otherwise inspect the decryption noise of an evaluated
    // ciphertext and learn more than the output, which is what stops the
    // receiver's view from being simulatable. Adding a uniform mask of
    // magnitude 2^FloodNoiseBits() -- calibrated to exceed any evaluation
    // noise this circuit can produce by 2^lambda_stat -- brings the real view
    // within statistical distance 2^-lambda_stat of a fresh encryption.
    //
    // Apply this ONLY to a ciphertext being handed back to the receiver. The
    // mask is enormous by construction, so any further homomorphic operation
    // on a flooded ciphertext will exhaust the modulus and destroy the result.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;
```

- [ ] **Step 4: Implement the sampler and `Flood()`**

In `src/fhe/bfv_context.cpp`, add these includes at the top:

```cpp
#include "math/distributiongenerator.h"

#include <vector>
```

Add an anonymous namespace directly after `namespace piccard {`:

```cpp
namespace {

/// A polynomial whose every coefficient is an independent uniform integer on
/// [-2^bits, 2^bits - 1], returned in EVALUATION format so it can be added to
/// a ciphertext component directly.
///
/// `bits` exceeds 128 for every configuration and reaches 283 for the
/// threshold variant, so the value is never materialised. Each coefficient is
/// drawn as 32-bit words w_0, w_1, ... representing u = sum_j w_j * 2^(32j),
/// and reduced per RNS limb using u mod q = sum_j w_j * (2^(32j) mod q).
/// Subtracting 2^bits mod q centres the result.
lbcrypto::DCRTPoly SampleFloodingNoise(
    const std::shared_ptr<lbcrypto::DCRTPoly::Params>& params, uint32_t bits) {
    auto& prng = lbcrypto::PseudoRandomNumberGenerator::GetPRNG();

    const uint32_t n = params->GetRingDimension();
    const auto& towers = params->GetParams();
    const uint32_t total_bits = bits + 1;              // u is drawn on [0, 2^(bits+1))
    const uint32_t num_words = (total_bits + 31) / 32;
    const uint32_t top_bits = total_bits - 32 * (num_words - 1);

    // Draw every coefficient's words once; the same integer has to be reduced
    // consistently against each limb, so it cannot be re-drawn per limb.
    std::vector<uint32_t> words(static_cast<size_t>(n) * num_words);
    for (size_t i = 0; i < words.size(); i++) {
        words[i] = prng();
    }
    // Trim the most significant word so u stays below 2^(bits+1).
    if (top_bits < 32) {
        const uint32_t mask = (1u << top_bits) - 1u;
        for (uint32_t c = 0; c < n; c++) {
            words[static_cast<size_t>(c) * num_words + (num_words - 1)] &= mask;
        }
    }

    lbcrypto::DCRTPoly noise(params, Format::COEFFICIENT, true);

    for (size_t i = 0; i < towers.size(); i++) {
        const lbcrypto::NativeInteger q = towers[i]->GetModulus();

        // pow[j] = 2^(32j) mod q
        std::vector<lbcrypto::NativeInteger> pow(num_words);
        pow[0] = lbcrypto::NativeInteger(1).Mod(q);
        lbcrypto::NativeInteger step = lbcrypto::NativeInteger(1).Mod(q);
        for (uint32_t s = 0; s < 32; s++) step = step.ModAdd(step, q);   // 2^32 mod q
        for (uint32_t j = 1; j < num_words; j++) pow[j] = pow[j - 1].ModMul(step, q);

        // centre = 2^bits mod q
        lbcrypto::NativeInteger centre = lbcrypto::NativeInteger(1).Mod(q);
        for (uint32_t s = 0; s < bits; s++) centre = centre.ModAdd(centre, q);

        lbcrypto::NativePoly limb(towers[i], Format::COEFFICIENT, true);
        for (uint32_t c = 0; c < n; c++) {
            lbcrypto::NativeInteger acc(0);
            const uint32_t* w = &words[static_cast<size_t>(c) * num_words];
            for (uint32_t j = 0; j < num_words; j++) {
                acc = acc.ModAdd(lbcrypto::NativeInteger(w[j]).ModMul(pow[j], q), q);
            }
            limb[c] = acc.ModSub(centre, q);
        }
        noise.SetElementAtIndex(i, limb);
    }

    noise.SetFormat(Format::EVALUATION);
    return noise;
}

} // namespace
```

Add the method at the end of the file, immediately before the closing `} // namespace piccard`:

```cpp
lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    // Throws unless Validate() sized the flooding term against the calibration
    // table, which is what keeps an unsized parameter set from producing a mask
    // smaller than the evaluation noise it is supposed to hide.
    const uint32_t bits = params_.FloodNoiseBits();

    auto out = ct->Clone();
    auto elem_params = cc_->GetCryptoParameters()->GetElementParams();

    // Decryption evaluates c0 + c1*s, so a term added to c0 lands in the
    // decryption noise additively; adding to c1 would be scaled by the key.
    out->GetElements()[0] += SampleFloodingNoise(elem_params, bits);
    return out;
}
```

- [ ] **Step 5: Run the tests and verify they pass**

```bash
cmake --build build --target test_bfv_context -j8 && ./build/test_bfv_context
```

Expected: PASS, including the three new tests. If `FloodPreservesPlaintext` fails, the flooding magnitude exceeds the modulus budget — stop and report; do not shrink the mask to make the test pass, because that silently weakens `lambda_stat`.

- [ ] **Step 6: Run the whole suite**

```bash
cd build && ctest --output-on-failure
```

Expected: 13/13 passing (no protocol path floods yet, so nothing else changes).

- [ ] **Step 7: Commit**

```bash
git add include/fhe/bfv_context.h src/fhe/bfv_context.cpp tests/unit/test_bfv_context.cpp
git commit -m "feat(fhe): add BFVContext::Flood for the R2-W6 noise flooding"
```

---

## Task 2: Assert the modulus budget when the context is built

**Files:**
- Modify: `src/fhe/bfv_context.cpp` (inside `Initialize()`, after line 60 where `params_.ring_dim` is updated)
- Test: `tests/unit/test_bfv_context.cpp`

**Interfaces:**
- Consumes: `PiccardParams::eval_noise_bits`, `flood_margin_bits`, `lambda_stat`, `ring_dim_natural` (Phase 1).
- Produces: no new API. `BFVContext::Initialize()` now throws `std::runtime_error` when the realised context cannot carry the flooding term.

**Why.** Phase 1 chose parameters from a table of *measurements*. `Initialize()` is the first moment the actual crypto context exists, so it is where the prediction can be checked against reality. Two things can diverge: OpenFHE may pick a different modulus than was measured, and it may silently enlarge the ring dimension — which would double every runtime in the paper.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_bfv_context.cpp`:

```cpp
TEST(BFVContextBudget, RejectsContextTooSmallForFlooding) {
    // Hand-set an evaluation-noise bound far beyond what this modulus can
    // carry. Initialize() must refuse rather than build a context whose
    // flooding term would destroy decryption.
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    RecordProperty("input_calibrated_eval_noise_bits",
                   static_cast<int>(params.eval_noise_bits));
    params.eval_noise_bits = 10000;
    RecordProperty("input_forced_eval_noise_bits", 10000);

    BFVContext ctx(params);
    EXPECT_THROW(ctx.Initialize(), std::runtime_error);
}

TEST(BFVContextBudget, AcceptsCalibratedParameters) {
    // The parameters Validate() selects must pass the check it predicted.
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    RecordProperty("input_lambda_stat", static_cast<int>(params.lambda_stat));
    BFVContext ctx(params);
    EXPECT_NO_THROW(ctx.Initialize());
}
```

Add `#include <stdexcept>` to the test file's includes if it is not already there.

- [ ] **Step 2: Run and verify the first test fails**

```bash
cmake --build build --target test_bfv_context -j8 && ./build/test_bfv_context --gtest_filter=BFVContextBudget.*
```

Expected: `RejectsContextTooSmallForFlooding` FAILS (no exception thrown); `AcceptsCalibratedParameters` passes.

- [ ] **Step 3: Implement the check**

In `src/fhe/bfv_context.cpp`, inside `Initialize()`, replace:

```cpp
    // Record the ring_dim OpenFHE actually selected.
    params_.ring_dim = cc_->GetRingDimension();
```

with:

```cpp
    // Record the ring_dim OpenFHE actually selected.
    params_.ring_dim = cc_->GetRingDimension();

    // The parameters came from measurements; this is the first point where the
    // context they predicted actually exists, so verify the prediction here.
    //
    // ring_dim_natural is what this circuit needs with no flooding headroom.
    // For the threshold variant it already exceeds the slot requirement,
    // because a degree-k polynomial needs a long modulus chain either way --
    // so growth is judged against it, not against the slot count. Growing past
    // it would double every runtime, which is not something to do implicitly.
    if (params_.ring_dim_natural != 0 &&
        params_.ring_dim > params_.ring_dim_natural) {
        throw std::runtime_error(
            "ring dimension grew to " + std::to_string(params_.ring_dim) +
            " past the calibrated " + std::to_string(params_.ring_dim_natural) +
            " while making room for noise flooding; every timing would double. "
            "Re-run `bench_noise --sweep` for this configuration.");
    }

    if (params_.FloodingSized()) {
        auto elem_params = cc_->GetCryptoParameters()->GetElementParams();
        const double log_q =
            std::log2(elem_params->GetModulus().ConvertToDouble());
        const double log_delta =
            log_q - std::log2(static_cast<double>(params_.plaintext_mod));
        const double required = static_cast<double>(params_.eval_noise_bits) +
                                params_.flood_margin_bits +
                                params_.lambda_stat + 2.0;
        if (required > log_delta) {
            throw std::runtime_error(
                "noise flooding does not fit: needs " +
                std::to_string(static_cast<int>(required)) +
                " bits but log2(q/t) is only " +
                std::to_string(static_cast<int>(log_delta)) +
                ". The calibration table and this crypto context disagree; "
                "re-run `bench_noise --sweep` and regenerate "
                "include/util/noise_calibration.inc.");
        }
    }
}
```

`<cmath>` and `<stdexcept>` are already included at the top of the file; add `#include <string>` if `std::to_string` does not resolve.

- [ ] **Step 4: Run and verify both tests pass**

```bash
cmake --build build --target test_bfv_context -j8 && ./build/test_bfv_context --gtest_filter=BFVContextBudget.*
```

Expected: both PASS.

- [ ] **Step 5: Run the whole suite**

```bash
cd build && ctest --output-on-failure
```

Expected: 13/13 passing. A failure here means some existing configuration cannot carry its flooding term — report it, do not weaken the check.

- [ ] **Step 6: Commit**

```bash
git add src/fhe/bfv_context.cpp tests/unit/test_bfv_context.cpp
git commit -m "feat(fhe): verify the flooding budget against the realised context"
```

---

## Task 3: Split `Evaluate` into raw and flooded

**Files:**
- Modify: `include/protocol/piccard.h` (the `Evaluate` declaration, around line 30)
- Modify: `src/protocol/piccard.cpp` (the `Evaluate` definition, around lines 55-71)
- Modify: `src/protocol/threshold_piccard.cpp:30`
- Test: `tests/unit/test_piccard_engine.cpp`

**Interfaces:**
- Consumes: `BFVContext::Flood()` from Task 1.
- Produces:
  - `Ciphertext Piccard::EvaluateRaw(const Ciphertext& ct_x, const Ciphertext& ct_y) const` — multiply + rotate-and-sum, no flooding.
  - `Ciphertext Piccard::Evaluate(const Ciphertext& ct_x, const Ciphertext& ct_y) const` — `Flood(EvaluateRaw(...))`. Same signature as before, so `Piccard::Run` and `DynamicPiccard` pick up flooding with no edit.

**Why the split.** `ThresholdPiccard::Evaluate` reuses `Piccard::Evaluate` as an *intermediate* and then applies a mask and a degree-`k` polynomial to it. Flooding inside `Evaluate` would push a mask `2^72` times the noise through a depth-15 polynomial and decryption would certainly fail. Making the default flood and requiring callers to name `EvaluateRaw` to opt out keeps the safe path the easy one.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_piccard_engine.cpp`:

```cpp
TEST_F(PiccardEngineTest, EvaluateAndEvaluateRawAgreeOnMatchCount) {
    // Flooding must not move the value the receiver reads. Both paths must
    // report the same match count for the same inputs.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 100; i++) { set_x.push_back(i); set_y.push_back(i); }

    auto ct_x = engine->Encrypt(set_x);
    auto ct_y = engine->Encrypt(set_y);

    auto raw = engine->EvaluateRaw(ct_x, ct_y);
    auto flooded = engine->Evaluate(ct_x, ct_y);

    auto raw_result = engine->Decrypt(raw);
    auto flooded_result = engine->Decrypt(flooded);

    RecordProperty("output_raw_match_count",
                   static_cast<int>(raw_result.match_count));
    RecordProperty("output_flooded_match_count",
                   static_cast<int>(flooded_result.match_count));

    EXPECT_EQ(raw_result.match_count, flooded_result.match_count);
    EXPECT_EQ(flooded_result.match_count, static_cast<int64_t>(params.k));
}

TEST_F(PiccardEngineTest, EvaluateFloodsAndEvaluateRawDoesNot) {
    // The two must differ as ciphertexts: if Evaluate returned the raw result
    // the protocol would ship unflooded output while looking correct.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 50; i++) { set_x.push_back(i); set_y.push_back(i); }

    auto ct_x = engine->Encrypt(set_x);
    auto ct_y = engine->Encrypt(set_y);

    auto raw = engine->EvaluateRaw(ct_x, ct_y);
    auto flooded = engine->Evaluate(ct_x, ct_y);

    const auto& er = raw->GetElements()[0];
    const auto& ef = flooded->GetElements()[0];
    bool differs = false;
    for (size_t i = 0; i < er.GetNumOfElements() && !differs; i++) {
        if (er.GetElementAtIndex(i) != ef.GetElementAtIndex(i)) differs = true;
    }

    RecordProperty("output_raw_differs_from_flooded", differs ? "true" : "false");
    EXPECT_TRUE(differs);
}
```

- [ ] **Step 2: Run and confirm it fails to compile**

```bash
cmake --build build --target test_piccard_engine -j8
```

Expected: compile error, `no member named 'EvaluateRaw' in 'piccard::Piccard'`.

- [ ] **Step 3: Declare both methods**

In `include/protocol/piccard.h`, replace the `Evaluate` declaration:

```cpp
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Evaluate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;
```

with:

```cpp
    // The result to hand back to the receiver: match count with the masking
    // noise the security proof requires already applied.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Evaluate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    // The same computation with no flooding applied.
    //
    // For callers that stack further homomorphic work on the result -- today
    // only ThresholdPiccard, which masks it and evaluates a degree-k
    // polynomial on top. The flooding mask is large enough to exhaust the
    // modulus if anything is computed on it, so those callers must take the
    // raw value and flood their own final output instead.
    //
    // Returning this ciphertext to the receiver is a security bug: the
    // receiver can read the evaluation noise, which is exactly what the proof
    // needs hidden.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EvaluateRaw(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;
```

- [ ] **Step 4: Split the definition**

In `src/protocol/piccard.cpp`, rename the existing `Piccard::Evaluate` to `Piccard::EvaluateRaw` (change only the method name on the definition line) and add the flooded wrapper immediately after it:

```cpp
lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Piccard::Evaluate(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {
    return bfv_->Flood(EvaluateRaw(ct_x, ct_y));
}
```

- [ ] **Step 5: Point ThresholdPiccard at the raw result**

In `src/protocol/threshold_piccard.cpp`, replace line 30:

```cpp
    auto rotated_sum = piccard_.Evaluate(ct_x, ct_y);
```

with:

```cpp
    // Raw on purpose: a mask and a degree-k polynomial are applied below, and
    // the flooding mask would exhaust the modulus long before they finished.
    // This method floods its own result at the end instead.
    auto rotated_sum = piccard_.EvaluateRaw(ct_x, ct_y);
```

- [ ] **Step 6: Run and verify the tests pass**

```bash
cmake --build build --target test_piccard_engine -j8 && ./build/test_piccard_engine
```

Expected: PASS.

- [ ] **Step 7: Run the whole suite**

```bash
cd build && ctest --output-on-failure
```

Expected: 13/13 passing. `ThresholdEngine` still passes because it now consumes the raw result; it is not yet flooded — Task 4 does that.

- [ ] **Step 8: Commit**

```bash
git add include/protocol/piccard.h src/protocol/piccard.cpp \
        src/protocol/threshold_piccard.cpp tests/unit/test_piccard_engine.cpp
git commit -m "feat(protocol): split Evaluate into flooded and raw variants"
```

---

## Task 4: Flood the threshold and sqrt outputs

**Files:**
- Modify: `src/protocol/threshold_piccard.cpp` (the `return` at the end of `Evaluate`, around line 38)
- Modify: `src/protocol/sqrt_piccard.cpp:94` (the `return result;` at the end of `Evaluate`)
- Test: `tests/unit/test_threshold_engine.cpp`, `tests/unit/test_sqrt_piccard.cpp`

**Interfaces:**
- Consumes: `BFVContext::Flood()` (Task 1), `Piccard::EvaluateRaw` (Task 3).
- Produces: no new API. Both variants now return flooded ciphertexts.

**Why these two separately.** `ThresholdPiccard::Evaluate` must flood *after* the polynomial, not after the rotate-and-sum — flooding the intermediate is the failure mode Task 3 exists to prevent. `SqrtPiccard::Evaluate` is an independent implementation that does not go through `Piccard::Evaluate` at all, so it needs its own call.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_threshold_engine.cpp`:

```cpp
TEST_F(ThresholdEngineTest, FloodedDecisionIsStillCorrect) {
    // The threshold output is one bit, and it must survive flooding: the
    // masking noise is applied after the degree-k polynomial.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 100; i++) { set_x.push_back(i); set_y.push_back(i); }

    RecordProperty("input_threshold_tau", static_cast<int>(params.threshold_tau));
    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));

    bool decision = engine->Run(set_x, set_y);

    RecordProperty("output_decision", decision ? "true" : "false");
    EXPECT_TRUE(decision);
}
```

Add to `tests/unit/test_sqrt_piccard.cpp`:

```cpp
TEST_F(SqrtPiccardTest, FloodedMatchCountIsStillExact) {
    // Flooding must leave the base-sqrt(m) match count untouched.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 100; i++) { set_x.push_back(i); set_y.push_back(i); }

    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));

    auto result = engine->Run(set_x, set_y);

    RecordProperty("output_match_count",
                   static_cast<int>(result.match_count));
    EXPECT_EQ(result.match_count, static_cast<int64_t>(params.k));
}
```

Note: both test fixtures already build an engine and call `params.Validate()`/`ValidateSqrt()`; check the existing `SetUp()` in each file and reuse its member names (`engine`, `params`) rather than declaring new ones.

- [ ] **Step 2: Run and verify they pass *before* the change**

```bash
cmake --build build --target test_threshold_engine test_sqrt_piccard -j8 \
  && ./build/test_threshold_engine && ./build/test_sqrt_piccard
```

Expected: PASS. These are regression guards — they must hold both before and after flooding is added, which is the point. Record that they passed here so a failure in Step 4 is unambiguously caused by flooding.

- [ ] **Step 3: Add the flooding calls**

In `src/protocol/threshold_piccard.cpp`, replace the final return of `Evaluate`:

```cpp
    // Step 4: Evaluate threshold polynomial (precomputed in KeyGen)
    return piccard_.GetBFVContext().EvalPolyBFV(masked, threshold_poly_);
```

with:

```cpp
    // Step 4: Evaluate threshold polynomial (precomputed in KeyGen)
    auto decision = piccard_.GetBFVContext().EvalPolyBFV(masked, threshold_poly_);

    // Step 5: flood, since this is what the receiver gets. It has to happen
    // here rather than after the rotate-and-sum: the mask would not survive
    // the polynomial above.
    return piccard_.GetBFVContext().Flood(decision);
```

In `src/protocol/sqrt_piccard.cpp`, replace the final return of `Evaluate` (line 94):

```cpp
    return result;
```

with:

```cpp
    // This ciphertext goes to the receiver, so it carries the masking noise
    // the security proof requires.
    return bfv_->Flood(result);
```

- [ ] **Step 4: Run and verify the tests still pass**

```bash
cmake --build build --target test_threshold_engine test_sqrt_piccard -j8 \
  && ./build/test_threshold_engine && ./build/test_sqrt_piccard
```

Expected: PASS. A failure means the flooding term does not fit that circuit's modulus — report it with the actual decrypted value; do not reduce the mask.

- [ ] **Step 5: Run the whole suite**

```bash
cd build && ctest --output-on-failure
```

Expected: 13/13 passing.

- [ ] **Step 6: Commit**

```bash
git add src/protocol/threshold_piccard.cpp src/protocol/sqrt_piccard.cpp \
        tests/unit/test_threshold_engine.cpp tests/unit/test_sqrt_piccard.cpp
git commit -m "feat(protocol): flood the threshold and base-sqrt(m) results"
```

---

## Task 5: Keep the calibration harness measuring unflooded noise

**Files:**
- Modify: `benchmarks/bench_noise.cpp` (the `base.Evaluate` call inside `RunThreshold`, around line 485)

**Interfaces:**
- Consumes: `Piccard::EvaluateRaw` (Task 3).
- Produces: no API change.

**Why.** `RunThreshold` recovers the pre-polynomial match count through `base.Evaluate(ct_x, ct_y)` as a correctness cross-check. After Task 3 that call floods, so the check would compare against a value whose noise has been deliberately blown up — and, worse, the harness would be measuring flooded noise while producing the very table that sizes the flooding. It must use the raw path.

The `RunOneHot` and `RunSqrt` measurements are a separate question: they call `engine.Evaluate(...)`, which now floods, so `eval_noise_bits` would be measured *after* flooding and the calibration would chase its own tail. Both must move to the raw path too. `SqrtPiccard` has no raw variant, so for that circuit measure the components directly — see Step 2.

- [ ] **Step 1: Point the one-hot and threshold measurements at the raw path**

In `benchmarks/bench_noise.cpp`, inside `RunOneHot`, replace:

```cpp
            auto ct_res = engine.Evaluate(ct_x, ct_y);
```

with:

```cpp
            // Raw: this harness measures the evaluation noise that sizes the
            // flooding term, so it must not include the flooding term itself.
            auto ct_res = engine.EvaluateRaw(ct_x, ct_y);
```

Inside `RunThreshold`, replace both:

```cpp
            auto ct_match = base.Evaluate(ct_x, ct_y);
```

with:

```cpp
            auto ct_match = base.EvaluateRaw(ct_x, ct_y);
```

and leave `engine.Evaluate(ct_x, ct_y)` (the `ThresholdPiccard` one) as it is for now — Step 2 handles it.

- [ ] **Step 2: Decide how sqrt and threshold outputs get measured**

`SqrtPiccard::Evaluate` and `ThresholdPiccard::Evaluate` now flood, and neither exposes a raw variant. Adding one to each is **outside this plan's scope**.

Stop here and report the situation, with these two options:
  - (a) add `EvaluateRaw` to `SqrtPiccard` and `ThresholdPiccard` mirroring Task 3 — a scope extension that needs approval;
  - (b) have the harness set `params.lambda_stat` and `flood_margin_bits` such that the flooding term is negligible while measuring, which is a measurement artefact and changes what is being measured.

Do not pick one unilaterally. Record whichever is chosen in `3_noise-flooding.md` §8.

- [ ] **Step 3: Verify the one-hot calibration is unchanged by flooding**

```bash
./build/bench_noise --circuit=onehot --security=TOY --k=16 --m=64 \
  --sms=40 --depth_delta=2 --reps=1 --patterns=match
```

Expected: a `B_eval` within ~1 bit of the value in `scripts/results/calibration/onehot.csv` for the same cell. A jump of tens of bits means the measurement is picking up the flooding term.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/bench_noise.cpp
git commit -m "fix(bench): measure evaluation noise on the unflooded path"
```

---

## Task 6: Record the cost and update the branch plan

**Files:**
- Modify: `3_noise-flooding.md` (§6 Phase 2 checklist, §8 integration notes)

**Interfaces:** none.

- [ ] **Step 1: Measure the flooding overhead**

```bash
./build/bench_piccard --mode=timing --security=STD128 --k=128 --m=64 --trials=10
```

Record `phase_multiply_ms`, `phase_rotate_sum_ms`, and total. Compare against the pre-flooding numbers in `3_noise-flooding.md` §3.4 (`d1/sms60`: encrypt 5.97, compute 13.09, decrypt 0.33, total 19.4 ms).

Note that `bench_piccard` inlines the protocol rather than calling `Piccard::Evaluate`, so it does **not** yet flood — the comparison measures the cost of the larger modulus only. Wiring flooding into the seven inlined benchmark sites is Phase 4, not this task.

- [ ] **Step 2: Update the plan document**

In `3_noise-flooding.md`, tick the Phase 2 items in §6 and append to §8:
  - the measured overhead from Step 1;
  - the Task 5 Step 2 decision and its rationale;
  - a note that `SqrtPiccard`/`ThresholdPiccard` have no raw variant, if option (a) was not taken.

- [ ] **Step 3: Commit**

```bash
git add 3_noise-flooding.md
git commit -m "docs: record Phase 2 results in the branch plan"
```

---

## Self-review notes

- **Spec coverage.** Plan §6 Phase 2 lists: `Initialize()` verification (Task 2), `Flood()` (Task 1), and a table of six edit sites. Of those: `piccard.cpp` and `piccard.h` (Task 3), `threshold_piccard.cpp:30` and `:38` (Tasks 3 and 4), `sqrt_piccard.cpp:94` (Task 4), `bench_noise.cpp` (Task 5). `dynamic_piccard` requires no change (inherits) and `piccard_engine.cpp` is explicitly untouched — both stated in the File Structure table.
- **Known gap, deliberately surfaced rather than papered over.** Task 5 Step 2 stops for a decision instead of silently extending scope; the plan's own Global Constraints forbid the unilateral fix.
- **Type consistency.** `Flood`, `EvaluateRaw`, `FloodNoiseBits`, `FloodingSized`, `ring_dim_natural`, `eval_noise_bits` are used with the same names and signatures throughout; `FloodNoiseBits()` and `FloodingSized()` exist as written in `include/util/params.h` from Phase 1.
