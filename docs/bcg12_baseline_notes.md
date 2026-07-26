# BCG12 baseline — implementation notes

Working notes for the BCG12 (EsPRESSo, arXiv:1111.5062v5) comparison
baseline, built on top of `include/baselines/group.h`. Phase 0 (this file)
covers only the group-arithmetic foundation: the abstract `Group` interface
and its two backends. Protocol-level notes (DGT12 PSI-CA, the `BCG12`
`PJSBaseline` wrapper, benchmark integration) land here in later phases.

## Group parameter provenance (Task 0.5)

### Finite-field backend: DSA-style `Z_p^*`, `|p|=3072`, `|q|=256`

The FF backend (`src/baselines/group_ff.cpp`) ships fixed domain parameters
`p`, `q`, `g` generated once on the dev machine (2026-07-26, OpenSSL 3.6.3),
using the exact commands whose output was pasted into the source file as hex
constants:

```bash
openssl genpkey -genparam -algorithm DSA \
  -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256 -out dsa3072.pem
openssl pkeyparam -in dsa3072.pem -text   # copy P, Q, G into hex constants
```

`dsa_paramgen_bits:3072` and `dsa_paramgen_q_bits:256` produce **DSA-style**
domain parameters: a 3072-bit prime `p` with a 256-bit prime subgroup order
`q` such that `q | (p-1)`, and a generator `g` of that order-`q` subgroup.
This is deliberately **not** a safe prime (`p = 2q'+1` with `q'` prime):
a safe prime's cofactor is only 2, so its "subgroup order" would be
`(p-1)/2 ≈ 3071` bits, not the 256-bit order this protocol's security
argument (and its exponent/point size accounting) assumes.

Verified 2026-07-26 that this exact `openssl genpkey -genparam -algorithm
DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256`
invocation runs cleanly on the dev machine (OpenSSL 3.6.3) and produces
valid params in ~1 second.

Before being pasted into `group_ff.cpp`, the generated `p`, `q`, `g` were
independently re-verified in Python (Miller-Rabin, 40 rounds, outside GMP)
to satisfy all of the required properties:

- `p` is prime, bit length exactly 3072.
- `q` is prime, bit length exactly 256.
- `q | (p-1)`.
- `1 < g < p`, `g != 1`.
- `g^q mod p == 1` (i.e. `g` generates a subgroup of order dividing `q`;
  combined with `q` prime and `g != 1`, `g`'s order is exactly `q`).

`FFGroup::ValidateParams()` (`src/baselines/group_ff.cpp`) re-checks the
same five properties with GMP (`mpz_probab_prime_p`, 40 rounds) at every
construction, so a corrupted or mistyped constant fails fast at startup
rather than silently degrading security.

### Elliptic-curve backend: NIST P-256

The EC backend (`src/baselines/group_ec.cpp`) uses OpenSSL's built-in
`NID_X9_62_prime256v1` (NIST P-256) curve parameters directly — no
generation step is needed since these are standard, widely-audited domain
parameters (FIPS 186-4). P-256 has cofactor 1, so every on-curve,
non-infinity point is a valid group element of the full prime order.

### Security-level justification

| Backend | Parameters | Security level | Source |
|---|---|---|---|
| FF `Z_p^*` (this branch) | `\|p\|=3072, \|q\|=256` | 128-bit | NIST SP 800-57 Pt.1 Rev.5, Table 2: 128-bit security ⇒ `L=3072, N=256` for FFC (DSA/DH-style) parameters |
| EC P-256 (this branch) | NIST P-256 | 128-bit | FIPS 186-4; standard 256-bit-order curve, ~128-bit security |
| BCG12 paper's original (EsPRESSo, §3.3) | `\|p\|=1024, \|q\|=160` | ~80-bit | Superseded parameter choice at time of publication (2011) |

Both backends target the modern 128-bit security level (NIST SP 800-57
Pt.1 Rev.5, Table 2), which is one full security-level step above the
paper's original 1024/160 (~80-bit) choice — chosen so the BCG12 comparison
in the paper is not artificially advantaged by outdated, weaker parameters.
`P-256` is the modern/fastest-reasonable secondary backend; the FF
`Z_p^*` backend at `3072/256` is the primary backend because it is
faithful to BCG12's own cost model (the paper is expressed in terms of
modular exponentiations over `Z_p^*`).

## Status

Phase 0 complete: `Group` interface, `TagHash`, item encoders
(`EncodeRawItem`/`EncodeTaggedItem`), the FF backend, and the EC backend
are implemented and unit-tested (`ctest -R Group`). Protocol logic
(DGT12 PSI-CA, `BCG12`, benchmark integration) is out of scope for this
phase and lands in later phases of the implementation plan.
