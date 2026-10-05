# CPaceOQUAKE+ authentication PoC

A standalone before/after reproducer of the verifier-only interleaving
from the [CFRG discussion](https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/)
for [draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html).
It compares the baseline with the proposed binding of the registered-KEM
shared secret `k` into the confirmation checked by the client.

## Run

Python 3.9+; standard library only. No installation or dependencies.

```sh
python3 protocol_harness.py
```

The script prints state transitions and checks four scenarios:

| Scenario | Expected result |
|---|---|
| Baseline, honest handshake | Both accept with the same key and a matching server session |
| Baseline, two-session interleaving | Client accepts without a matching honest server session |
| Hardened, honest handshake | Both accept with the same key and a matching server session |
| Hardened, same interleaving | Client rejects with `AuthenticationError` and exposes no key |

All four should print **PASS**. The second PASS means the baseline gap
was reproduced; the fourth means the hardened client rejected the attack.
Failed checks return a nonzero exit status. To repeat the comparison:

```sh
python3 protocol_harness.py --quiet --repeat 100
```

## Confirmation change

Both endpoints apply the same change:

```diff
-h1 = Extract(SK, DST || "h1" || public_context || enc_c)
+h1 = Extract(SK, DST || "h1" || public_context || enc_c || k)
```

## Read the code

The single script has three numbered sections:

1. **Shared definitions and operations**: data types, ideal PAKE/KEM,
   confirmation formulas, ciphertext masking, context binding, and observation.
2. **Endpoint processing and protocol interactions**: `Client`, `Server`,
   the interleaver, `run_honest_handshake`, and `run_interleaving`.
3. **Comparison tests and runner**: the four expected outcomes and CLI.

To change the confirmation rule, edit `derive_client_confirmation` in
section 1. To change endpoint handling or message delivery, edit section 2;
messages are written explicitly as `msg1` through `msg5`. Section 3 checks
the resulting behavior independently of those protocol operations.

## Model scope

The attacker obtains `v`, but not `pk_reg`, the password, or client
private material. PAKE and KEM operations are ideal opaque functionalities;
HKDF, masking and confirmation checks are concrete. A matching server
must have prepared its response before client acceptance; it need not
have received the final message. The patch does not protect against
exposure of both `v` and `pk_reg`. This finite simulation demonstrates
the stated trace, not a full protocol security proof or a production
post-quantum implementation.
