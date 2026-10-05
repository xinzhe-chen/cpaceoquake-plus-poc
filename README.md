# CPaceOQUAKE+ PoC

Reproduces the verifier-only interleaving in
[draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html)
and compares it with binding the registered KEM secret `k` into client confirmation.

## Run

Python 3.12+:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python poc.py
```

Expected: **4/4 PASS; 0 FAIL**.

- Honest handshake, both modes: matching session and equal final keys.
- Baseline attack: client accepts without a matching server session.
- Hardened attack: client rejects on `client_confirm mismatch`.

Uses real P-256/Scrypt, KemeleonNR/ML-KEM-1024, X-Wing and HKDF-SHA-256.
Message parsing is corrected and KemeleonNR encoding is adapted to -02's
advertised key size. The attacker knows only `v`, not `pk_reg` or client secrets.
This research code is not constant-time or a complete security proof.

## Reproduction details

The following explicit conventions resolve inconsistencies in
[draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html) for reproduction; they are not amendments to its encoding
specification:

- Parse the OQUAKE initiation as `s[96] || T[Nt] || rho[32]`, following
  Init, rather than Section 8.2.2's conflicting slices. In Finish,
  use the stored rho and received ciphertext ct for the undefined
  rho/c names; both sides hash `s || T || rho || ct`. Follow its
  pseudocode's random-key output on inner confirmation failure.
- Preserve Section 10's BUA Npk=1594, hence Nt=1562. The KemeleonNR
  size formula with 256 excess bits instead yields Nt=1530 and
  Npk=1562. The reproducer adapts NR encoding to the advertised full
  byte space, with more than 256 excess bits, and samples fresh
  encoding randomness. It does not rederive the BUA encoding from
  the ML-KEM seed.
- Use four-byte big-endian public-context lengths, CPace -21's
  initiator/responder transcript with empty associated data, and
  Section 8.3's random s1/s2, length-prefixed points, and
  `CPaceOQUAKE`/`SID` labels. Both OQUAKE and outer confirmation use
  `extended_sid || public_context`. Decode the suite DST from hex;
  use Nsec=32, Nkc=64, and Nkey=32.

### Validation history

Separate component-vector and integration checks passed all ten test
methods at implementation commit 9c3d1a2, before test artifacts were
removed from the runnable repository. Published vectors cover CPace
P-256, P-256 hashing to
the curve ([RFC 9380](https://www.rfc-editor.org/rfc/rfc9380)), X-Wing key generation and decapsulation, NIST
ACVP ML-KEM-768/1024 key generation, HKDF, and Scrypt. Additional
checks cover Kemeleon arithmetic, KEM round trips, context mismatches,
implicit rejection, and malformed messages. The [historical commit](https://github.com/xinzhe-chen/cpaceoquake-plus-poc/tree/9c3d1a27605a5dd879e2f14d7ba1faae155e1abb)
retains the validation sources and vector provenance. These checks
do not constitute
an externally supplied end-to-end CPaceOQUAKE+ conformance vector.

All four core comparisons pass: both honest profiles agree on a key
with a matching server session; the baseline interleaving causes
client acceptance without a matching server; the hardened interleaving
aborts at `client_confirm mismatch`. Expected attack outcomes count
as PASS. Each comparison is run once; no repeated campaign is required.

The adversary interface receives only v and exchanged messages.
All actors share a Python process; this is not memory isolation.
Python field and integer arithmetic is not constant-time. These
results reproduce the specified execution and do not establish
production readiness, full specification conformance, general
concurrent agreement, forward secrecy, or post-quantum security.
