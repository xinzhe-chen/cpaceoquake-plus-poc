# CPaceOQUAKE+ PoC

Reproduces the verifier-only interleaving discussed on
[CFRG](https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/)
for [draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html),
and compares it with adding the registered KEM secret `k` to client confirmation.

## Run

Python 3.12+:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v test_crypto
python poc.py
```

The PoC runs each of four scenarios once. Expected: **4/4 PASS; 0 FAIL**.

- Baseline honest: both endpoints accept the same key with a matching session.
- Baseline interleaving: client accepts with no matching honest server session.
- Hardened honest: both endpoints accept the same key with a matching session.
- Hardened interleaving: client aborts on `client_confirm mismatch`.

`python poc.py --quiet` prints results only. No repeated campaign is needed.

## Algorithms and messages

`crypto.py` implements CPace P-256/SHA-256, OQUAKE with KemeleonNR and
ML-KEM-1024, registered X-Wing (ML-KEM-768 + X25519), Scrypt
(`N=32768, r=8, p=1`), and HKDF-SHA-256. `poc.py` exchanges byte strings;
there are no ideal PAKE/KEM registries. Five message lengths are
**98, 98, 1690, 2816, 64 bytes**, including CPace's random `s1/s2`, LEB128
point prefixes, and the derived extended SID.

Published vectors in `test_vectors.json` include source URLs and SHA-256
snapshot hashes: [CPace -21](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.txt)
Appendix B.5, [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html#appendix-J.1.2)
(five P-256 NU vectors), [X-Wing -10](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html#appendix-C)
(three key-generation/decapsulation vectors), [NIST ACVP](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
(768/1024 key generation), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
(three SHA-256 cases), and [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
(three Scrypt cases). Ten test methods also check Kemeleon arithmetic,
KEM round trips, context mismatches, implicit rejection, and malformed input.
These are component-vector and integration checks, not an externally supplied
end-to-end CPaceOQUAKE+ vector.

## Resolutions of draft inconsistencies

- Use Section 10's P-256/Scrypt alternative, its hex-decoded 32-byte DST,
  `Nsec=32`, `Nkc=64`, and `Nkey=32`.
- Section 8.2.2's `T`/rho slices conflict with `Init`: parse
  `s[96] || T[Nt] || rho[32]`. In 8.2.3, read undefined `rho/c` as stored
  rho/received `ct`; both sides hash `s || T || rho || ct`. Inner confirmation
  failure returns a random key as its pseudocode specifies.
- Section 10 advertises BUA `Npk=1594`; the
  [KemeleonNR -00](https://www.ietf.org/archive/id/draft-veitch-kemeleon-00.html#section-4.4)
  size formula with 256 excess bits gives `Nt=1530`, `Npk=1562`. Preserve the
  advertised `Npk`, using `Nt=1562` and randomized base-3329 encoding over
  that full byte space (more than 256 excess bits). This is an explicit
  encoding-size adaptation. BUA key creation samples fresh NR randomness;
  this PoC does not rederive a BUA public encoding from its ML-KEM seed.
- Interpret Section 8's `bytes_to_int(len, 4)` as a four-byte big-endian
  length. CPace uses the -21 initiator/responder transcript with empty AD.
  Section 9.4's composition reuses 8.3's `CPaceOQUAKE`/`SID` labels;
  both OQUAKE and outer confirmation use `extended_sid || public_context`.

## Scope

The attacker receives only `v`, learns a registered ciphertext through an
honest server session, and translates it into a fresh client session.
It receives neither `pk_reg` nor password/seed/private key/registered `k`.
If `pk_reg` also leaks, the attacker can encapsulate itself; this patch does
not address that stronger model. Python objects share a process; this is
an explicit actor interface, not memory isolation. Python field/integer
arithmetic is not constant-time. This research reproducer establishes the
specified trace, not production readiness, full conformance, or a security proof.
