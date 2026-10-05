# CPaceOQUAKE+ PoC

Reproduces the verifier-only interleaving from the
[CFRG discussion](https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/)
for [draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html),
and compares it with the proposed `k`-bound client confirmation.

## Run

Python 3.9+; standard library only.

```sh
python3 poc.py
```

All four tests should print **PASS**:

- Honest handshake, either mode: both accept the same key with a matching session.
- Baseline attack: client accepts without a matching honest server session.
- Hardened attack: client rejects at the confirmation check.

## Scope

The attacker knows only the verifier `v`, not `pk_reg` or client secrets.
PAKE/KEM are idealized; HKDF and confirmation checks are concrete.
This demonstrates the specified trace, not a full security proof.
