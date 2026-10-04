# CPaceOQUAKE+ authentication PoC

Companion to **draft-chen-cfrg-pqpake-authentication-00**, an individual
Informational Internet-Draft by Xinzhe Chen, National University of Singapore.

The PoC reproduces the verifier-only interleaving from the
[CFRG discussion](https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/)
against [draft-vos-cfrg-pqpake-02](https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html),
and repeats it with the proposed confirmation binding.

## Reproduce

Python 3.9+; no dependencies or installation.

```sh
python3 protocol_harness.py
```

The single script prints state transitions and checks four scenarios:

| Scenario | Expected result |
|---|---|
| Baseline, honest handshake | Both accept with the same key and a matching server session |
| Baseline, two-session interleaving | Client accepts without a matching honest server session |
| Hardened, honest handshake | Both accept with the same key and a matching server session |
| Hardened, same interleaving | Client rejects with `AuthenticationError` and exposes no key |

All four should print **PASS**: the second PASS means the baseline gap was
reproduced; the fourth means the hardened client rejected the attack.
Failed checks return a nonzero exit status. Optional repeated comparison:

```sh
python3 protocol_harness.py --quiet --repeat 100
```

The only confirmation change, applied at both endpoints, is:

```diff
-h1 = Extract(SK, DST || "h1" || public_context || enc_c)
+h1 = Extract(SK, DST || "h1" || public_context || enc_c || k)
```

**Model:** the attacker obtains `v`, but not `pk_reg`, the password, or
client private material. PAKE and KEM operations are ideal opaque
functionalities; HKDF, masking and confirmation checks are concrete.
This demonstrates the stated trace, not a full protocol security proof.

## Draft

- [Markdown source](draft-chen-cfrg-pqpake-authentication-00.md)
- [HTML reading edition](rendered/draft-chen-cfrg-pqpake-authentication-00.html)
- [Submission text](rendered/draft-chen-cfrg-pqpake-authentication-00.txt)
- [RFCXML](rendered/draft-chen-cfrg-pqpake-authentication-00.xml)

For Chrome, open the generated **HTML** locally (download it if viewing
on GitHub). Ordinary Markdown previews do not parse kramdown-rfc markers.
The draft has not been submitted to IETF.

To rebuild these editions, install `kramdown-rfc` and `xml2rfc`, then run
`make`. These authoring tools are not needed to run the PoC.

The layout follows the root draft/README/Makefile convention used by
[PQPAKE](https://github.com/chris-wood/draft-pqpake) and
[OPAQUE](https://github.com/cfrg/draft-irtf-cfrg-opaque), with one standalone
Python reproducer and the generated reading editions in `rendered/`.
