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
