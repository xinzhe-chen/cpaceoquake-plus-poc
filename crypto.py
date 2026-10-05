"""Concrete cryptography for the CPaceOQUAKE+ reproducer.

Algorithms: draft-vos-cfrg-pqpake-02 (P-256/Scrypt configuration),
draft-irtf-cfrg-cpace-21, RFC 9380, draft-veitch-kemeleon-00,
draft-connolly-cfrg-xwing-kem-10, and RFC 5869.

ML-KEM, X25519, ECDH, HMAC, HKDF-Expand and Scrypt use cryptography.
Full-point multiplication uses ecdsa. SSWU and Kemeleon perform actual
field/integer arithmetic, not secret registries. This research code's
Python arithmetic is not constant-time. See implementation notes in README.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from ecdsa import NIST256p, ellipticcurve


# Section 10's alternative configuration, including its advertised UPK size.
DST = bytes.fromhex("b840fa4d4b4caec9e25d13d8c016cfe93e7468d54e936490bd0b0a3ffca1a01b")
NKEY = NSEC = NVERIFIER = 32
NKC = 64
NCT = 1120                         # Registered X-Wing ciphertext
BUA_NCT = 1568                     # ML-KEM-1024 ciphertext
BUA_NPK = 1594
BUA_NT = BUA_NPK - 32
OQUAKE_INIT_LEN = 3 * NSEC + BUA_NT + 32
OQUAKE_RESP_LEN = BUA_NCT + NKC
CPACE_DSI = b"CPaceP256_XMD:SHA-256_SSWU_NU_"
CPACE_DST = CPACE_DSI + b"_DST"
P256_P = NIST256p.curve.p()
P256_A = NIST256p.curve.a()
P256_B = NIST256p.curve.b()
P256_ORDER = NIST256p.order
KEMELEON_Q = 3329
KEMELEON_COEFFICIENTS = 1024
KEMELEON_MODULUS = KEMELEON_Q ** KEMELEON_COEFFICIENTS
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")


class AuthenticationError(Exception):
    """A confirmation or a cryptographic input check failed."""


def require_bytes(value: bytes, length: int, name: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise AuthenticationError("invalid " + name + " length/type")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract, with arguments in the draft's order."""
    mac = crypto_hmac.HMAC(salt, hashes.SHA256())
    mac.update(ikm)
    return mac.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(prk)


def xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def verify_confirmation(expected: bytes, received: bytes, label: str) -> None:
    if not hmac.compare_digest(expected, received):
        raise AuthenticationError(label + " mismatch")


def lv_encode(data: bytes) -> bytes:
    """CPace prepend_len / lv_encode: unsigned LEB128 length prefix."""
    length, prefix = len(data), bytearray()
    while length >= 128:
        prefix.append((length & 127) | 128)
        length >>= 7
    prefix.append(length)
    return bytes(prefix) + data


def lv_cat(*fields: bytes) -> bytes:
    return b"".join(lv_encode(item) for item in fields)


# CPace: password-derived generator, ephemeral public points and shared key.

def expand_message_xmd(message: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380 Section 5.3.1, SHA-256 instantiation."""
    if not 0 < length <= 255 * 32 or len(dst) > 255:
        raise ValueError("unsupported XMD length/DST")
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(bytes(64) + message + length.to_bytes(2, "big")
                        + b"\x00" + dst_prime).digest()
    block = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    output = block
    for index in range(2, (length + 31) // 32 + 1):
        block = hashlib.sha256(xor(b0, block) + bytes([index])
                               + dst_prime).digest()
        output += block
    return output[:length]


def encode_to_curve(message: bytes, dst: bytes = CPACE_DST) -> bytes:
    """P256_XMD:SHA-256_SSWU_NU_, RFC 9380 Sections 6.6.2 and 8.2."""
    p, a, b, z = P256_P, P256_A, P256_B, -10
    u = int.from_bytes(expand_message_xmd(message, dst, 48), "big") % p
    denominator = (z * z * pow(u, 4, p) + z * u * u) % p
    inverse = pow(denominator, p - 2, p)   # inv0(0) = 0
    if inverse:
        x = (-b * pow(a, p - 2, p) * (1 + inverse)) % p
    else:
        x = (b * pow(z * a % p, p - 2, p)) % p
    gx = (pow(x, 3, p) + a * x + b) % p
    y = pow(gx, (p + 1) // 4, p)
    if y * y % p != gx:
        x = (z * u * u * x) % p
        gx = (pow(x, 3, p) + a * x + b) % p
        y = pow(gx, (p + 1) // 4, p)
    if y * y % p != gx:
        raise ArithmeticError("SSWU failed to produce a curve point")
    if (y & 1) != (u & 1):
        y = -y % p
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def cpace_generator(prs: bytes, context: bytes,
                    secret_context: bytes = b"") -> bytes:
    # CPace's CI = secret_context; sid = public_context.
    padding_length = max(0, 64 - len(lv_encode(prs))
                         - len(lv_encode(CPACE_DSI)) - 1)
    message = lv_cat(CPACE_DSI, prs, bytes(padding_length),
                     secret_context, context)
    return encode_to_curve(message)


def point_multiply(scalar: int, point: bytes) -> bytes:
    require_bytes(point, 65, "P-256 point")
    if point[0] != 4 or not 1 <= scalar < P256_ORDER:
        raise AuthenticationError("invalid P-256 point/scalar")
    # Native parser checks coordinates, curve membership and infinity.
    numbers = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), point).public_numbers()
    affine = ellipticcurve.Point(NIST256p.curve, numbers.x, numbers.y,
                                 P256_ORDER)
    product = ellipticcurve.PointJacobi.from_affine(affine) * scalar
    return b"\x04" + product.x().to_bytes(32, "big") + product.y().to_bytes(32, "big")


def cpace_key(scalar: int, peer: bytes, context: bytes, ya: bytes, yb: bytes,
              ada: bytes = b"", adb: bytes = b"") -> bytes:
    require_bytes(peer, 65, "P-256 peer point")
    if peer[0] != 4:
        raise AuthenticationError("P-256 share must be uncompressed")
    try:
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)
        shared_x = ec.derive_private_key(scalar, ec.SECP256R1()).exchange(
            ec.ECDH(), public)
    except ValueError as error:
        raise AuthenticationError("invalid P-256 peer point") from error
    transcript = lv_cat(ya, ada) + lv_cat(yb, adb)
    return hashlib.sha256(lv_cat(CPACE_DSI + b"_ISK", context, shared_x)
                          + transcript).digest()


@dataclass(frozen=True, repr=False)
class CPaceState:
    scalar: int
    public: bytes
    context: bytes


def cpace_init(prs: bytes, context: bytes) -> Tuple[CPaceState, bytes]:
    scalar = secrets.randbelow(P256_ORDER - 1) + 1
    public = point_multiply(scalar, cpace_generator(prs, context))
    return CPaceState(scalar, public, context), public


def cpace_respond(prs: bytes, context: bytes, ya: bytes) -> Tuple[bytes, bytes]:
    scalar = secrets.randbelow(P256_ORDER - 1) + 1
    yb = point_multiply(scalar, cpace_generator(prs, context))
    return yb, cpace_key(scalar, ya, context, ya, yb)


def cpace_finish(state: CPaceState, yb: bytes) -> bytes:
    return cpace_key(state.scalar, yb, state.context, state.public, yb)


# KemeleonNR / ML-BUA-sKEM: no ciphertext or secret lookup tables.

def unpack_coefficients(packed: bytes) -> list:
    require_bytes(packed, 1536, "ML-KEM-1024 t")
    coefficients = []
    for offset in range(0, len(packed), 3):
        value = int.from_bytes(packed[offset:offset + 3], "little")
        coefficients.extend((value & 4095, value >> 12))
    if any(coefficient >= KEMELEON_Q for coefficient in coefficients):
        raise AuthenticationError("noncanonical ML-KEM coefficients")
    return coefficients


def pack_coefficients(coefficients: list) -> bytes:
    return b"".join((coefficients[i] | (coefficients[i + 1] << 12))
                    .to_bytes(3, "little")
                    for i in range(0, len(coefficients), 2))


def kemeleon_encode(packed: bytes) -> bytes:
    coefficients = unpack_coefficients(packed)
    value = 0
    for coefficient in reversed(coefficients):
        value = value * KEMELEON_Q + coefficient
    # Fill the advertised Nt-byte space. Its statistical margin exceeds 256
    # bits; -02's Npk does not equal ceil(log2(q^1024)+256)/8 + 32.
    maximum = (1 << (8 * BUA_NT)) - 1
    multiplier = secrets.randbelow((maximum - value) // KEMELEON_MODULUS + 1)
    return (value + multiplier * KEMELEON_MODULUS).to_bytes(BUA_NT, "big")


def kemeleon_decode(encoded: bytes) -> bytes:
    require_bytes(encoded, BUA_NT, "KemeleonNR t")
    value = int.from_bytes(encoded, "big") % KEMELEON_MODULUS
    coefficients = []
    for _ in range(KEMELEON_COEFFICIENTS):
        value, coefficient = divmod(value, KEMELEON_Q)
        coefficients.append(coefficient)
    return pack_coefficients(coefficients)


def bua_key_pair() -> Tuple[bytes, mlkem.MLKEM1024PrivateKey]:
    private = mlkem.MLKEM1024PrivateKey.from_seed_bytes(secrets.token_bytes(64))
    public = private.public_key().public_bytes_raw()
    return kemeleon_encode(public[:-32]) + public[-32:], private


def bua_encapsulate(public: bytes) -> Tuple[bytes, bytes]:
    require_bytes(public, BUA_NPK, "ML-BUA-sKEM public key")
    raw_public = kemeleon_decode(public[:-32]) + public[-32:]
    key = mlkem.MLKEM1024PublicKey.from_public_bytes(raw_public)
    shared, ciphertext = key.encapsulate()
    return ciphertext, shared


# OQUAKE's two messages, Feistel masking and both KDF layers (Section 8.2).

@dataclass(frozen=True, repr=False)
class OQUAKEState:
    effective_prs: bytes
    private: mlkem.MLKEM1024PrivateKey
    public: bytes
    initiation: bytes
    context: bytes
    secret_context: bytes


def effective_prs(prs: bytes, context: bytes, secret_context: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(prs, DST + b"OQUAKE-context"
                                    + context + secret_context),
                       DST + b"effective_PRS", NKEY)


def oquake_pad(prs: bytes, context: bytes, rho: bytes,
               data: bytes, label: bytes, length: int) -> bytes:
    prk = hkdf_extract(prs, DST + b"OQUAKE" + context + rho + data)
    return hkdf_expand(prk, DST + label, length)


def oquake_init(prs: bytes, context: bytes, secret_context: bytes
                ) -> Tuple[OQUAKEState, bytes]:
    password = effective_prs(prs, context, secret_context)
    public, private = bua_key_pair()
    ut, rho = public[:-32], public[-32:]
    r = secrets.token_bytes(3 * NSEC)
    t = xor(ut, oquake_pad(password, context, rho, r, b"T_pad", BUA_NT))
    s = xor(r, oquake_pad(password, context, rho, t, b"s_pad", 3 * NSEC))
    initiation = s + t + rho
    return OQUAKEState(password, private, public, initiation,
                       context, secret_context), initiation


def oquake_outputs(password: bytes, public: bytes, initiation: bytes,
                   ciphertext: bytes, k: bytes, context: bytes,
                   secret_context: bytes) -> Tuple[bytes, bytes]:
    s_t = initiation[:-32]
    prk = hkdf_extract(password, DST + b"OQUAKE" + context + s_t
                       + public + ciphertext + k)
    intermediate = hkdf_expand(prk, DST + b"sk", NKEY)
    transcript = initiation + ciphertext
    final_prk = hkdf_extract(intermediate, DST + b"final_key" + context
                             + secret_context + transcript)
    return (hkdf_expand(prk, DST + b"confirm", NKC),
            hkdf_expand(final_prk, DST + b"key", NKEY))


def oquake_respond(prs: bytes, context: bytes, secret_context: bytes,
                   initiation: bytes) -> Tuple[bytes, bytes]:
    require_bytes(initiation, OQUAKE_INIT_LEN, "OQUAKE initiation")
    password = effective_prs(prs, context, secret_context)
    s, t, rho = initiation[:3 * NSEC], initiation[3 * NSEC:-32], initiation[-32:]
    r = xor(s, oquake_pad(password, context, rho, t, b"s_pad", 3 * NSEC))
    ut = xor(t, oquake_pad(password, context, rho, r, b"T_pad", BUA_NT))
    public = ut + rho
    ciphertext, k = bua_encapsulate(public)
    confirmation, key = oquake_outputs(password, public, initiation,
                                        ciphertext, k, context, secret_context)
    return ciphertext + confirmation, key


def oquake_finish(state: OQUAKEState, response: bytes) -> bytes:
    require_bytes(response, OQUAKE_RESP_LEN, "OQUAKE response")
    ciphertext, target = response[:BUA_NCT], response[BUA_NCT:]
    k = state.private.decapsulate(ciphertext)
    expected, key = oquake_outputs(state.effective_prs, state.public,
                                   state.initiation, ciphertext, k,
                                   state.context, state.secret_context)
    # Section 8.2.3 returns a random key on inner confirmation failure.
    # OQUAKE+ will reject through decapsulation / outer confirmation.
    return key if hmac.compare_digest(expected, target) else secrets.token_bytes(NKEY)


# X-Wing: actual ML-KEM-768 + X25519 and the specified SHA3-256 combiner.

def xwing_expand(seed: bytes):
    require_bytes(seed, 32, "X-Wing seed")
    expanded = hashlib.shake_256(seed).digest(96)
    ml_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    x_private = x25519.X25519PrivateKey.from_private_bytes(expanded[64:])
    return ml_private, x_private


def xwing_public_key(seed: bytes) -> bytes:
    ml_private, x_private = xwing_expand(seed)
    return (ml_private.public_key().public_bytes_raw()
            + x_private.public_key().public_bytes_raw())


def xwing_combine(ml_shared: bytes, x_shared: bytes,
                   ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ml_shared + x_shared + ct_x + pk_x
                            + XWING_LABEL).digest()


def xwing_encapsulate(public: bytes) -> Tuple[bytes, bytes]:
    require_bytes(public, 1216, "X-Wing public key")
    pk_m, pk_x = public[:1184], public[1184:]
    ml_shared, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    ephemeral = x25519.X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    x_shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    return ct_m + ct_x, xwing_combine(ml_shared, x_shared, ct_x, pk_x)


def xwing_decapsulate(seed: bytes, ciphertext: bytes) -> bytes:
    require_bytes(ciphertext, NCT, "X-Wing ciphertext")
    ml_private, x_private = xwing_expand(seed)
    ct_m, ct_x = ciphertext[:1088], ciphertext[1088:]
    ml_shared = ml_private.decapsulate(ct_m)  # ML-KEM implicit rejection
    x_shared = x_private.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    return xwing_combine(ml_shared, x_shared, ct_x,
                         x_private.public_key().public_bytes_raw())


def verifier_material(password: bytes, salt: bytes,
                       client_id: bytes, server_id: bytes) -> Tuple[bytes, bytes]:
    material = Scrypt(salt=salt, length=64, n=32768, r=8, p=1).derive(
        DST + password + client_id + server_id)
    return material[:NVERIFIER], material[NVERIFIER:]
