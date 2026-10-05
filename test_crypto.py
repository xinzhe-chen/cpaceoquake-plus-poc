"""Published component vectors plus focused arithmetic/wire rejection checks.

Run: python -m unittest -v test_crypto
Fixtures and source hashes are in test_vectors.json; no network is needed.
The four PoC scenarios are run separately, once, by python poc.py.
"""

import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import crypto as c
import poc

VECTORS = json.loads(Path(__file__).with_name("test_vectors.json").read_text())


def unhex(value):
    return bytes.fromhex(value)


class PublishedVectors(unittest.TestCase):
    def test_hkdf_rfc5869_sha256(self):
        for index, v in enumerate(VECTORS["hkdf"], 1):
            with self.subTest(case=index):
                prk = c.hkdf_extract(unhex(v["salt"]), unhex(v["IKM"]))
                self.assertEqual(prk, unhex(v["PRK"]))
                self.assertEqual(c.hkdf_expand(prk, unhex(v["info"]), v["L"]),
                                 unhex(v["OKM"]))

    def test_hash_to_curve_rfc9380_p256_nu(self):
        suite = VECTORS["hash_to_curve"]
        for v in suite["vectors"]:
            with self.subTest(msg=v["msg"]):
                message, dst = v["msg"].encode(), suite["dst"].encode()
                u = int.from_bytes(c.expand_message_xmd(message, dst, 48), "big") % c.P256_P
                self.assertEqual(u, int(v["u"][0], 16))
                point = b"\x04" + int(v["P"]["x"], 16).to_bytes(32, "big")
                point += int(v["P"]["y"], 16).to_bytes(32, "big")
                self.assertEqual(c.encode_to_curve(message, dst), point)

    def test_cpace_draft21_p256(self):
        v = {k: unhex(x) for k, x in VECTORS["cpace"].items()}
        self.assertEqual(c.cpace_generator(v["PRS"], v["sid"], v["CI"]), v["g"])
        ya, yb = int.from_bytes(v["ya"], "big"), int.from_bytes(v["yb"], "big")
        self.assertEqual(c.point_multiply(ya, v["g"]), v["Ya"])
        self.assertEqual(c.point_multiply(yb, v["g"]), v["Yb"])
        for scalar, peer in [(ya, v["Yb"]), (yb, v["Ya"])]:
            self.assertEqual(c.point_multiply(scalar, peer)[1:33], v["K"])
            self.assertEqual(c.cpace_key(scalar, peer, v["sid"], v["Ya"], v["Yb"],
                                         v["ADa"], v["ADb"]), v["ISK_IR"])
        points = VECTORS["cpace_points"]
        valid = points["Valid"]
        scalar = int(valid["s"], 16)
        self.assertEqual(c.point_multiply(scalar, unhex(valid["X"])),
                         unhex(valid["G.scalar_mult(s,X) (full coordinates)"]))
        for name in ["Invalid Y1", "Invalid Y2"]:
            with self.subTest(point=name), self.assertRaises(c.AuthenticationError):
                c.cpace_key(scalar, unhex(points[name]), b"", v["Ya"], v["Yb"])

    def test_mlkem_nist_acvp_keygen(self):
        for v in VECTORS["mlkem_keygen"]:
            with self.subTest(parameter=v["parameterSet"], tcId=v["tcId"]):
                cls = getattr(mlkem, v["parameterSet"].replace("-", "") + "PrivateKey")
                private = cls.from_seed_bytes(unhex(v["d"] + v["z"]))
                self.assertEqual(private.public_key().public_bytes_raw(), unhex(v["ek"]))

    def test_xwing_draft10_keygen_and_decapsulation(self):
        for index, v in enumerate(VECTORS["xwing"], 1):
            with self.subTest(case=index):
                seed = unhex(v["seed"])
                self.assertEqual(c.xwing_public_key(seed), unhex(v["pk"]))
                self.assertEqual(c.xwing_decapsulate(seed, unhex(v["ct"])), unhex(v["ss"]))

    def test_scrypt_rfc7914_and_verifier_material(self):
        for v in VECTORS["scrypt"]:
            with self.subTest(n=v["n"]):
                actual = Scrypt(salt=v["salt"].encode(), length=v["length"],
                                n=v["n"], r=v["r"], p=v["p"]).derive(v["password"].encode())
                self.assertEqual(actual, unhex(v["output"]))
        password, salt, u, s = b"test password", bytes(range(32)), b"alice", b"server.example"
        expected = hashlib.scrypt(c.DST + password + u + s, salt=salt,
                                  n=32768, r=8, p=1, dklen=64, maxmem=128 * 1024 * 1024)
        verifier, seed = c.verifier_material(password, salt, u, s)
        self.assertEqual(verifier + seed, expected)
        self.assertEqual((len(verifier), len(seed)), (32, 32))


class IntegrationAndRejection(unittest.TestCase):
    def test_kemeleon_arithmetic_and_bua_roundtrip(self):
        # Independent base-q arithmetic, including the maximal encoded integer.
        maximum = (1 << (8 * c.BUA_NT)) - 1
        for value in [0, 1, c.KEMELEON_MODULUS - 1, c.KEMELEON_MODULUS, maximum]:
            encoded = value.to_bytes(c.BUA_NT, "big")
            coefficients = c.unpack_coefficients(c.kemeleon_decode(encoded))
            reconstructed = sum(a * pow(3329, i) for i, a in enumerate(coefficients))
            self.assertEqual(reconstructed, value % pow(3329, 1024))
        # Exercise both ends of the randomized multiplier's allowed range.
        private = mlkem.MLKEM1024PrivateKey.from_seed_bytes(bytes(range(64)))
        packed = private.public_key().public_bytes_raw()[:-32]
        for chooser in [lambda n: 0, lambda n: n - 1]:
            with patch.object(c.secrets, "randbelow", side_effect=chooser):
                encoded = c.kemeleon_encode(packed)
            self.assertEqual(len(encoded), c.BUA_NT)
            self.assertEqual(c.kemeleon_decode(encoded), packed)
        self.assertGreaterEqual(8 * c.BUA_NT - c.KEMELEON_MODULUS.bit_length(), 256)
        # Encapsulation of the re-encoded public key reaches the actual ML-KEM private key.
        public, private = c.bua_key_pair()
        ciphertext, shared = c.bua_encapsulate(public)
        self.assertEqual((len(public), len(ciphertext), len(shared)), (1594, 1568, 32))
        self.assertEqual(private.decapsulate(ciphertext), shared)

    def test_xwing_encapsulation_and_implicit_rejection(self):
        seed = bytes(range(32))
        ciphertext, key = c.xwing_encapsulate(c.xwing_public_key(seed))
        self.assertEqual((len(ciphertext), len(key)), (1120, 32))
        self.assertEqual(c.xwing_decapsulate(seed, ciphertext), key)
        changed_mlkem = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        self.assertNotEqual(c.xwing_decapsulate(seed, changed_mlkem), key)
        with self.assertRaises(ValueError):
            c.xwing_decapsulate(seed, ciphertext[:-32] + bytes(32))
        with self.assertRaises(c.AuthenticationError):
            c.xwing_decapsulate(seed, ciphertext[:-1])

    def test_oquake_agreement_and_context_rejection(self):
        prs, context, secret = bytes(range(32)), b"public context", b"CPace secret"
        state, initiation = c.oquake_init(prs, context, secret)
        response, key = c.oquake_respond(prs, context, secret, initiation)
        self.assertEqual((len(initiation), len(response)), (1690, 1632))
        self.assertEqual(c.oquake_finish(state, response), key)
        changed_tag = response[:-1] + bytes([response[-1] ^ 1])
        self.assertNotEqual(c.oquake_finish(state, changed_tag), key)
        for wrong_prs, wrong_context, wrong_secret in [
            (bytes(32), context, secret), (prs, context + b"x", secret),
            (prs, context, secret + b"x")
        ]:
            reply, other_key = c.oquake_respond(wrong_prs, wrong_context, wrong_secret, initiation)
            self.assertNotEqual(c.oquake_finish(state, reply), other_key)
        with self.assertRaises(c.AuthenticationError):
            c.oquake_finish(state, response[:-1])
        with self.assertRaises(c.AuthenticationError):
            c.oquake_respond(prs, context, secret, initiation[:-1])

    def test_wire_and_endpoint_rejection(self):
        verifier, seed = bytes(range(32)), bytes(reversed(range(32)))
        client_creds = poc.ClientCredentials(verifier, seed)
        server_creds = poc.ServerCredentials(verifier, c.xwing_public_key(seed))
        def endpoints():
            args = dict(mode=poc.MODE_BASELINE, observer=poc.Observer(), trace=poc.Trace(True))
            return (poc.Client(client_creds, session="C", **args),
                    poc.Server(server_creds, session="S", **args))
        for malformed in [b"", bytes(98), bytes(32) + b"\x41\x04" + bytes(64)]:
            _, server = endpoints()
            with self.subTest(message=malformed[:34]), self.assertRaises(c.AuthenticationError):
                server.respond_cpace(malformed)
            self.assertEqual(server.state, poc.State.ABORT)
        client, server = endpoints()
        with self.assertRaises(poc.StateError):
            client.finish(bytes(poc.CONFIRMATION_MESSAGE_LEN))
        offer = client.initiate()
        reply = server.respond_cpace(offer)
        self.assertEqual((len(offer), len(reply)), (98, 98))
        client.receive_cpace(reply)
        with self.assertRaises(c.AuthenticationError):
            client.finish(bytes(poc.CONFIRMATION_MESSAGE_LEN - 1))
        self.assertEqual(client.state, poc.State.ABORT)
        self.assertIsNone(client.key)
        self.assertEqual(poc.build_public_context("alice", "server.example"),
                         bytes(4) + b"\x00\x00\x00\x05alice\x00\x00\x00\x0eserver.example")


if __name__ == "__main__":
    unittest.main(verbosity=2)
