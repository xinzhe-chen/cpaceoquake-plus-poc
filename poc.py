#!/usr/bin/env python3
"""Reproduce the verifier-only interleaving before and after k binding.

Run: python3 poc.py [--quiet] [--repeat N]
Python 3.12+; install requirements.txt first.

CPace P-256, OQUAKE with KemeleonNR/ML-KEM-1024, registered X-Wing,
Scrypt and HKDF-SHA256 run concrete cryptography and byte messages.
The attacker receives only v and uses public algorithms and wire data.
This executable research reproducer is not a security proof or production
implementation; Python field arithmetic is not constant-time.

Source: draft-vos-cfrg-pqpake-02, Sections 8, 9 and 10. See README for
explicit resolutions of inconsistent pseudocode and encoding sizes.
A matching server must have produced its confirmation response before
client acceptance; it need not have received the final message.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from crypto import (
    AuthenticationError, CPaceState, OQUAKEState, DST, NCT, NKC, NKEY,
    OQUAKE_INIT_LEN, OQUAKE_RESP_LEN, cpace_init, cpace_respond, cpace_finish,
    oquake_init, oquake_respond, oquake_finish, xwing_public_key,
    xwing_encapsulate, xwing_decapsulate, verifier_material,
    hkdf_extract, hkdf_expand, xor, verify_confirmation, require_bytes, lv_encode,
)


# ------------------------------------------------------------------------
# 1. Shared definitions, operations, and observation
# ------------------------------------------------------------------------

MODE_BASELINE = "baseline"
MODE_HARDENED = "hardened"
MODES = (MODE_BASELINE, MODE_HARDENED)
HASH_LEN = 32
CPACE_MESSAGE_LEN = 32 + 1 + 65  # s_i || lv_encode(uncompressed P-256 share)
CONFIRMATION_MESSAGE_LEN = OQUAKE_RESP_LEN + NCT + NKC


class StateError(Exception):
    """A message was delivered in an invalid local state."""


class State(Enum):
    INIT = "Init"
    MSG1 = "Msg1 / CPace offer"
    MSG2 = "Msg2 / CPace response"
    OQUAKE_INIT = "OQUAKE initiation"
    CONFIRMATION = "Confirmation / waiting for client"
    ACCEPT = "Finished / Accept"
    ABORT = "Abort"


@dataclass(frozen=True, repr=False)
class ClientCredentials:
    verifier: bytes
    seed: bytes


@dataclass(frozen=True, repr=False)
class ServerCredentials:
    verifier: bytes
    registered_public_key: bytes


@dataclass(frozen=True, repr=False)
class Witness:
    """Honest execution metadata used only by the external test observer."""

    session: str
    role: str
    identities: Tuple[str, str]
    mode: str
    context: bytes
    transcript: bytes
    lower_key_commitment: bytes
    final_key_commitment: bytes

    def matches(self, other: "Witness") -> bool:
        return (self.role != other.role
                and self.identities == other.identities
                and self.mode == other.mode
                and self.context == other.context
                and self.transcript == other.transcript
                and hmac.compare_digest(self.lower_key_commitment,
                                        other.lower_key_commitment)
                and hmac.compare_digest(self.final_key_commitment,
                                        other.final_key_commitment))


# Cryptographic operations

def frame(*fields: bytes) -> bytes:
    """Four-byte big-endian lengths for public context and observer data."""
    return b"".join(len(item).to_bytes(4, "big") + item for item in fields)


def build_public_context(client_id: str, server_id: str) -> bytes:
    # Section 8: EncodePublicContext(sid, U, S), using an empty application sid.
    return frame(b"", client_id.encode(), server_id.encode())


def decode_cpace_message(message: bytes) -> Tuple[bytes, bytes]:
    require_bytes(message, CPACE_MESSAGE_LEN, "CPace composition message")
    # The selected suite has a fixed 65-byte point, whose LEB128 prefix is 0x41.
    if message[32:33] != b"\x41":
        raise AuthenticationError("invalid CPace length prefix")
    return message[:32], message[33:]


def begin_cpace(verifier: bytes, context: bytes) -> Tuple[CPaceState, bytes]:
    state, point = cpace_init(verifier, context)
    return state, secrets.token_bytes(32) + lv_encode(point)


def respond_cpace(verifier: bytes, context: bytes, message: bytes
                  ) -> Tuple[bytes, bytes]:
    _, point = decode_cpace_message(message)
    reply, key = cpace_respond(verifier, context, point)
    return secrets.token_bytes(32) + lv_encode(reply), key


def finish_cpace(state: CPaceState, message: bytes) -> bytes:
    _, point = decode_cpace_message(message)
    return cpace_finish(state, point)


def bind_cpace_context(public_context: bytes, offer: bytes, reply: bytes) -> bytes:
    s1, _ = decode_cpace_message(offer)
    s2, _ = decode_cpace_message(reply)
    prk = hkdf_extract(s1 + s2, DST + b"CPaceOQUAKE")
    return hkdf_expand(prk, DST + b"SID", 32) + public_context


def ciphertext_pad(sk: bytes) -> bytes:
    return hkdf_expand(sk, DST + b"OTP", NCT)


def mask_ciphertext(sk: bytes, ciphertext: bytes) -> bytes:
    """Wrap the registered-key ciphertext in the current PAKE session."""
    return xor(ciphertext, ciphertext_pad(sk))


def unmask_ciphertext(sk: bytes, enc_c: bytes) -> bytes:
    """Recover the ciphertext; this operation does not recover its secret k."""
    return xor(enc_c, ciphertext_pad(sk))


def derive_client_confirmation(mode: str, sk: bytes, context: bytes,
                               enc_c: bytes, k: Optional[bytes] = None) -> bytes:
    """Derive the server-sent, client-checked tag using the source h1 schedule."""
    if mode not in MODES:
        raise ValueError("unknown confirmation mode")
    confirm_input = context + enc_c
    if mode == MODE_HARDENED:
        if k is None or len(k) != HASH_LEN:
            raise ValueError("hardened confirmation requires a KEM shared secret")
        confirm_input += k
    prk = hkdf_extract(sk, DST + b"h1" + confirm_input)
    return hkdf_expand(prk, DST + b"client_confirm", NKC)


def derive_server_confirmation_and_key(sk: bytes, context: bytes,
                                       enc_c: bytes, k: bytes
                                       ) -> Tuple[bytes, bytes]:
    """Derive the client-sent final tag and session key using source h2."""
    # Identical in both modes. k was already present in source h2.
    prk = hkdf_extract(sk, DST + b"h2" + context + enc_c + k)
    return (hkdf_expand(prk, DST + b"server_confirm", NKC),
            hkdf_expand(prk, DST + b"key", NKEY))


def register(password: bytes, salt: bytes, client_id: str, server_id: str
             ) -> Tuple[ClientCredentials, ServerCredentials]:
    verifier, seed = verifier_material(password, salt, client_id.encode(),
                                       server_id.encode())
    return (ClientCredentials(verifier, seed),
            ServerCredentials(verifier, xwing_public_key(seed)))


# Logging, observation, and test setup

class Trace:
    def __init__(self, quiet: bool = False) -> None:
        self.lines: List[str] = []
        self.quiet = quiet

    def log(self, message: str) -> None:
        self.lines.append(message)
        if not self.quiet:
            print("  " + message)


class Observer:
    """Match earlier server responses to client acceptance; never decide Accept."""

    def __init__(self) -> None:
        self.__sequence = 0
        self.__servers: List[Tuple[int, Witness]] = []
        self.__clients: List[Tuple[int, Witness]] = []

    def record(self, witness: Witness) -> None:
        self.__sequence += 1
        if witness.role == "server":
            self.__servers.append((self.__sequence, witness))
        else:
            self.__clients.append((self.__sequence, witness))

    def matching_servers(self, client_session: str) -> List[str]:
        event = next(((sequence, w) for sequence, w in self.__clients
                      if w.session == client_session), None)
        if event is None:
            return []
        client_sequence, client = event
        return [w.session for sequence, w in self.__servers
                if sequence < client_sequence and client.matches(w)]

    def accepted_clients(self) -> List[str]:
        return [w.session for _, w in self.__clients]


class Endpoint:
    def __init__(self, session: str, mode: str, observer: Observer, trace: Trace,
                 client_id: str = "alice", server_id: str = "server.example"):
        if mode not in MODES:
            raise ValueError("unknown confirmation mode")
        self.session, self.mode = session, mode
        self._observer, self._trace = observer, trace
        self._identities = (client_id, server_id)
        self._base_context = build_public_context(client_id, server_id)
        self._context = self._base_context
        self._wire: List[bytes] = []
        self._sk: Optional[bytes] = None
        self.key: Optional[bytes] = None
        self.state = State.INIT

    def _expect(self, expected: State) -> None:
        if self.state != expected:
            raise StateError("%s expected %s, found %s" %
                             (self.session, expected.value, self.state.value))

    def _move(self, state: State, reason: str) -> None:
        self._trace.log("%s: %s -> %s; %s" %
                        (self.session, self.state.value, state.value, reason))
        self.state = state

    def _reject(self, reason: str) -> None:
        self.key = None
        self._move(State.ABORT, reason)
        raise AuthenticationError(reason)

    def _check(self, message: bytes, length: int, label: str) -> None:
        try:
            require_bytes(message, length, label)
        except AuthenticationError as error:
            self._reject(str(error))

    def _witness(self, role: str) -> Witness:
        assert self._sk is not None and self.key is not None
        return Witness(self.session, role, self._identities, self.mode,
                       self._context, hashlib.sha256(frame(*self._wire)).digest(),
                       hashlib.sha256(DST + b"observer-SK" + self._sk).digest(),
                       hashlib.sha256(DST + b"observer-key" + self.key).digest())


@dataclass
class Fixture:
    """Fresh registration and independent endpoints for one test."""

    mode: str
    trace: Trace
    observer: Observer = field(default_factory=Observer)

    def __post_init__(self) -> None:
        self.client_credentials, self.server_credentials = register(
            secrets.token_bytes(32), secrets.token_bytes(32),
            "alice", "server.example")
        self.public_context = build_public_context("alice", "server.example")

    def client(self, label: str = "C1", mode: Optional[str] = None) -> Client:
        return Client(self.client_credentials, session=label,
                      mode=mode or self.mode,
                      observer=self.observer, trace=self.trace)

    def server(self, label: str = "S1", mode: Optional[str] = None) -> Server:
        return Server(self.server_credentials, session=label,
                      mode=mode or self.mode,
                      observer=self.observer, trace=self.trace)

    def attacker(self) -> AdversaryInterleaver:
        return AdversaryInterleaver(self.server_credentials.verifier,
                                   self.trace)


def ensure(condition: bool, description: str) -> None:
    # Explicit checks remain active when Python is invoked with -O.
    if not condition:
        raise AssertionError(description)


def check_verifier_only_knowledge(attacker: AdversaryInterleaver) -> None:
    """Check declared knowledge; Python memory isolation is not modeled."""
    forbidden = {"password", "seed", "pk_reg", "k_1", "final_key"}
    ensure(not forbidden.intersection(attacker.knowledge),
           "verifier-only actor must not gain the protected credentials/secrets")


def summarize_result(client: Client, server: Server, observer: Observer,
                     attacker: Optional[AdversaryInterleaver] = None) -> dict:
    result = {
        "client_state": client.state.value,
        "server_state": server.state.value,
        "matching_server_sessions": observer.matching_servers(client.session),
    }
    if attacker is not None:
        result["attacker_knowledge_names"] = sorted(attacker.knowledge)
    return result


# ------------------------------------------------------------------------
# 2. Endpoint processing and protocol interactions
# ------------------------------------------------------------------------

class Client(Endpoint):
    def __init__(self, credentials: ClientCredentials, **kwargs):
        super().__init__(**kwargs)
        self._credentials = credentials
        self._cp_state: Optional[CPaceState] = None
        self._oq_state: Optional[OQUAKEState] = None

    def initiate(self) -> bytes:
        self._expect(State.INIT)
        self._cp_state, message = begin_cpace(
            self._credentials.verifier, self._base_context)
        self._wire.append(message)
        self._move(State.MSG1, "send CPace initiation (%d bytes)" % len(message))
        return message

    def receive_cpace(self, reply: bytes) -> bytes:
        self._expect(State.MSG1)
        self._check(reply, CPACE_MESSAGE_LEN, "CPace reply")
        try:
            assert self._cp_state is not None
            key1 = finish_cpace(self._cp_state, reply)
            self._context = bind_cpace_context(
                self._base_context, self._wire[0], reply)
        except AuthenticationError as error:
            self._reject(str(error))
        self._wire.append(reply)
        self._move(State.MSG2, "complete P-256 CPace")
        self._oq_state, message = oquake_init(
            self._credentials.verifier, self._context, key1)
        self._wire.append(message)
        self._move(State.OQUAKE_INIT, "send OQUAKE initiation (%d bytes)" % len(message))
        return message

    def finish(self, reply: bytes) -> bytes:
        self._expect(State.OQUAKE_INIT)
        self._check(reply, CONFIRMATION_MESSAGE_LEN, "OQUAKE+ reply")
        oq_reply = reply[:OQUAKE_RESP_LEN]
        enc_c = reply[OQUAKE_RESP_LEN:OQUAKE_RESP_LEN + NCT]
        target = reply[OQUAKE_RESP_LEN + NCT:]
        self._move(State.CONFIRMATION, "process OQUAKE+ response")
        try:
            assert self._oq_state is not None
            sk = oquake_finish(self._oq_state, oq_reply)
            k = xwing_decapsulate(self._credentials.seed, unmask_ciphertext(sk, enc_c))
            expected = derive_client_confirmation(self.mode, sk, self._context, enc_c, k)
            verify_confirmation(expected, target, "client_confirm")
            server_confirm, key = derive_server_confirmation_and_key(sk, self._context, enc_c, k)
        except (AuthenticationError, ValueError) as error:
            self._reject(str(error))
        self._sk, self.key = sk, key
        self._wire.append(reply)
        self._move(State.ACCEPT, "client_confirm verified; output final key")
        self._observer.record(self._witness("client"))
        self._trace.log(self.session + ": send server_confirm (%d bytes)" % len(server_confirm))
        return server_confirm


class Server(Endpoint):
    def __init__(self, credentials: ServerCredentials, **kwargs):
        super().__init__(**kwargs)
        self._credentials = credentials
        self._key1: Optional[bytes] = None
        self._server_confirm: Optional[bytes] = None

    def respond_cpace(self, offer: bytes) -> bytes:
        self._expect(State.INIT)
        self._check(offer, CPACE_MESSAGE_LEN, "CPace initiation")
        try:
            reply, self._key1 = respond_cpace(
                self._credentials.verifier, self._base_context, offer)
            self._context = bind_cpace_context(self._base_context, offer, reply)
        except AuthenticationError as error:
            self._reject(str(error))
        self._wire.extend((offer, reply))
        self._move(State.MSG2, "send CPace response (%d bytes)" % len(reply))
        return reply

    def respond_oquake(self, offer: bytes) -> bytes:
        self._expect(State.MSG2)
        self._check(offer, OQUAKE_INIT_LEN, "OQUAKE initiation")
        assert self._key1 is not None
        try:
            oq_reply, sk = oquake_respond(
                self._credentials.verifier, self._context, self._key1, offer)
            ciphertext, k = xwing_encapsulate(self._credentials.registered_public_key)
        except (AuthenticationError, ValueError) as error:
            self._reject(str(error))
        enc_c = mask_ciphertext(sk, ciphertext)
        client_confirm = derive_client_confirmation(self.mode, sk, self._context, enc_c, k)
        self._server_confirm, self.key = derive_server_confirmation_and_key(
            sk, self._context, enc_c, k)
        self._sk = sk
        reply = oq_reply + enc_c + client_confirm
        self._wire.extend((offer, reply))
        self._move(State.CONFIRMATION, "send challenge (%d bytes); await reply" % len(reply))
        self._observer.record(self._witness("server"))
        return reply

    def verify(self, server_confirm: bytes) -> bytes:
        self._expect(State.CONFIRMATION)
        self._check(server_confirm, NKC, "server_confirm")
        assert self._server_confirm is not None
        try:
            verify_confirmation(self._server_confirm, server_confirm, "server_confirm")
        except AuthenticationError as error:
            self._reject(str(error))
        self._move(State.ACCEPT, "server_confirm verified; output final key")
        assert self.key is not None
        return self.key


class AdversaryInterleaver:
    """Receives only v; runs public algorithms and consumes byte messages."""

    def __init__(self, verifier: bytes, trace: Trace):
        self.__verifier, self.__trace = verifier, trace
        self.knowledge = {"verifier"}
        self.__ciphertext: Optional[bytes] = None

    def obtain_challenge(self, server: Server, public_context: bytes) -> None:
        cp_state, msg1 = begin_cpace(self.__verifier, public_context)
        msg2 = server.respond_cpace(msg1)
        key1 = finish_cpace(cp_state, msg2)
        context1 = bind_cpace_context(public_context, msg1, msg2)
        oq_state, msg3 = oquake_init(self.__verifier, context1, key1)
        msg4 = server.respond_oquake(msg3)
        sk1 = oquake_finish(oq_state, msg4[:OQUAKE_RESP_LEN])
        enc_c = msg4[OQUAKE_RESP_LEN:OQUAKE_RESP_LEN + NCT]
        self.__ciphertext = unmask_ciphertext(sk1, enc_c)
        self.knowledge.update(("CPace_secret_1", "SK_1", "r_1", "c_1"))
        self.__trace.log("A / Session 1: computes SK_1; unmasks X-Wing c_1")
        self.__trace.log("A / Session 1: no seed, pk_reg, k_1, or final key")

    def impersonate_server(self, client: Client, public_context: bytes) -> bytes:
        msg1 = client.initiate()
        msg2, key1 = respond_cpace(self.__verifier, public_context, msg1)
        msg3 = client.receive_cpace(msg2)
        context2 = bind_cpace_context(public_context, msg1, msg2)
        oq_reply, sk2 = oquake_respond(self.__verifier, context2, key1, msg3)
        self.knowledge.update(("CPace_secret_2", "SK_2", "r_2"))
        if self.__ciphertext is None:
            raise StateError("Session 1 challenge has not been obtained")
        candidate_k = secrets.token_bytes(NKEY)
        self.__trace.log("A / Session 2: rewrap c_1 with r_2; recompute client_confirm")
        if client.mode == MODE_HARDENED:
            self.__trace.log("A / Session 2: k_1 unavailable; use fresh guessed k")
        enc_c = mask_ciphertext(sk2, self.__ciphertext)
        forged = derive_client_confirmation(client.mode, sk2, context2, enc_c, candidate_k)
        msg5 = client.finish(oq_reply + enc_c + forged)
        self.knowledge.add("server_confirm_2")
        return msg5


def run_honest_handshake(client: Client, server: Server) -> None:
    """Deliver the five composition messages in their wire order."""
    msg1 = client.initiate()                  # C -> S: CPace initiation
    msg2 = server.respond_cpace(msg1)         # S -> C: CPace response
    msg3 = client.receive_cpace(msg2)         # C -> S: OQUAKE initiation
    msg4 = server.respond_oquake(msg3)        # S -> C: OQUAKE+ confirmation
    msg5 = client.finish(msg4)                # C -> S: final confirmation
    server.verify(msg5)


def run_interleaving(client: Client, server: Server,
                     attacker: AdversaryInterleaver, public_context: bytes
                     ) -> None:
    """Deliver the two-session translation; propagate client check failures."""
    attacker.obtain_challenge(server, public_context)     # Session 1: A <-> S1
    attacker.impersonate_server(client, public_context)   # Session 2: C2 <-> A
    # Discard msg5_2; S1 remains waiting for its own final confirmation.


# ------------------------------------------------------------------------
# 3. Four comparison tests and command-line runner
# ------------------------------------------------------------------------

def test_baseline_honest(trace: Trace) -> dict:
    """Both baseline endpoints accept the same key in one matching session."""
    experiment = Fixture(MODE_BASELINE, trace)
    client, server = experiment.client(), experiment.server()
    run_honest_handshake(client, server)

    ensure(client.state == server.state == State.ACCEPT,
           "normal endpoints must accept")
    ensure(client.key is not None and hmac.compare_digest(client.key, server.key),
           "normal endpoints must derive the same final key")
    ensure(experiment.observer.matching_servers(client.session)
           == [server.session],
           "normal client must have a matching server witness")
    trace.log("Observer: matching server session exists; both final keys agree")
    return summarize_result(client, server, experiment.observer)


def test_baseline_interleaving(trace: Trace) -> dict:
    """The baseline client accepts without a matching honest server session."""
    experiment = Fixture(MODE_BASELINE, trace)
    client, server = experiment.client("C2"), experiment.server("S1")
    attacker = experiment.attacker()

    run_interleaving(client, server, attacker, experiment.public_context)
    ensure(client.state == State.ACCEPT,
           "baseline interleaving must reach Accept")
    ensure(experiment.observer.matching_servers(client.session) == [],
           "baseline Accept must lack a matching server session")
    ensure(server.state == State.CONFIRMATION, "S1 must remain pending")
    check_verifier_only_knowledge(attacker)
    trace.log("Observer: Client.Accept has no matching server witness")
    return summarize_result(client, server, experiment.observer, attacker)


def test_hardened_honest(trace: Trace) -> dict:
    """Binding k preserves the honest handshake and matching session."""
    experiment = Fixture(MODE_HARDENED, trace)
    client, server = experiment.client(), experiment.server()
    run_honest_handshake(client, server)

    ensure(client.state == server.state == State.ACCEPT,
           "normal endpoints must accept")
    ensure(client.key is not None and hmac.compare_digest(client.key, server.key),
           "normal endpoints must derive the same final key")
    ensure(experiment.observer.matching_servers(client.session)
           == [server.session],
           "normal client must have a matching server witness")
    trace.log("Observer: matching server session exists; both final keys agree")
    return summarize_result(client, server, experiment.observer)


def test_hardened_interleaving(trace: Trace) -> dict:
    """The same translation fails at the client's confirmation comparison."""
    experiment = Fixture(MODE_HARDENED, trace)
    client, server = experiment.client("C2"), experiment.server("S1")
    attacker = experiment.attacker()

    try:
        run_interleaving(client, server, attacker, experiment.public_context)
    except AuthenticationError as error:
        ensure(str(error) == "client_confirm mismatch",
               "the interleaving must fail at the client confirmation check")
    else:
        raise AssertionError("expected AuthenticationError")

    ensure(client.state == State.ABORT and client.key is None,
           "hardened client must reject before outputting a final key")
    ensure(experiment.observer.accepted_clients() == [], "no Client.Accept event")
    ensure(server.state == State.CONFIRMATION, "S1 must remain pending")
    check_verifier_only_knowledge(attacker)
    trace.log("Observer: guessed confirmation fails; no Client.Accept event")
    return summarize_result(client, server, experiment.observer, attacker)


TESTS = (
    ("Test 1: Baseline honest handshake", test_baseline_honest),
    ("Test 2: Baseline verifier-only interleaving", test_baseline_interleaving),
    ("Test 3: Hardened honest handshake", test_hardened_honest),
    ("Test 4: Hardened verifier-only interleaving", test_hardened_interleaving),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="show results only")
    parser.add_argument("--repeat", type=int, default=1,
                        help="repeat all four scenarios with fresh randomness")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    print("CPaceOQUAKE+ verifier-only exposure: baseline vs k binding")
    print("Crypto: P-256/Scrypt, KemeleonNR/ML-KEM-1024, X-Wing, HKDF-SHA256")
    passed = failed = 0
    for repetition in range(1, args.repeat + 1):
        for name, test in TESTS:
            if not args.quiet:
                print("\n" + name)
            try:
                result = test(Trace(args.quiet))
                passed += 1
                print("PASS: %s (run %d)" % (name, repetition))
                if not args.quiet:
                    print("  Client=%s; Server=%s; matching servers=%s" %
                          (result["client_state"], result["server_state"],
                           result["matching_server_sessions"]))
            except Exception as error:
                failed += 1
                print("FAIL: %s: %s: %s" % (name, type(error).__name__, error))
    print("\nResult: %d/%d PASS; %d FAIL" % (passed, passed + failed, failed))
    return int(failed > 0)


if __name__ == "__main__":
    raise SystemExit(main())
