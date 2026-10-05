#!/usr/bin/env python3
"""Reproduce the verifier-only interleaving before and after k binding.

Run: python3 protocol_harness.py [--quiet] [--repeat N]
Python 3.9+; standard library only.

Layout: shared operations and model support; endpoint processing and
protocol interactions; comparison tests and the command-line runner.

CPace/OQUAKE and the registered KEM are ideal functionalities with opaque
capabilities. HKDF-SHA256, ciphertext masking, confirmation checks and
endpoint state transitions are concrete. The attacker receives only v;
it cannot read endpoint secrets or the ideal registries. This is a model
contract, not isolation against arbitrary Python introspection.

Source: draft-vos-cfrg-pqpake-02, Sections 9.2 and 9.4, and
https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/
This finite simulation is not a concrete PQ implementation or a security
proof. A matching server must have started its confirmation response
before client acceptance; it need not have received the final message.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ------------------------------------------------------------------------
# 1. Shared definitions, operations, and model support
# ------------------------------------------------------------------------

MODE_BASELINE = "baseline"
MODE_HARDENED = "hardened"
MODES = (MODE_BASELINE, MODE_HARDENED)
HASH_LEN = NCT = NKC = NKEY = 32
# Illustrative suite domain; not an interoperable CPaceOQUAKE+ ciphersuite.
DST = b"pqpake-authentication-harness-v1/"


# Data types and states

class AuthenticationError(Exception):
    """A confirmation, ideal credential check, or decapsulation failed."""


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
class _InitiatorCapability:
    token: bytes
    private_capability: bytes


@dataclass(frozen=True, repr=False)
class _PublicKey:
    capability: bytes


@dataclass(frozen=True, repr=False)
class _PrivateKey:
    capability: bytes


@dataclass(frozen=True, repr=False)
class ClientCredentials:
    verifier: bytes
    seed: bytes


@dataclass(frozen=True, repr=False)
class ServerCredentials:
    verifier: bytes
    registered_public_key: _PublicKey


@dataclass(frozen=True)
class Offer:
    token: bytes


@dataclass(frozen=True)
class CPaceReply:
    token: bytes


@dataclass(frozen=True)
class ConfirmationReply:
    oquake_token: bytes
    enc_c: bytes
    client_confirm: bytes


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

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256, taking (salt, IKM) in draft order."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    if not 0 <= length <= 255 * HASH_LEN:
        raise ValueError("HKDF output length out of range")
    output, previous = b"", b""
    for counter in range(1, (length + HASH_LEN - 1) // HASH_LEN + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]),
                            hashlib.sha256).digest()
        output += previous
    return output[:length]


def xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def frame(*fields: bytes) -> bytes:
    """Unambiguous framing for observer transcripts and ideal inputs."""
    return b"".join(len(item).to_bytes(4, "big") + item for item in fields)


def build_public_context(client_id: str, server_id: str) -> bytes:
    """Public identities and experiment context shared by both endpoints."""
    return frame(client_id.encode(), server_id.encode(),
                 b"authentication-semantics experiment")


def bind_cpace_context(public_context: bytes, offer: bytes, reply: bytes) -> bytes:
    """Bind the OQUAKE stage to the preceding CPace exchange."""
    return frame(offer, reply) + public_context


def ciphertext_pad(sk: bytes) -> bytes:
    return hkdf_expand(sk, DST + b"OTP", NCT)


def mask_ciphertext(sk: bytes, ciphertext: bytes) -> bytes:
    """Wrap the registered-key ciphertext in the current PAKE session."""
    return xor(ciphertext, ciphertext_pad(sk))


def unmask_ciphertext(sk: bytes, enc_c: bytes) -> bytes:
    """Recover the ciphertext; this operation does not recover its secret k."""
    return xor(enc_c, ciphertext_pad(sk))


def verify_confirmation(expected: bytes, received: bytes, label: str) -> None:
    """Compare a confirmation in constant time, or raise authentication failure."""
    if not hmac.compare_digest(expected, received):
        raise AuthenticationError(label + " mismatch")


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


class IdealPAKE:
    """Ideal lower PAKE branch; same verifier/context is a precondition.

    begin/respond/finish model the CPace and OQUAKE interfaces without
    implementing their group operations, password masking, BUA-sKEM,
    intermediate confirmation, or concrete serialized messages.
    """

    def __init__(self) -> None:
        self.__offers: Dict[bytes, Tuple[bytes, bytes, bytes]] = {}
        self.__responses: Dict[bytes, Tuple[bytes, bytes]] = {}

    @staticmethod
    def _binding(stage: bytes, verifier: bytes, context: bytes,
                 secret_context: bytes) -> bytes:
        return hashlib.sha256(frame(stage, verifier, context,
                                    secret_context)).digest()

    def begin(self, stage: bytes, verifier: bytes, context: bytes,
              secret_context: bytes) -> Tuple[_InitiatorCapability, bytes]:
        token, capability = secrets.token_bytes(32), secrets.token_bytes(32)
        self.__offers[token] = (capability,
                               self._binding(stage, verifier, context,
                                             secret_context), stage)
        return _InitiatorCapability(token, capability), token

    def respond(self, stage: bytes, verifier: bytes, context: bytes,
                secret_context: bytes, offer: bytes) -> Tuple[bytes, bytes]:
        record = self.__offers.get(offer)
        binding = self._binding(stage, verifier, context, secret_context)
        if record is None or not hmac.compare_digest(record[1], binding):
            raise AuthenticationError("ideal lower PAKE binding mismatch")
        response, shared = secrets.token_bytes(32), secrets.token_bytes(32)
        self.__responses[response] = (offer, shared)
        return response, shared

    def finish(self, capability: _InitiatorCapability, response: bytes) -> bytes:
        offer = self.__offers.get(capability.token)
        record = self.__responses.get(response)
        if (offer is None or record is None or record[0] != capability.token
                or not hmac.compare_digest(offer[0],
                                           capability.private_capability)):
            raise AuthenticationError("ideal lower PAKE response mismatch")
        return record[1]


class IdealKEM:
    """Opaque ciphertext registry; c does not encode k or pk.

    derive_key_pair requires the hidden seed, encapsulate requires the
    registered public-key capability, and decapsulate requires its private
    counterpart. Decapsulation rejects unknown/wrong-owner ciphertexts.
    Concrete KEM implicit-rejection behavior is outside this abstraction.
    No registry-reading method is exposed to the interleaver.
    """

    def __init__(self) -> None:
        self.__seeds: Dict[bytes, Tuple[_PublicKey, _PrivateKey]] = {}
        self.__pairs: Dict[bytes, bytes] = {}
        self.__ciphertexts: Dict[bytes, Tuple[bytes, bytes]] = {}

    def derive_key_pair(self, seed: bytes) -> Tuple[_PublicKey, _PrivateKey]:
        if seed not in self.__seeds:
            public = _PublicKey(secrets.token_bytes(32))
            private = _PrivateKey(secrets.token_bytes(32))
            self.__seeds[seed] = (public, private)
            self.__pairs[public.capability] = private.capability
        return self.__seeds[seed]

    def encapsulate(self, public: _PublicKey) -> Tuple[bytes, bytes]:
        if not isinstance(public, _PublicKey):
            raise AuthenticationError("registered public-key capability absent")
        private = self.__pairs.get(public.capability)
        if private is None:
            raise AuthenticationError("unknown public-key capability")
        ciphertext, shared = secrets.token_bytes(NCT), secrets.token_bytes(32)
        self.__ciphertexts[ciphertext] = (private, shared)
        return ciphertext, shared

    def decapsulate(self, private: _PrivateKey, ciphertext: bytes) -> bytes:
        record = self.__ciphertexts.get(ciphertext)
        if (not isinstance(private, _PrivateKey) or record is None
                or not hmac.compare_digest(record[0], private.capability)):
            raise AuthenticationError("ideal KEM decapsulation failed")
        return record[1]


def register(kem: IdealKEM, password: bytes, salt: bytes,
             client_id: str, server_id: str
             ) -> Tuple[ClientCredentials, ServerCredentials]:
    """Illustrative KSF, preserving the verifier/seed split of Section 9.1.

    The caller retains password only for fixture construction. The server
    credential record contains verifier and pk, never seed/password/sk.
    This low iteration count is for simulation, not production password use.
    """
    material = hashlib.pbkdf2_hmac(
        "sha256", frame(DST, password, client_id.encode(), server_id.encode()),
        salt, 1000, dklen=64)
    verifier, seed = material[:32], material[32:]
    public, _ = kem.derive_key_pair(seed)
    return (ClientCredentials(verifier, seed),
            ServerCredentials(verifier, public))


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
    def __init__(self, session: str, mode: str, lower: IdealPAKE,
                 kem: IdealKEM, observer: Observer, trace: Trace,
                 client_id: str = "alice", server_id: str = "server.example"):
        if mode not in MODES:
            raise ValueError("unknown confirmation mode")
        self.session, self.mode = session, mode
        self._lower, self._kem = lower, kem
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

    def _check(self, value: object, message_type: type,
               field_names: Tuple[str, ...]) -> None:
        if not isinstance(value, message_type):
            self._reject("unexpected message type")
        for name in field_names:
            item = getattr(value, name)
            if not isinstance(item, bytes) or len(item) != 32:
                self._reject("invalid message length/type: " + name)

    def _witness(self, role: str) -> Witness:
        assert self._sk is not None and self.key is not None
        return Witness(self.session, role, self._identities, self.mode,
                       self._context, hashlib.sha256(frame(*self._wire)).digest(),
                       hashlib.sha256(DST + b"observer-SK" + self._sk).digest(),
                       hashlib.sha256(DST + b"observer-key" + self.key).digest())


@dataclass
class Fixture:
    """Fresh registration, ideal services, and observer for one test."""

    mode: str
    trace: Trace
    lower: IdealPAKE = field(default_factory=IdealPAKE)
    kem: IdealKEM = field(default_factory=IdealKEM)
    observer: Observer = field(default_factory=Observer)

    def __post_init__(self) -> None:
        self.client_credentials, self.server_credentials = register(
            self.kem, secrets.token_bytes(32), secrets.token_bytes(32),
            "alice", "server.example")
        self.public_context = build_public_context("alice", "server.example")

    def client(self, label: str = "C1", mode: Optional[str] = None) -> Client:
        return Client(self.client_credentials, session=label,
                      mode=mode or self.mode, lower=self.lower, kem=self.kem,
                      observer=self.observer, trace=self.trace)

    def server(self, label: str = "S1", mode: Optional[str] = None) -> Server:
        return Server(self.server_credentials, session=label,
                      mode=mode or self.mode, lower=self.lower, kem=self.kem,
                      observer=self.observer, trace=self.trace)

    def attacker(self) -> AdversaryInterleaver:
        return AdversaryInterleaver(self.server_credentials.verifier,
                                   self.lower, self.trace)


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
        self._cp_cap: Optional[_InitiatorCapability] = None
        self._oq_cap: Optional[_InitiatorCapability] = None

    def initiate(self) -> Offer:
        self._expect(State.INIT)
        self._cp_cap, token = self._lower.begin(
            b"CPace", self._credentials.verifier, self._base_context, b"")
        self._wire.append(token)
        self._move(State.MSG1, "send CPace initiation")
        return Offer(token)

    def receive_cpace(self, reply: CPaceReply) -> Offer:
        self._expect(State.MSG1)
        self._check(reply, CPaceReply, ("token",))
        try:
            assert self._cp_cap is not None
            key1 = self._lower.finish(self._cp_cap, reply.token)
        except AuthenticationError:
            self._reject("CPace response rejected")
        self._wire.append(reply.token)
        self._context = bind_cpace_context(
            self._base_context, self._wire[0], reply.token)
        self._move(State.MSG2, "complete ideal CPace shared-secret branch")
        self._oq_cap, token = self._lower.begin(
            b"OQUAKE", self._credentials.verifier, self._context, key1)
        self._wire.append(token)
        self._move(State.OQUAKE_INIT, "send OQUAKE initiation")
        return Offer(token)

    def finish(self, reply: ConfirmationReply) -> bytes:
        self._expect(State.OQUAKE_INIT)
        self._check(reply, ConfirmationReply,
                    ("oquake_token", "enc_c", "client_confirm"))
        self._move(State.CONFIRMATION, "process OQUAKE+ response")
        try:
            assert self._oq_cap is not None
            sk = self._lower.finish(self._oq_cap, reply.oquake_token)
            ciphertext = unmask_ciphertext(sk, reply.enc_c)
            _, private = self._kem.derive_key_pair(self._credentials.seed)
            k = self._kem.decapsulate(private, ciphertext)
            expected = derive_client_confirmation(
                self.mode, sk, self._context, reply.enc_c, k)
            verify_confirmation(expected, reply.client_confirm, "client_confirm")
            server_confirm, key = derive_server_confirmation_and_key(
                sk, self._context, reply.enc_c, k)
        except AuthenticationError as error:
            self._reject(str(error))
        self._sk, self.key = sk, key
        self._wire.extend((reply.oquake_token, reply.enc_c,
                           reply.client_confirm))
        self._move(State.ACCEPT, "client_confirm verified; output final key")
        self._observer.record(self._witness("client"))
        self._trace.log(self.session + ": send server_confirm")
        return server_confirm


class Server(Endpoint):
    def __init__(self, credentials: ServerCredentials, **kwargs):
        super().__init__(**kwargs)
        self._credentials = credentials
        self._key1: Optional[bytes] = None
        self._server_confirm: Optional[bytes] = None

    def respond_cpace(self, offer: Offer) -> CPaceReply:
        self._expect(State.INIT)
        self._check(offer, Offer, ("token",))
        try:
            token, self._key1 = self._lower.respond(
                b"CPace", self._credentials.verifier, self._base_context,
                b"", offer.token)
        except AuthenticationError:
            self._reject("CPace credential/context mismatch")
        self._wire.extend((offer.token, token))
        self._context = bind_cpace_context(
            self._base_context, offer.token, token)
        self._move(State.MSG2, "send CPace response")
        return CPaceReply(token)

    def respond_oquake(self, offer: Offer) -> ConfirmationReply:
        self._expect(State.MSG2)
        self._check(offer, Offer, ("token",))
        assert self._key1 is not None
        try:
            token, sk = self._lower.respond(
                b"OQUAKE", self._credentials.verifier, self._context,
                self._key1, offer.token)
            ciphertext, k = self._kem.encapsulate(
                self._credentials.registered_public_key)
        except AuthenticationError:
            self._reject("OQUAKE or registered-key operation failed")
        enc_c = mask_ciphertext(sk, ciphertext)
        client_confirm = derive_client_confirmation(
            self.mode, sk, self._context, enc_c, k)
        self._server_confirm, self.key = derive_server_confirmation_and_key(
            sk, self._context, enc_c, k)
        self._sk = sk
        self._wire.extend((offer.token, token, enc_c, client_confirm))
        self._move(State.CONFIRMATION, "send confirmation challenge; await reply")
        # A live matching server witness exists before the final message.
        self._observer.record(self._witness("server"))
        return ConfirmationReply(token, enc_c, client_confirm)

    def verify(self, server_confirm: bytes) -> bytes:
        self._expect(State.CONFIRMATION)
        if not isinstance(server_confirm, bytes) or len(server_confirm) != NKC:
            self._reject("invalid server_confirm length/type")
        assert self._server_confirm is not None
        try:
            verify_confirmation(self._server_confirm, server_confirm,
                                "server_confirm")
        except AuthenticationError as error:
            self._reject(str(error))
        self._move(State.ACCEPT, "server_confirm verified; output final key")
        assert self.key is not None
        return self.key


class AdversaryInterleaver:
    """Verifier-only actor; never reads endpoint or primitive internals."""

    def __init__(self, verifier: bytes, lower: IdealPAKE, trace: Trace):
        self.__verifier, self.__lower = verifier, lower
        self.__trace = trace
        self.knowledge = {"verifier"}
        self.__ciphertext: Optional[bytes] = None

    def obtain_challenge(self, server: Server, public_context: bytes) -> None:
        """Session 1: act as client, recover c_1, and leave S1 pending."""
        cpace_state, cpace_token = self.__lower.begin(
            b"CPace", self.__verifier, public_context, b"")
        msg1 = Offer(cpace_token)                 # A -> S1
        msg2 = server.respond_cpace(msg1)         # S1 -> A
        key1 = self.__lower.finish(cpace_state, msg2.token)
        context1 = bind_cpace_context(public_context, msg1.token, msg2.token)

        oquake_state, oquake_token = self.__lower.begin(
            b"OQUAKE", self.__verifier, context1, key1)
        msg3 = Offer(oquake_token)                # A -> S1
        msg4 = server.respond_oquake(msg3)        # S1 -> A
        sk1 = self.__lower.finish(oquake_state, msg4.oquake_token)
        self.__ciphertext = unmask_ciphertext(sk1, msg4.enc_c)
        self.knowledge.update(("CPace_secret_1", "SK_1", "r_1", "c_1"))
        self.__trace.log("A / Session 1: knows SK_1 and r_1; recovers opaque c_1")
        self.__trace.log("A / Session 1: no seed, pk_reg, k_1, or final key")

    def impersonate_server(self, client: Client, public_context: bytes) -> bytes:
        """Session 2: act as server and translate c_1 into a fresh PAKE context."""
        msg1 = client.initiate()                  # C2 -> A
        cpace_token, key1 = self.__lower.respond(
            b"CPace", self.__verifier, public_context, b"", msg1.token)
        msg2 = CPaceReply(cpace_token)            # A -> C2
        msg3 = client.receive_cpace(msg2)         # C2 -> A
        context2 = bind_cpace_context(public_context, msg1.token, msg2.token)
        oquake_token, sk2 = self.__lower.respond(
            b"OQUAKE", self.__verifier, context2, key1, msg3.token)
        self.knowledge.update(("CPace_secret_2", "SK_2", "r_2"))
        if self.__ciphertext is None:
            raise StateError("Session 1 challenge has not been obtained")
        ciphertext = self.__ciphertext
        # The attacker cannot decapsulate c_1. Try a fresh guessed secret;
        # Client.finish decides solely by its actual confirmation check.
        candidate_k = secrets.token_bytes(32)
        self.__trace.log(
            "A / Session 2: rewrap c_1 with r_2; recompute client_confirm")
        if client.mode == MODE_HARDENED:
            self.__trace.log("A / Session 2: k_1 unavailable; use fresh guessed k")
        enc_c = mask_ciphertext(sk2, ciphertext)
        forged = derive_client_confirmation(
            client.mode, sk2, context2, enc_c, candidate_k)
        msg4 = ConfirmationReply(oquake_token, enc_c, forged)  # A -> C2
        msg5 = client.finish(msg4)                # C2 -> A, or authentication error
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
    print("Model: ideal PAKE/KEM; concrete HKDF and confirmation checks")
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
