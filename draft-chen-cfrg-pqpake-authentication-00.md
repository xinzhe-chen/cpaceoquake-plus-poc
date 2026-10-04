---
title: Authentication Semantics under Partial Credential Exposure in CPaceOQUAKE+
abbrev: PQ-PAKE Authentication
docname: draft-chen-cfrg-pqpake-authentication-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
workgroup: Network Working Group
date: 2026-10-05
stand_alone: true
keyword:
  - PAKE
  - post-quantum cryptography
  - authentication
  - partial credential exposure
author:
  - ins: X. Chen
    name: Xinzhe Chen
    org: National University of Singapore
    abbrev: NUS
    country: Singapore
    email: asleep@u.nus.edu
normative:
  RFC2119:
  RFC8174:
  PQPAKE:
    title: Hybrid Post-Quantum Password Authenticated Key Exchange
    target: https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-02.html
    author:
      - ins: J. Vos
        name: Jelle Vos
      - ins: S. Jarecki
        name: Stanislaw Jarecki
      - ins: C. A. Wood
        name: Christopher A. Wood
    date: 2026-07-06
    seriesinfo:
      Internet-Draft: draft-vos-cfrg-pqpake-02
informative:
  RFC3552:
  RFC5746:
  RFC5869:
  RFC7457:
  RFC7627:
  RFC7991:
  CFRG-COMMENT:
    title: "[CFRG] Comment on draft-vos-cfrg-pqpake"
    target: https://mailarchive.ietf.org/arch/msg/cfrg/G_tFVXIi_mmuq2EXRZYJ1acL36w/
    author:
      - name: Jiawei Wu
        ins: J. Wu
    date: 2026-09-30
    ann: Message to the CFRG mailing list
--- abstract

This document analyzes client authentication in CPaceOQUAKE+ after
exposure of the password verifier field, while the registered KEM
public key and client secret material remain unavailable to the
adversary. A two-session execution allows a registered-key ciphertext
to be transferred between independently established sessions and its
outer confirmation to be recomputed. The client accepts without a
matching honest server session, although this execution does not
reveal its final session key. This document defines the affected
agreement property, describes the execution, and proposes binding the
registered-key KEM shared secret into the confirmation checked by the
client. The analysis applies to draft-vos-cfrg-pqpake-02; its companion
state-machine simulation is not a complete protocol security proof.

--- middle

# Introduction {#introduction}

Authenticated key exchange must protect the negotiated key and bind an
accepting endpoint to its intended peer's protocol execution. These
obligations are distinct: key secrecy alone does not establish a
matching peer conversation.

CPaceOQUAKE+ is a hybrid augmented password-authenticated key exchange
(aPAKE). Its classical CPace stage feeds a secret context into the
post-quantum OQUAKE+ stage. The latter adds password confirmation using
a registered KEM key. This design addresses password authentication
and session-key protection in a quantum threat model.

The server's registration record contains two password-derived values
with different roles: a verifier used by the PAKE stages and a KEM
public key used by password confirmation. The CFRG discussion in
{{CFRG-COMMENT}} identifies a client-authentication gap when only the
former is exposed and proposes including the registered-key KEM
shared secret in the client-checked confirmation. This document
specifies that observation and proposed repair.

The presentation follows the separation of attack conditions, impact,
algorithm changes, and interoperability used in {{RFC7457}},
{{RFC7627}}, and {{RFC5746}}. Those documents provide specification
precedents, not evidence that the underlying attacks are identical.

## Scope

This is an individual submission with intended status Informational,
for discussion on <mailto:cfrg@irtf.org>. It does not represent CFRG
consensus or amend the base specification by itself.

The baseline is revision 02 of {{PQPAKE}}, dated 6 July 2026. The
proposed change applies to OQUAKE+ and CPaceOQUAKE+, not symmetric
OQUAKE or CPaceOQUAKE. It establishes a concrete counterexample and
an argument against its confirmation translation. It does not
establish security of all concurrent executions or a deployed
implementation.

# Conventions and Background {#background}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in
all capitals, as shown here. Requirements apply to implementations
that select the proposed hardened profile.

During registration, the client derives disjoint values `v` and
`seed` from a stretched password-related string, salt, and identities.
Deterministic KEM key generation from `seed` produces
`(pk_reg, sk_reg)`. The server stores `v`, `pk_reg`, and the salt;
it MUST NOT store `seed` under the base specification. Credential
registration uses a secure channel. The client can rederive its
registered private key from the password-related inputs.

CPace runs on `v` and produces `key1`. OQUAKE runs on `v` with
`key1` as its secret context and produces `SK`. The password-confirmation
component encapsulates to `pk_reg`, obtaining ciphertext `c` and
shared secret `k`. It masks `c` under a pad derived from `SK` and
derives the final key using both `SK` and `k`.

| Symbol | Meaning |
|:-------|:--------|
| `C`, `S`, `A` | Honest client, honest server, adversary |
| `U`, `S_id` | Client and server identities |
| `v` | Verifier field, not the entire registration record |
| `pk_reg`, `sk_reg` | Registered password-confirmation KEM pair |
| `key1_i`, `SK_i` | CPace and OQUAKE outputs in execution `i` |
| `c_i`, `k_i` | Registered-key ciphertext and shared secret |
| `P_i` | Public-context bytes supplied to OQUAKE+ |
| `r_i`, `e_i` | Ciphertext pad and masked ciphertext `enc_c` |
| `cc_i`, `sc_i` | `client_confirm` and `server_confirm` |
| `K_i`, `T_i` | Final key and ordered handshake transcript |

`||` means concatenation; `XOR` requires equal-length byte strings.
`Extract`, `Expand`, `DST`, `Nct`, `Nkc`, and `Nkey` retain their
base-configuration meanings. `P_i` includes the composition's
cryptographic session context, not merely a socket identifier.
Identity and context encodings must be unambiguous.

The base field names denote their verifiers: `client_confirm` is sent
by the server and checked by the client; `server_confirm` is sent by
the client and checked by the server. These names are retained below.

# Threat Model and Authentication Goals {#threat-model}

## Verifier-Only Exposure {#partial-exposure}

Following {{RFC3552}}, the exposure premise is explicit. The adversary
learns exactly `v` for the target registration. It does not learn the
password-related string, `seed`, `sk_reg`, `pk_reg`, other registrations'
private data, honest ephemeral secrets, or registered-key KEM shared
secrets. Salt, identities, parameters, and public contexts may be known.

The adversary controls network delivery, suppression, replay, and
modification. It can start concurrent sessions and choose legitimate
ephemeral contributions. Holding `v` permits participation in the
underlying PAKE stages without granting access to honest private state.

Although `pk_reg` is a cryptographic public key, its unavailability is
an explicit field-exposure assumption. Any interface or directory
revealing it invalidates that premise. The analysis also conditions
on no successful password recovery: a leaked verifier can provide an
offline guessing test, whose cost depends on the password and KSF.
The execution below requires no password guess.

## Matching Conversations and Acceptance {#goals}

An honest server records `ServerRunning` after preparing its
password-confirmation response and candidate final key. An honest
client records `ClientAccept` after checking that response and
committing to its final key. A server accepts only after checking
the final client message.

The client-side agreement requirement is:

~~~
ClientAccept(U, S_id, profile, sid, T, K)
  ==> an earlier honest
      ServerRunning(S_id, U, profile, sid, T, K).
~~~

Matching requires agreement on identities, profile, cryptographic
session context, ordered messages through the server's confirmation
response, and candidate key. Send and receive directions are aligned;
local process labels need not coincide. Injective agreement additionally
requires distinct accepting executions to have distinct peer witnesses.

The server-side requirement analogously relates its acceptance to a
matching client execution that generated the final confirmation.
Explicit mutual authentication requires both directions under a stated
compromise model. It does not require simultaneous acceptance: the
last client message can still be in transit, and a network adversary
can always suppress it.

Key confidentiality is a separate goal. An acceptance lacking a peer
witness can violate agreement without revealing the accepted key.
The following trace demonstrates this distinction, not a general
confidentiality theorem for the baseline.

# Concurrent Confirmation Translation {#analysis}

## Baseline Computation {#baseline}

Sections 9.2.2 and 9.2.3 of {{PQPAKE}} use this confirmation schedule,
with shortened local names:

~~~
r  = Expand(SK, DST || "OTP", Nct)
e  = XOR(c, r)
I  = P || e
h1 = Extract(SK, DST || "h1" || I)
h2 = Extract(SK, DST || "h2" || I || k)
cc = Expand(h1, DST || "client_confirm", Nkc)
sc = Expand(h2, DST || "server_confirm", Nkc)
K  = Expand(h2, DST || "key", Nkey)
~~~

The server obtains `(c, k)` by encapsulation. The client unmasks `c`
and decapsulates using `sk_reg` before checking `cc`. Nevertheless,
`cc` itself does not depend on `k`; `sc` and `K` do.

## Preconditions and Message Schedule

Both sessions target the same registration and configuration, with
fresh independent PAKE state and different session contexts. No
nonce reuse, invalid group element, identity ambiguity, or collision
is required.

In Session 1, `A` acts as client toward honest server `S1`. In
Session 2, it acts as server toward honest client `C2`. After receiving
Session 1's registered-key ciphertext, `A` leaves S1 pending and
starts Session 2. The executions overlap while S1 awaits its final
confirmation. Session 1 need not complete.

The table uses the five-message composition numbering from Section
9.4 of {{PQPAKE}}. Composition message 4 is inner OQUAKE+ message 2.

| Step | Delivery or computation | Result |
|:-----|:------------------------|:-------|
| 1 | S1: `A -> S1: msg1_1`, CPace initiation | S1 creates fresh state |
| 2 | S1: `S1 -> A: msg2_1`, CPace response | A obtains `key1_1` |
| 3 | S1: `A -> S1: msg3_1`, OQUAKE initiation | S1 obtains `SK_1` |
| 4 | S1: `S1 -> A: msg4_1` | A obtains `SK_1`; S1 awaits msg5 |
| 5 | S2: `C2 -> A: msg1_2`, CPace initiation | C2 waits for response |
| 6 | S2: `A -> C2: msg2_2`, CPace response | Both obtain `key1_2` |
| 7 | S2: `C2 -> A: msg3_2`, OQUAKE initiation | A prepares response with `SK_2` |
| 8 | A unmasks `c_1` and remasks it under `r_2` | A constructs `e_2`, baseline `cc_2` |
| 9 | S2: `A -> C2: modified msg4_2` | C2 decapsulates and checks `cc_2` |
| 10 | S2: `C2 -> A: msg5_2 = sc_2` | C2 accepts `K_2` |
| 11 | A suppresses final confirmations | S1 stays pending without matching C2 |

~~~
Honest C2          A (both false roles)          Honest S1
                  -- msg1_1 ------------------>
                  <-- msg2_1 ------------------
                  -- msg3_1 ------------------>
                  <-- msg4_1 (e1, cc1) ---------
                  recover c1 = e1 XOR r1
-- msg1_2 ------->
<-- msg2_2 -------
-- msg3_2 ------->
                  form e2 = c1 XOR r2
                  recompute cc2 with SK2
<-- msg4_2 -------
decapsulate c1
check cc2; Accept
-- msg5_2 -------> (discard)
                                             waiting msg5_1
~~~

## Knowledge and State Derivation {#knowledge}

1. Knowing `v` and its own ephemeral state, A completes Session 1's
   underlying PAKE exchanges and obtains `key1_1` and `SK_1`. S1
   encapsulates to `pk_reg`, obtaining `(c_1, k_1)`.
2. From S1's response A computes
   `r_1 = Expand(SK_1, DST || "OTP", Nct)` and
   `c_1 = XOR(e_1, r_1)`. This recovers a valid ciphertext, not `k_1`.
3. A completes independent PAKE exchanges as Session 2's responder
   and obtains `SK_2`. It creates a valid OQUAKE response 2 and computes:

~~~
r_2  = Expand(SK_2, DST || "OTP", Nct)
e_2  = XOR(c_1, r_2)
h1_2 = Extract(SK_2, DST || "h1" || P_2 || e_2)
cc_2 = Expand(h1_2, DST || "client_confirm", Nkc)
~~~

All these inputs are available to A. It recomputes `cc_2`, rather
than replaying `cc_1` unchanged.

C2 then obtains `SK_2`, recovers `c_1`, and decapsulates it to `k_1`.
Its baseline `cc_2` calculation equals A's value, so the check
succeeds. C2 derives `sc_2` and `K_2` using `k_1`, sends its final
message, and accepts.

| Point | Added adversary knowledge | Still unavailable |
|:------|:--------------------------|:------------------|
| Initial | `v`, public inputs | password, `seed`, `pk_reg`, `sk_reg` |
| Session 1 PAKE | `key1_1`, `SK_1` | `k_1`, `K_1` |
| Response 1 | `r_1`, `e_1`, `c_1`, `cc_1` | `k_1`, `K_1` |
| Session 2 PAKE | `key1_2`, `SK_2`, `r_2` | `k_1`, `K_2` |
| Translation and acceptance | `e_2`, `cc_2`, observed `sc_2` | `k_1`, `K_2` |

The final row assumes the selected KEM and KDF prevent feasible secret
recovery from ciphertexts and confirmation outputs.

## Agreement Failure {#consequence}

S1 records context `P_1`, transcript `T_1`, and candidate key `K_1`.
C2 accepts `P_2`, `T_2`, and `K_2`. Their conversations differ, and
their keys differ except with negligible KDF collision probability.
S1 therefore cannot witness C2's required `ServerRunning` event.
No other honest server runs in this execution.

There is consequently no matching honest server conversation for
C2, although its ciphertext originated at an honest server. That
ciphertext's origin does not authenticate the enclosing session.
Forwarding `sc_2` to S1 fails S1's different confirmation check.
The trace supplies no method for A to recover C2's key or decrypt
its protected application traffic; application impact depends on
actions authorized by handshake acceptance alone.

# Proposed Specification Change {#patch}

## Confirmation Binding {#algorithm-change}

Replace this line in BOTH `OQUAKE+.Respond` (Section 9.2.2) and
`OQUAKE+.Finish` (Section 9.2.3) of {{PQPAKE}}:

~~~ diff
- prk_k_h1 = KDF.Extract(SK, DST || "h1" || confirm_input)
+ prk_k_h1 = KDF.Extract(SK, DST || "h1" || confirm_input || k)
~~~

`confirm_input` remains `public_context || enc_c`. In `Respond`,
`k` is returned by the current execution's `KEM.Encaps(pk)`; in
`Finish`, it is returned by decapsulation of the recovered ciphertext
with the rederived registered private key. It MUST NOT be replaced
by `key1`, `SK`, the ciphertext, or another execution's secret.

The resulting schedule is:

~~~
h1 = Extract(SK, DST || "h1" || P || enc_c || k)
h2 = Extract(SK, DST || "h2" || P || enc_c || k)
cc = Expand(h1, DST || "client_confirm", Nkc)
sc = Expand(h2, DST || "server_confirm", Nkc)
K  = Expand(h2, DST || "key", Nkey)
~~~

The labels retain domain separation. `h2`, `server_confirm`, final-key
derivation, and `OQUAKE+.Verify` are otherwise unchanged. Fixed
ciphertext and secret lengths make the appended `k` unambiguous;
public-context encoding remains a separate requirement.

## Endpoint Requirements

* The responder MUST use its current encapsulation's `k` when
  constructing `client_confirm`.
* The initiator MUST decapsulate and verify `client_confirm` before
  reporting authenticated completion or exposing the final key.
* A confirmation mismatch or reported decapsulation error MUST
  terminate the execution with an authentication failure. With
  implicit KEM rejection, the confirmation check remains mandatory.
* Implementations MUST compare confirmations in constant time,
  consume confirmation state at most once, and avoid reusing failed
  state. They SHOULD report a uniform external authentication failure.
* A verifier-only exposure claim MUST identify `v` as the leaked
  field and state that `pk_reg` and client secret material remain
  unavailable. It MUST NOT be presented as protection after compromise
  of the complete server record.

## Effect on the Interleaving {#patch-argument}

A can still recover `c_1` and construct `e_2`, but the hardened
`cc_2` requires `k_1`. Under the assumed KEM and KDF properties,
A cannot compute it. Reusing `cc_1` fails because the PAKE key and
confirmation input belong to a different session. For an independently
guessed `Nkc`-byte confirmation in the ideal random-output model,
success probability is `2^(-8*Nkc)` per attempt.

The change therefore blocks the specified confirmation translation
and binds the client check to the registered-key secret within its
PAKE context. A transparent relay of one complete honest execution
can still succeed, with a matching server witness. General concurrent
or injective agreement requires further analysis of KEM/KDF oracle
access, collisions, password guesses, and the complete composition;
the local argument and harness do not provide that proof.

# Deployment and Compatibility {#deployment}

Both endpoints MUST select the same confirmation profile before the
handshake. The formulas have identical field sizes but different
confirmation values and are not interoperable. Selection can use
coordinated configuration or an explicitly versioned enclosing
protocol. Negotiated selection MUST be authenticated through the
public context or the enclosing protocol. A deployment requiring the
hardened profile MUST NOT fall back to the baseline after failure.

This document defines no discovery message or wire code point. The
harness mode constants are local experiment controls. An interoperable
negotiation extension would need its own encoding and downgrade policy.

The minimal patch adds no message, round trip, KEM operation, or field.
The composed handshake remains five messages. It adds `len(k)` bytes
to each existing `h1` extraction input; the hash-work increase depends
on the KDF and input length. No performance measurement is claimed.

The client already decapsulates before the check, and the server
already knows `k`. Existing registration records need no change.
The responder can continue storing the expected final confirmation
and candidate key without extending raw `k`'s lifetime. Confirmation
test vectors need regeneration. For identical contexts and successful
inputs, `h2`, `server_confirm`, and final-key values remain unchanged;
adding a profile identifier to the context changes those values too.

# Security Considerations {#security}

## Exposure Boundary

Knowing both `v` and `pk_reg`, A can run the PAKE stages and call
`Encaps(pk_reg)` to obtain its own `(c, k)`. It can then compute the
hardened confirmation and key while impersonating the server. Thus
the proposed binding offers no protection in that expanded model.
Deployers SHOULD assess whether registration, storage, logs, backups,
or other interfaces make the field-exposure premise meaningful.
Successful password recovery or exposure of `seed` or `sk_reg` also
changes the premise.

## Forward Secrecy and Quantum Resistance

The patch retains the ephemeral stages and final-key dependency graph,
but introduces an additional confirmation output depending on `k`.
A forward-secrecy proof must account for that output and the intended
later-compromise cases. Recovery of a recorded registered-key secret
does not by itself determine whether the ephemeral stages still
protect the final key. An unchanged key formula alone is insufficient
to establish forward secrecy.

The change introduces no additional classical public-key operation.
Quantum resistance still depends on the selected KEM, specialized
OQUAKE primitive properties, KDF parameters, and hybrid composition.
The added confirmation output must be included in that analysis.
Neither a classical hash simulation nor this local trace establishes
post-quantum security.

Implementations SHOULD erase ephemeral secrets, `k`, and intermediate
state when no longer needed and MUST avoid logging secret material.
The Python artifact supplies neither secure erasure nor production
cryptography.

## State and Application Behavior

Fresh randomness, unambiguous identity binding, message-length checks,
and one-use confirmation state remain necessary. Regression testing
SHOULD include malformed messages, out-of-order delivery, confirmation
tampering, completed-session replay, and incompatible profiles.

A network adversary can still consume server resources and suppress
completion. Pending-session quotas, rate limits, and timeouts SHOULD
avoid exposing account existence or the failed internal check.
Applications SHOULD specify the agreement property attached to
handshake acceptance; evidence of subsequent peer activity requires
protected application communication. The reported consequence is an
authentication-correspondence failure, not demonstrated traffic
recovery or a device implementation exploit.

# IANA Considerations

This document has no IANA actions.

# Acknowledgments

Jiawei Wu described the verifier-only execution and proposed binding
`k` into the client-checked confirmation in {{CFRG-COMMENT}}. The
protocol is due to the authors of {{PQPAKE}}. These acknowledgments
do not imply their review or endorsement of this document.

--- back

# Reproducible State-Machine Comparison {#harness}

The companion `protocol_harness.py` uses Python 3.9 or later and only
standard-library modules. `Client`, `Server`, and
`AdversaryInterleaver` implement the endpoint transitions and schedule.
HKDF-SHA-256 {{RFC5869}}, ciphertext masking, and constant-time
confirmation comparison are concrete; `MODE_HARDENED` changes only
the `h1` secret input.

CPace and OQUAKE are represented by ideal verifier-gated shared-secret
capabilities. An ideal KEM associates opaque ciphertext tokens with
registered-key capabilities; ciphertext bytes disclose neither the
public key nor shared secret. The trusted service and observer are
outside the adversary. This abstraction does not implement CPace,
ML-BUA-sKEM, ML-KEM, or X-Wing, or model arbitrary Python memory access.

| Scenario | Required assertion |
|:---------|:-------------------|
| Baseline honest | Both accept; keys agree; matching server witness exists |
| Baseline interleaving | Client accepts; honest server stays pending without a matching witness |
| Hardened honest | Both accept; keys agree; matching server witness exists |
| Hardened interleaving | Client raises authentication failure and exposes no accepted key |

The observer compares honest events, identities, profile, context,
transcript, and key. A witness must precede client acceptance; server
acceptance need not precede it. The script runs the four scenarios
above with fresh independent session state.

Run:

~~~ shell
python3 protocol_harness.py
python3 protocol_harness.py --quiet --repeat 100
~~~

The script reports state transitions and PASS/FAIL, returns nonzero
on failed assertions, and omits secrets from logs. Fresh randomness
changes private values, while semantic outcomes are reproducible.
Repeated runs are regression checks, not exhaustive schedule
exploration or a formal security proof.

The Markdown source is converted to RFCXML version 3 {{RFC7991}} and
submission text. The repository README provides the build command
and links to the generated reading editions.
