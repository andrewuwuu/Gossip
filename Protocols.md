## Gossip Protocol Specification

**Status:** Production Specification

**Version:** 1.0.0

**Date:** 2026-01-25

This document defines the authoritative wire protocol for the Gossip P2P mesh. The protocol is designed to remain secure under active network attackers, malicious peers, packet loss, and implementation diversity.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as defined in RFC 2119.

---

### 0. Threat Model (Non-Negotiable)

The protocol assumes:

* Attackers can intercept, replay, delay, drop, and reorder packets.
* Malicious peers can generate arbitrary keys and identities.
* UDP discovery traffic is fully hostile.
* TCP connections can be raced, reflected, or simultaneously opened.

**Security Goals:**

* Forward Secrecy
* Peer Authentication
* Replay Resistance
* Identity Binding
* Implementation Determinism

---

### 1. Identity Model

#### 1.1 Static Identity Key

Each node possesses a long-term Ed25519 keypair:

* `IK_pub` — 32 bytes
* `IK_priv` — 64 bytes

The static private key **MUST** never be transmitted.

#### 1.2 NodeID

A NodeID is a 32-byte identifier derived from the public key, or the public key itself (implementation dependent). Truncation of NodeID is **NOT PERMITTED**.

#### 1.3 Trust Model (TOFU)

* UDP discovery is never trusted.
* TCP sessions establish trust via authenticated handshake.
* A peer identity is pinned as: `PinnedIdentity := (NodeID, IK_pub)`.
* Pinning occurs only after successful handshake completion. If a pinned NodeID is later observed with a different `IK_pub`, the connection **MUST** be rejected.

---

### 2. Cryptographic Primitives

| Purpose | Algorithm |
| --- | --- |
| Key Exchange | X25519 |
| Signatures | Ed25519 |
| Encryption | XChaCha20-Poly1305 |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 |

---

### 3. Framing

#### 3.1 Byte Order

All multi-byte integers use big-endian encoding.

#### 3.2 Frame Header (8 bytes)

All TCP frames use the following header, authenticated as AEAD AAD:
`[ Magic (2) | Version (1) | Type (1) | Length (4) ]`

* **Magic:** `0x47 0x52` ("GR")
* **Version:** `0x01`
* **Length:** payload size in bytes (Max: 65,535 bytes).

---

### 4. Handshake Protocol

The handshake provides mutual authentication and forward secrecy.

#### 4.1 Ephemeral Key Generation

Each side generates an ephemeral X25519 keypair: `(E_priv, E_pub)`. Ephemeral private keys **MUST** be wiped after handshake completion or failure.

#### 4.2 HELLO Message (Plaintext)

`HELLO := [ Magic | Version | Role | E_pub ]`

* **Role:** `0x01` = Initiator, `0x02` = Responder.
* **Simultaneous Open:** If both peers initiate, the peer with the lexicographically smaller `E_pub` is the **Initiator**.

#### 4.3 Handshake Transcript

The handshake transcript is computed as:
`Transcript = SHA-256(HELLO_init || HELLO_resp)`

This hash **MUST** be bound into key derivation and authentication.

#### 4.4 Key Derivation

Keys are derived using HKDF-SHA256:

* `IKM = X25519(E_priv, E_pub_peer)`
* `Salt = Transcript`
* `PRK = HKDF-Extract(Salt, IKM)`

Session keys are expanded from PRK:

* `K_init = HKDF-Expand(PRK, "gossip-init", 32)`
* `K_resp = HKDF-Expand(PRK, "gossip-resp", 32)`

#### 4.5 AUTH Message (Encrypted)

`AUTH := [ IK_pub (32) | Signature (64) ]`

**Signature input:**
`Sign(IK_priv, "gossip-auth" || Role || E_pub || Transcript)`

Where `Role` is the sender's role (1 byte) and `E_pub` is the sender's ephemeral public key.
Handshake completes only after both AUTH messages verify successfully.

---

### 5. Transport Encryption

#### 5.1 Nonce Construction

Nonces are 24 bytes (192-bit) for XChaCha20, implicit, and never transmitted.
`Nonce = [ Seq (8 bytes, BE) | Padding (16 zero bytes) ]`
Each direction maintains an independent sequence counter starting at zero.

#### 5.2 Replay & Ordering Rules

* Receivers **MUST** reject duplicate sequence numbers.
* **Strict in-order delivery is REQUIRED.** If `(ReceivedSeq != ExpectedSeq)`, the session **MUST** terminate.
* The session **MUST** terminate if the 8-byte counter wraps.

---

### 6. Message Types

| Type | Name | Encrypted | Payload |
| --- | --- | --- | --- |
| 0x01 | HELLO | No | Ephemeral Key |
| 0x02 | AUTH | Yes | Identity + Signature |
| 0x10 | MSG | Yes | MsgID (8) + Data |
| 0x20 | PING | Yes | Empty |
| 0xFF | ERR | Yes | Code (1) |

---

### 7. Message Deduplication

`MsgID` is scoped per `(Peer NodeID, SessionID)`. Implementations **MUST** maintain a bounded LRU cache.

---

### 8. UDP Discovery Beacon

UDP beacons are advisory only.
`Beacon := [ Magic (2) | Version (1) | IK_pub (32) | Timestamp (8) | Signature (64) | Port (2) ]`

**Signature input:** 
`Sign(IK_priv, Magic || Version || IK_pub || Timestamp)`

* Beacons older than ±60 seconds **MUST** be rejected.
* Implementations **SHOULD** track signatures within the 60s window to prevent replay floods.

---

### 9. Session Lifecycle

* **Handshake timeout:** 5 seconds.
* **Rekeying:** Out of scope for v1.0.
* All failures **MUST** wipe session keys and ephemeral secrets before closing.

---

### 10. Compliance Checklist

Implementations **MUST**:

1. Authenticate handshake transcripts using the local peer's role.
2. Enforce strict contiguous sequence numbering (TCP).
3. Enforce `NodeID` consistency (pinning).
4. Zero ephemeral secrets and shared secrets after KDF.
5. Reject replayed UDP beacons using a signature cache.
