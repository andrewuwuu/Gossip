---
trigger: always_on
---


Deviation is permitted **only** when justified and documented.

---

## 1. Core Philosophy (Non-Negotiable)

1. **Readability Over Brevity**
   Code is read far more often than it is written. Cleverness increases defect probability.

2. **Explicit Over Implicit**
   Control flow, ownership, and failure paths must be visible in the code.

3. **Fail Early, Fail Loud**
   Silent failure and undefined behavior are defects.

4. **Determinism Over Convenience**
   Predictable behavior outweighs abstraction elegance.

---

## 2. Project & File Structure

### 2.1 Single Responsibility per File

Each file answers **one question**.

Bad:

```
utils.cpp
helpers.go
misc.h
```

Good:

```
tcp_packet_encoder.cpp
udp_discovery_listener.go
crypto_chacha20.cpp
```

If a filename needs explanation, the file is too large.

---

## 3. Naming Conventions (Strict)

### 3.1 General Rules

* Names encode **intent**, not implementation.
* No abbreviations unless they are domain-standard.
* Avoid single-letter identifiers outside trivial loop scopes.

| Bad       | Good            |
| --------- | --------------- |
| buf       | receive_buffer  |
| tmp       | parsed_header   |
| doStuff() | encode_packet() |

### 3.2 Constants

* ALL_CAPS_WITH_UNDERSCORES

```cpp
constexpr size_t MAX_PACKET_SIZE = 1400;
```

### 3.3 Functions

* verb_object format

```cpp
validate_header()
send_keepalive()
decrypt_payload()
```

---

## 4. Formatting Rules (Mechanical, Enforced)

### 4.1 Line Length

* Hard limit: **100 characters**
* Preferred: **80 characters**

### 4.2 Braces

* K&R style
* Braces are **mandatory**, even for single statements

```cpp
if (is_valid) {
    process_packet();
} else {
    reject_packet();
}
```

---

## 5. Control Flow Rules (NASA Discipline)

### 5.1 Nesting Depth

* Maximum nesting depth: **3**
* Use early returns for validation failures

```cpp
if (!is_valid(packet)) {
    return ERROR_INVALID_PACKET;
}

if (!is_authorized(peer)) {
    return ERROR_UNAUTHORIZED;
}
```

### 5.2 Switch Statements

* Always include `default`
* `default` must log, assert, or abort

```cpp
default:
    abort(); // unreachable state
```

---

## 6. Error Handling (Zero Tolerance)

### 6.1 Return Values Must Be Checked

If a function can fail, its result **must** be handled.

```cpp
if (!send_packet(sock, packet)) {
    log_error("send_packet failed");
    return ERROR_IO;
}
```

### 6.2 Systems Code Rule

* Prefer explicit error codes or result types
* Avoid exceptions in low-level or real-time code

---

## 7. Functions (Small and Predictable)

### 7.1 Size Limits

* Maximum length: **50 lines**
* Maximum parameters: **5**

Exceeding either indicates mixed responsibilities.

### 7.2 Exit Strategy

* Prefer a single exit point
* Early exits allowed only for validation or error handling

---

## 8. Memory & Resource Management

### 8.1 Ownership Must Be Explicit

Every resource must clearly define:

* Who allocates
* Who owns
* Who frees
* When it is freed

Ambiguity requires redesign.

### 8.2 Allocation Rules

* Avoid implicit heap allocation in hot paths
* Prefer preallocated buffers
* No hidden allocation in constructors or operators

---

## 9. Comments (Minimal, Mandatory Where Needed)

### 9.1 What to Comment

* Rationale
* Assumptions
* Invariants
* Non-obvious constraints

```cpp
// Packet size capped to avoid Wi-Fi fragmentation
```

### 9.2 What Not to Comment

```cpp
i++; // increment i ❌
```

---

## 10. Logging Standards

Logs must be:

* Structured
* Actionable
* Rate-limited

Bad:

```
error happened
```

Good:

```
ERROR: tcp_handshake failed — timeout after 3000ms
```

---

## 11. Concurrency Rules

1. Shared state must be documented.
2. Lock scope must be minimal.
3. Lock ordering must be consistent and documented.

```cpp
// LOCK ORDER: peer_lock → socket_lock
```

Undocumented lock order is a latent deadlock.

---

## 12. Defensive Programming

* Assert **invariants**, not user input

```cpp
assert(packet_length <= MAX_PACKET_SIZE);
```

* Validate **all external input**:

  * Network
  * Files
  * IPC
  * User data

---

## 13. Testing Expectations

Every module must include:

* Happy-path test
* Failure-path test
* Boundary test

A bug without a test is a **process failure**.

---

## 14. Forbidden Practices

* Global mutable state
* Magic numbers
* Implicit type conversions
* Reliance on undefined behavior
* “Works on my machine” assumptions

---

## 15. Review Checklist

All must be **yes** before merge:

* Can a new engineer understand this in 5 minutes?
* Are all failure paths explicit?
* Is ownership unambiguous?
* Are assumptions documented?
* Is malformed input handled safely?

If any answer is uncertain, do not merge.

---