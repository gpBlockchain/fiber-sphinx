# Security Audit Report — fiber-sphinx

**Date**: 2026-02-28  
**Auditor**: AI Security Review Agent  
**Scope**: `src/lib.rs`, `src/tests.rs`, `Cargo.toml`, protocol specification (`docs/spec.md`)  
**Commit**: Current `develop` branch  
**Version**: 2.3.0

---

## Executive Summary

This report covers a manual security code review of the `fiber-sphinx` crate — a Rust implementation of the Sphinx mix network protocol for Fiber. The review focused on cryptographic correctness, timing side-channels, panic safety (denial of service), memory safety, and protocol conformance.

**Critical findings**: 2  
**High findings**: 2  
**Medium findings**: 3  
**Low/Informational findings**: 5

---

## Findings

### [CRITICAL-01] Non-constant-time HMAC Comparison in `OnionPacket::peel` (Timing Side-Channel)

**File**: `src/lib.rs`, line 255–257  
**Severity**: Critical  
**Category**: Timing Side-Channel Attack

```rust
// TODO: constant time comparison
if expected_hmac != self.hmac {
    return Err(SphinxError::HmacMismatch);
}
```

**Description**: The `!=` operator on `[u8; 32]` arrays performs a byte-by-byte comparison that short-circuits on the first mismatch. This is a classic timing oracle vulnerability. An attacker relaying packets through a node could measure response times to progressively guess the correct HMAC byte-by-byte.

**Impact**: An attacker who can measure the timing of HMAC verification could forge HMAC values with O(32×256) = O(8192) queries instead of brute-forcing 2^256 possibilities. In a mix network context, this would allow an adversary to forge packets that bypass integrity checks.

**Recommendation**: Use `subtle::ConstantTimeEq` (the `subtle` crate is already a transitive dependency via `hmac`) or the `hmac` crate's built-in `verify_slice` / `verify_truncated` methods which use constant-time comparison internally.

```rust
use subtle::ConstantTimeEq;
if expected_hmac.ct_eq(&self.hmac).unwrap_u8() != 1 {
    return Err(SphinxError::HmacMismatch);
}
```

**Note**: The code already has a `// TODO: constant time comparison` comment acknowledging this issue.

---

### [CRITICAL-02] Non-constant-time HMAC Comparison in `OnionErrorPacket::parse` (Timing Side-Channel)

**File**: `src/lib.rs`, line 362  
**Severity**: Critical  
**Category**: Timing Side-Channel Attack

```rust
if hmac == packet.packet_data[..32] {
    return Some((error, index));
}
```

**Description**: Same timing oracle issue as CRITICAL-01, but in the error packet parsing path. The origin node compares HMAC values using `==` which is non-constant-time. While this is on the origin node side (not an intermediate hop), it still leaks information about the HMAC through timing.

**Impact**: An attacker who can observe the origin node's timing could determine which hop generated an error, breaking the anonymity properties of the Sphinx protocol.

**Recommendation**: Same as CRITICAL-01 — use `subtle::ConstantTimeEq`.

---

### [HIGH-01] Potential Panic (Slice Out-of-Bounds) in `OnionPacket::peel`

**File**: `src/lib.rs`, lines 266–274  
**Severity**: High  
**Category**: Denial of Service / Panic Safety

```rust
let data_len = get_hop_data_len(&packet_data).ok_or(SphinxError::HopDataLenUnavailable)?;
if data_len > packet_data_len {
    return Err(SphinxError::HopDataLenTooLarge);
}
let hop_data = packet_data[0..data_len].to_vec();
let mut hmac = [0; 32];
hmac.copy_from_slice(&packet_data[data_len..(data_len + 32)]);  // ← PANIC if data_len + 32 > packet_data_len
shift_slice_left(&mut packet_data[..], data_len + 32);          // ← PANIC via underflow in shift_slice_left
chacha.apply_keystream(&mut packet_data[(packet_data_len - data_len - 32)..]);  // ← PANIC via underflow
```

**Description**: The bounds check on line 266 only validates `data_len > packet_data_len`, but does NOT validate `data_len + 32 <= packet_data_len`. If `get_hop_data_len` returns a value in the range `(packet_data_len - 31)..=packet_data_len`, the subsequent slice operations will panic:

1. `packet_data[data_len..(data_len + 32)]` — out-of-bounds slice access
2. `shift_slice_left` — the internal computation `arr.len() - amt` will underflow
3. `packet_data_len - data_len - 32` — arithmetic underflow

**Impact**: A malicious or corrupted packet with a crafted `get_hop_data_len` return value can crash the node process. In a networked context, this is a remote denial-of-service vulnerability.

**Proof of Concept**: Any `get_hop_data_len` that returns a value where `packet_data_len - 31 <= data_len <= packet_data_len` will trigger the panic.

**Recommendation**: Change the bounds check from:
```rust
if data_len > packet_data_len {
```
to:
```rust
if data_len + 32 > packet_data_len {
```

---

### [HIGH-02] Guaranteed Panic in `OnionErrorPacket::split` for Short Packets

**File**: `src/lib.rs`, lines 372–382  
**Severity**: High  
**Category**: Denial of Service / Panic Safety

```rust
pub fn split(self) -> ([u8; 32], Vec<u8>) {
    let mut hmac = [0u8; 32];
    if self.packet_data.len() >= 32 {
        hmac.copy_from_slice(&self.packet_data[..32]);
        let payload = self.packet_data[32..].to_vec();
        (hmac, payload)
    } else {
        hmac.copy_from_slice(&self.packet_data[..]);  // ← PANIC: source length != 32
        (hmac, Vec::new())
    }
}
```

**Description**: In the `else` branch, when `self.packet_data.len() < 32`, the code attempts `hmac.copy_from_slice(&self.packet_data[..])`. The `copy_from_slice` method requires the source and destination slices to have identical lengths. Since `hmac` is 32 bytes and `self.packet_data` is less than 32 bytes, this will **always** panic.

**Impact**: Any `OnionErrorPacket` with fewer than 32 bytes of data will cause a panic when `split()` is called. Since `OnionErrorPacket::from_bytes` accepts arbitrary bytes with no validation, an attacker can trivially trigger this.

**Recommendation**: Replace `copy_from_slice` with a length-aware copy:
```rust
} else {
    hmac[..self.packet_data.len()].copy_from_slice(&self.packet_data[..]);
    (hmac, Vec::new())
}
```

---

### [MEDIUM-01] Static All-Zero ChaCha20 Nonce Reuse

**File**: `src/lib.rs`, line 98  
**Severity**: Medium  
**Category**: Cryptographic Design

```rust
const CHACHA_NONCE: [u8; 12] = [0u8; 12];
```

**Description**: All ChaCha20 operations use the all-zero nonce. This is by design in the Sphinx protocol — each encryption uses a unique key derived from the shared secret, so the (key, nonce) pair is always unique. However:

1. This deviates from general cryptographic best practice of unique nonces.
2. If the key derivation ever produces duplicate keys (e.g., due to a bug in shared secret computation), the nonce reuse would be catastrophic — it would allow XOR of two ciphertexts to recover plaintext.

**Impact**: No immediate vulnerability given correct key derivation, but increases the blast radius of any key derivation bug.

**Recommendation**: Document this design decision explicitly in comments. Consider using a key-derived nonce as a defense-in-depth measure.

---

### [MEDIUM-02] `forward_stream_cipher` Has O(n) Byte-by-Byte Processing

**File**: `src/lib.rs`, lines 567–572  
**Severity**: Medium  
**Category**: Denial of Service / Performance

```rust
fn forward_stream_cipher<S: StreamCipher>(stream: &mut S, n: usize) {
    for _ in 0..n {
        let mut dummy = [0; 1];
        stream.apply_keystream(&mut dummy);
    }
}
```

**Description**: This function advances the stream cipher position by processing one byte at a time. For large `n` values, this is extremely inefficient. The function is called with `packet_data_len - pos` which can be up to 1300 for the first hop. While 1300 iterations is manageable, the `packet_data_len` parameter comes from user input in `OnionPacket::create`, and there's no upper bound enforced.

**Impact**: If a very large `packet_data_len` is used (e.g., `usize::MAX`), this could cause an effective denial-of-service through CPU exhaustion.

**Recommendation**: Process in larger blocks:
```rust
fn forward_stream_cipher<S: StreamCipher>(stream: &mut S, n: usize) {
    let mut dummy = [0u8; 256];
    let mut remaining = n;
    while remaining > 0 {
        let chunk = remaining.min(256);
        stream.apply_keystream(&mut dummy[..chunk]);
        remaining -= chunk;
    }
}
```

---

### [MEDIUM-03] No Version Validation in Packet Processing

**File**: `src/lib.rs`, lines 198–215, 237–288  
**Severity**: Medium  
**Category**: Protocol Robustness

**Description**: `OnionPacket::from_bytes` and `peel` do not validate the `version` field. The current version is 0, but any value (0–255) is silently accepted and propagated. If a future version changes the packet format, old nodes would silently process incompatible packets with potentially incorrect results.

**Impact**: Forward compatibility risk. Could lead to silent data corruption if protocol versions diverge.

**Recommendation**: Add version validation in `from_bytes` and/or `peel`.

---

### [LOW-01] `expect()` Calls in Cryptographic Paths Can Panic

**File**: `src/lib.rs`, lines 600–601, 622–624  
**Severity**: Low  
**Category**: Panic Safety

```rust
ephemeral_secret_key
    .mul_tweak(&Scalar::from_be_bytes(blinding_factor).expect("valid scalar"))
    .expect("valid mul tweak")
```

**Description**: `Scalar::from_be_bytes` returns `Err` if the input is zero (or is the curve order). `mul_tweak` can fail if the result is the point at infinity. While the probability of SHA-256 producing exactly zero is ~2^-256, a library-grade implementation should handle this gracefully rather than panicking.

**Impact**: Astronomically unlikely panic, but violates the principle that library code should not panic.

**Recommendation**: Return `Result<_, SphinxError>` instead of using `expect()`.

---

### [LOW-02] Public Fields Allow Construction of Invalid OnionPacket

**File**: `src/lib.rs`, lines 101–111  
**Severity**: Low  
**Category**: API Design

**Description**: All fields of `OnionPacket` are `pub`, allowing external code to construct packets with arbitrary values that bypass the construction logic. This could lead to invalid packets being processed.

**Recommendation**: Consider making fields private with accessor methods, or add validation methods.

---

### [LOW-03] `OnionErrorPacket::from_bytes` Accepts Arbitrary Data

**File**: `src/lib.rs`, lines 389–391  
**Severity**: Low  
**Category**: Input Validation

```rust
pub fn from_bytes(bytes: Vec<u8>) -> Self {
    Self { packet_data: bytes }
}
```

**Description**: No validation is performed on the input bytes. While `parse()` has a minimum length check, `split()` and other methods may panic on short inputs (see HIGH-02).

**Recommendation**: Add a minimum length check or return `Result`.

---

### [LOW-04] Sensitive Cryptographic Material Not Zeroed After Use

**File**: `src/lib.rs`, throughout  
**Severity**: Low  
**Category**: Memory Safety

**Description**: Intermediate cryptographic values such as shared secrets, derived keys (`rho`, `mu`, `ammag`, `um`), and HMAC keys are stored in `[u8; 32]` arrays on the stack. These are not explicitly zeroed after use. While Rust's `SecretKey` type uses `Zeroize`, the derived values remain in memory until the stack frame is overwritten.

**Impact**: Memory scraping attacks (e.g., cold boot, core dumps, swap files) could recover sensitive key material.

**Recommendation**: Use the `zeroize` crate with `Zeroize` trait on sensitive intermediate values.

---

### [LOW-05] HMAC Key Derivation Uses Very Short Keys

**File**: `src/lib.rs`, lines 93–97  
**Severity**: Low / Informational  
**Category**: Cryptographic Design

```rust
const HMAC_KEY_RHO: &[u8] = b"rho";   // 3 bytes
const HMAC_KEY_MU: &[u8] = b"mu";     // 2 bytes
const HMAC_KEY_PAD: &[u8] = b"pad";   // 3 bytes
const HMAC_KEY_UM: &[u8] = b"um";     // 2 bytes
const HMAC_KEY_AMMAG: &[u8] = b"ammag"; // 5 bytes
```

**Description**: The HMAC keys used for key derivation are very short (2–5 bytes). While HMAC-SHA256 internally pads keys to the block size, this is by design from the BOLT#4 specification. The security relies on the shared secret input, not the key.

**Impact**: No direct vulnerability — this follows the BOLT#4 specification. Documented for completeness.

---

## Dependency Analysis

| Dependency | Version | Known Vulnerabilities |
|---|---|---|
| secp256k1 | 0.30.0 | None known |
| sha2 | 0.10.8 | None known |
| hmac | 0.12.1 | None known |
| chacha20 | 0.9.1 | None known |
| thiserror | 1.0 | None known |
| hex-conservative (dev) | 0.2.1 | None known |

Note: `secp256k1` was upgraded from 0.28.0 (documented in AGENTS.md) to 0.30.0 (actual Cargo.toml). The AGENTS.md documentation is outdated.

---

## TODO — Areas Requiring Further Review

- [ ] **TODO-1 (CRITICAL)**: Fix non-constant-time HMAC comparison in `peel()` (line 256). Use `subtle::ConstantTimeEq` or `hmac` crate's `verify_slice`.
- [ ] **TODO-2 (CRITICAL)**: Fix non-constant-time HMAC comparison in `OnionErrorPacket::parse()` (line 362).
- [ ] **TODO-3 (HIGH)**: Fix bounds check in `peel()` — change `data_len > packet_data_len` to `data_len + 32 > packet_data_len` (line 266).
- [ ] **TODO-4 (HIGH)**: Fix `OnionErrorPacket::split()` panic for packets shorter than 32 bytes (line 379).
- [ ] **TODO-5 (MEDIUM)**: Review `forward_stream_cipher` performance with large inputs; consider adding an upper bound on `packet_data_len` or optimizing the function.
- [ ] **TODO-6 (MEDIUM)**: Add version field validation in `from_bytes` and/or `peel`.
- [ ] **TODO-7 (LOW)**: Replace `expect()` calls in `derive_next_hop_ephemeral_secret_key` and `derive_next_hop_ephemeral_public_key` with proper error handling.
- [ ] **TODO-8 (LOW)**: Consider using the `zeroize` crate for sensitive intermediate cryptographic values.
- [ ] **TODO-9 (LOW)**: Add minimum length validation in `OnionErrorPacket::from_bytes`.
- [ ] **TODO-10**: Update AGENTS.md to reflect actual `secp256k1` version (0.30.0 vs documented 0.28.0).
- [ ] **TODO-11**: Add fuzz testing for `OnionPacket::from_bytes`, `OnionPacket::peel`, `OnionErrorPacket::split`, and `OnionErrorPacket::parse` to catch edge cases.
- [ ] **TODO-12**: Verify that the `Scalar::from_be_bytes` and `mul_tweak` operations cannot produce degenerate values under adversarial inputs (e.g., small-subgroup attacks, invalid curve points).
- [ ] **TODO-13**: Review whether the blinding factor derivation (SHA-256 of public key + shared secret) provides adequate domain separation to prevent cross-protocol attacks.
- [ ] **TODO-14**: Assess whether the `packet_data_len` parameter in `OnionPacket::create` should have an enforced maximum to prevent resource exhaustion.
- [ ] **TODO-15**: Consider adding replay protection documentation/guidance — the Sphinx protocol itself doesn't prevent replay, and the library should document this responsibility for callers.

---

## Conclusion

The fiber-sphinx implementation is generally well-structured and follows the Sphinx/BOLT#4 specification. However, there are **two critical timing side-channel vulnerabilities** in HMAC comparisons and **two high-severity panic bugs** that could lead to denial-of-service. These should be addressed before production deployment.

The timing side-channel issues (CRITICAL-01, CRITICAL-02) are particularly concerning in a mix network context where anonymity is the primary security goal — timing leaks could help an adversary correlate packets or forge integrity checks.

The panic bugs (HIGH-01, HIGH-02) can be triggered by malicious or malformed inputs and would crash the node process.
