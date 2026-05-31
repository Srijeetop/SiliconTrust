<div align="center">

```
███████╗██╗██╗     ██╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝██║██║     ██║██╔════╝██╔═══██╗████╗  ██║
███████╗██║██║     ██║██║     ██║   ██║██╔██╗ ██║
╚════██║██║██║     ██║██║     ██║   ██║██║╚██╗██║
███████║██║███████╗██║╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                           ████████╗██████╗ ██╗   ██╗███████╗████████╗
                           ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
                           ██║   ██████╔╝██║   ██║███████╗   ██║
                           ██║   ██╔══██╗██║   ██║╚════██║   ██║
                           ██║   ██║  ██║╚██████╔╝███████║   ██║
                           ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
```

**Hardware-Derived Environment-Bound Stateless Cryptographic System.**
**The machine *becomes* the trust.**

---

![Status](https://img.shields.io/badge/status-experimental-orange?style=flat-square)
![Architecture](https://img.shields.io/badge/architecture-stateless-blue?style=flat-square)
![Crypto](https://img.shields.io/badge/crypto-ephemeral-purple?style=flat-square)
![Hardware](https://img.shields.io/badge/trust-hardware--derived-green?style=flat-square)

![Argon2id](https://img.shields.io/badge/Argon2id-Memory--hard%20KDF-4A90D9?style=flat-square&logo=keycdn&logoColor=white)
![HKDF](https://img.shields.io/badge/HKDF-Key%20Expansion-7B61FF?style=flat-square&logo=letsencrypt&logoColor=white)
![BLAKE3](https://img.shields.io/badge/BLAKE3-Hashing-00B37E?style=flat-square&logo=hashnode&logoColor=white)
![SHA-3](https://img.shields.io/badge/SHA--3-Auxiliary%20%2F%20Fallback-F5A623?style=flat-square&logo=openssl&logoColor=white)

</div>

---

## The Problem with Every Other System

Every traditional security model asks the same question:

> **How do we protect the key?**

So they build vaults. Encrypted keystores. Password managers. HSMs. Recovery phrases written on fireproof paper and stored in a safe.

The key exists. It's somewhere. And somewhere is an attack surface.

Silicon Trust asks a different question entirely:

> **What if the machine itself becomes part of the key?**

---

## What is Silicon Trust?

Silicon Trust is a **hardware-assisted, stateless cryptographic architecture** that derives trust from the physical identity and runtime characteristics of a computing system.

There is no key file.
There is no password vault.
There is no recovery token.

Instead, cryptographic material is **reconstructed on demand** from the originating machine's hardware identity — and destroyed the moment the operation is complete.

The secret doesn't live anywhere.
**It's re-derived from what the machine *is*.**

---

## Architecture

Silicon Trust operates in five layers, from raw hardware signals to secure destruction.

---

### ◈ Layer 1 — Hardware Trust Collection

The originating machine is the source of truth.

```
┌─────────────────────────────────────────────────────────┐
│                  HARDWARE SIGNAL COLLECTION              │
├──────────────┬──────────────┬──────────────┬────────────┤
│  CPU Signals │  TPM Signals │  Platform ID │  Device    │
│              │              │              │  Topology  │
├──────────────┴──────────────┴──────────────┴────────────┤
│           Runtime Environment  ·  System Entropy        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Hardware Trust  │
                │      Pool       │
                └────────┬────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  CRYPTOGRAPHIC PIPELINE                  │
├─────────────────────┬───────────────────────────────────┤
│  Argon2id           │  Memory-hard KDF                  │
│  HKDF               │  Key expansion                    │
│  BLAKE3             │  Hashing                          │
│  SHA-3              │  Auxiliary / fallback             │
└─────────────────────┴───────────────────────────────────┘
```

Signals collected from:

| Signal Class | Examples |
|---|---|
| **CPU Characteristics** | Processor ID, microarchitecture features, cache topology |
| **Platform Identity** | Motherboard serial, firmware identity, UEFI measurements |
| **TPM Signals** | PCR values, endorsement key, attestation data |
| **Device Topology** | Bus layout, connected peripheral fingerprint |
| **Runtime Environment** | OS state, boot measurements, kernel parameters |
| **Hardware Entropy** | RDRAND, TPM RNG, hardware noise sources |

---

### ◈ Layer 2 — Trust Reconstruction

Raw signals are noisy, platform-variable, and non-cryptographic. This layer transforms them into usable cryptographic material.

```
   Hardware Trust Pool
           │
           ▼
    ┌─────────────┐
    │Normalization│   ← Stabilize variable signals across reboots
    └──────┬──────┘
           ▼
    ┌──────────────────┐
    │ Entropy Derivation│  ← Extract high-quality entropy
    └──────┬───────────┘
           ▼
    ┌──────────────────────────────────────────────────────────┐
    │  Trust Reconstruction  ←  Cryptographic derivation pipeline│
    ├──────────────────────────────────────────────────────────┤
    │                                                          │
    │  Argon2id  ·  Memory-hard KDF                            │
    │  HKDF      ·  Key expansion                              │
    │  BLAKE3    ·  Hashing                                    │
    │  SHA-3     ·  Auxiliary / fallback                       │
    │                                                          │
    └──────┬───────────────────────────────────────────────────┘
           ▼
   Derived Trust Material
```

**Cryptographic components:**

- `Argon2id` — Memory-hard KDF, resistant to brute-force and hardware attacks
- `HKDF` — HMAC-based key derivation for structured expansion
- `BLAKE3` — High-performance cryptographic hashing
- `SHA-3` — Standardized fallback and auxiliary hashing

---

### ◈ Layer 3 — Ephemeral Session Key

```
  Derived Trust Material
            │
            ▼
   ┌─────────────────────┐
   │  Ephemeral Session  │
   │        Key          │
   └─────────────────────┘

  ✓ Generated on demand
  ✓ Never written to disk
  ✓ Exists only for active operation duration
  ✓ Scoped to a single cryptographic operation
```

---

### ◈ Layer 4 — Cryptographic Operations

The ephemeral key performs the requested operation:

| Operation | Purpose |
|---|---|
| **Encryption** | Data confidentiality |
| **Decryption** | Data access on the originating machine |
| **Authentication** | Origin verification |
| **Integrity** | Tamper detection |

**Default cipher:** `XChaCha20-Poly1305`
- Authenticated encryption with associated data (AEAD)
- Extended 192-bit nonce (eliminates nonce-reuse risk)
- 256-bit security level
- Constant-time implementation

---

### ◈ Layer 5 — Secure Destruction

```
  Session Key
       │
       ▼
  ┌──────────────────┐
  │Memory Zeroization│
  └────────┬─────────┘
           │
           ▼
       Destroyed

  — No key file
  — No persistent secret
  — No long-lived credential storage
  — No automatic recovery; optional user‑managed recovery function available
```

---

## Operational Workflows

### Encryption

```
User Request
     │
     ▼
Collect Hardware Signals ──► CPU · TPM · Platform · Entropy
     │
     ▼
Normalize & Derive ──────────► Argon2id · HKDF · BLAKE3
     │
     ▼
Generate Session Key ─────────────────────────────────────┐
     │                                                     │
     ▼                                                     │
Encrypt Data                                    [key exists here only]
     │                                                     │
     ▼                                                     │
Destroy Session Key ◄────────────────────────────────────-┘
     │
     ▼
Ciphertext Output
```

### Decryption

```
User Request
     │
     ▼
Collect Hardware Signals ──► Same machine? Same signals.
     │
     ▼
Reconstruct Trust ───────────► Identical derivation path
     │
     ▼
Regenerate Session Key ───────────────────────────────────┐
     │                                                     │
     ▼                                                     │
Decrypt Data                                    [key exists here only]
     │                                                     │
     ▼                                                     │
Destroy Session Key ◄────────────────────────────────────-┘
     │
     ▼
Plaintext Output
```

### Emergency Recovery Function

To allow decryption on a different machine in case of hardware failure:
Before disaster - Manually retrieve the Hardware Fingerprint and feed it to the recovery function along with the passphrase.

```bash
stcs.exe recover encrypted.stcs -f my-machine.json -p "passphrase"
```

> **Key insight:** Decryption doesn't retrieve a stored key. It *re-derives* the same key from the same machine. If the machine changes, the key changes. The data becomes inaccessible — not because the key was protected, but because the key can no longer be reconstructed.

---

## Traditional Security vs. Silicon Trust

```
TRADITIONAL                        SILICON TRUST
──────────────────────────         ──────────────────────────────
Stored Key                         Hardware Identity
     │                                      │
     ▼                                      ▼
Protect Key ◄── ATTACK SURFACE     Trust Reconstruction
(vault, password, HSM, backup)              │
     │                                      ▼
     ▼                             Session Key (ephemeral)
Use Key                                     │
     │                                      ▼
     ▼                             Cryptographic Operation
Key persists                                │
(available for theft,                       ▼
 reuse, exfiltration)              Key Destruction
                                   (nothing persists)
```

---

## Key Properties

### 🔩 Hardware-Assisted Trust
The originating machine is a cryptographic participant, not just a host. Physical hardware characteristics contribute to trust generation. Virtualized or cloned environments cannot reproduce the same trust material.

### 🔄 Stateless Design
No key files. No encrypted keystores. No tokens. No backup codes. The system maintains zero persistent cryptographic state between operations.

### ⚡ Ephemeral Cryptography
Session keys exist only during active operations. There is no window between "key generated" and "key used" where a key can be stolen — those two events are the same event.

### 🔒 Reduced Trust Portability
Trust is bound to the originating hardware environment. Data encrypted on Machine A cannot be decrypted on Machine B. This is a feature, not a limitation.

### 📉 Minimal Persistent Attack Surface
An attacker cannot steal what doesn't exist. Long-lived credentials are the most common target in key compromise scenarios. Silicon Trust eliminates them from the threat model.

---

## Threat Model

| Threat | Traditional | Silicon Trust |
|---|---|---|
| Key file theft | ❌ Catastrophic | ✅ No key file exists |
| Password database breach | ❌ Catastrophic | ✅ Not applicable |
| Credential replay | ❌ Vulnerable | ✅ Keys are ephemeral |
| Cold boot attack | ⚠️ Partial mitigations | ✅ Keys exist only during operation |
| VM/snapshot exfiltration | ❌ Full key exposure | ✅ Hardware signals differ |
| Backup theft | ❌ Key included | ✅ Key cannot be backed up |
| Insider key exfiltration | ❌ Possible | ✅ Key doesn't persist to exfiltrate |

---

| Primitive | Role | Why |
|:---|:---|:---|
| `Argon2id` | Memory-hard KDF | Defeats GPU/ASIC brute-force on captured signals |
| `HKDF` | Key expansion | Structured derivation from high-entropy seed |
| `BLAKE3` | Hashing | High-speed, cryptographically sound, constant-time |
| `SHA-3` | Auxiliary / fallback | Standardized Keccak-based alternative |


---

## Design Philosophy

Most security systems are built around the assumption that secrets must be stored somewhere, and the job of security is to protect the storage.

Silicon Trust rejects the premise.

If the secret never exists in persistent form, the attacker has nothing to steal. If the key is re-derived from the machine itself, moving the data is meaningless without moving the hardware. If the session key is destroyed after use, even a successful memory extraction after the fact yields nothing.

This is not about stronger locks.
It's about a different model of what a secret is.

---

<div align="center">

**Silicon Trust**

*Trust Derived from Hardware. Reconstructed on Demand.*

---

> *"The machine doesn't store the trust.*
> *The machine becomes the trust."*

</div>
