# RIP-25: Post-Quantum Hybrid Signatures via ML-DSA-44

```
RIP: 25
Title: Post-Quantum Hybrid Signatures via ML-DSA-44
Authors: ALENOC (https://github.com/ALENOC)
Status: Draft
Type: Standards Track (Consensus)
Created: 2026-04-05
License: MIT
```

---

## Abstract

This RIP proposes adding **ML-DSA-44** (FIPS 204) as a hybrid post-quantum digital signature scheme to Ravencoin, paired with the existing ECDSA/secp256k1 signatures. Transactions from quantum-resistant addresses require **both** a valid ECDSA signature **and** a valid ML-DSA-44 signature, ensuring security as long as at least one of the two underlying cryptographic schemes remains unbroken.

The upgrade is deployed as a **soft fork** via a new **witness version 2** program, following the SegWit extensibility model. A phased block weight increase from 8 MWU to 16 MWU, combined with a PQ witness discount factor, ensures that network throughput remains adequate during and after migration.

---

## Motivation

### The Quantum Threat to Ravencoin

Ravencoin relies exclusively on ECDSA over the secp256k1 elliptic curve for all transaction authorization -- including RVN transfers, asset issuance, asset transfers, admin token operations, restricted asset qualifiers, and messaging. The security of ECDSA rests on the Elliptic Curve Discrete Logarithm Problem (ECDLP), which Shor's algorithm solves in polynomial time on a sufficiently large quantum computer.

**Timeline estimates for a Cryptographically Relevant Quantum Computer (CRQC):**

| Source | Estimate |
|--------|----------|
| NSA CNSA 2.0 (2022) | Requires PQ migration to begin immediately; full compliance by 2035 |
| NIST (2024) | "Within the next few decades" |
| IBM Quantum Roadmap | 100,000+ qubit systems by 2033 |
| Global Risk Institute (2024) | ~50% probability of CRQC by 2037 |
| BSI (German Federal Office) | Recommends PQ migration by 2030 |

The consensus places the CRQC threat window at **2034-2041**. Given that blockchain migration takes years to design, implement, test, deploy, and achieve user adoption, preparation must begin now.

### "Harvest Now, Decrypt Later" and Blockchain Immutability

Unlike encrypted communications, blockchain data is:

1. **Publicly available** -- anyone can download the entire Ravencoin blockchain
2. **Immutable** -- public keys exposed in 2018 transactions are permanently recorded
3. **Economically motivated** -- UTXOs retain (or appreciate in) value indefinitely
4. **Unrevocable** -- no central authority can rotate compromised keys

An adversary can **today** compile a database of every public key ever exposed on the Ravencoin blockchain (from spent P2PKH transactions, P2PK outputs, and multisig scripts), cross-reference with the UTXO set, and attack those funds the moment a CRQC becomes available.

### Ravencoin-Specific Risk: The Asset Layer

Ravencoin's unique asset layer amplifies the quantum threat beyond simple coin theft:

- **Admin token theft** (`$ASSET!`) gives an attacker control over an asset's entire supply and properties -- damage that is **irreversible**
- **Unique assets and NFTs** cannot be "replaced" after theft
- **Restricted asset qualifiers** control who can transact with restricted assets
- **Message channel assets** enable impersonation and fraudulent messaging

Protecting the asset layer is as critical as protecting RVN coins.

### Why Act Now

- **Migration timeline**: A conservative 2-3 year development cycle plus multi-year adoption period means activation around 2029-2030 -- just ahead of the threat window
- **FIPS 204 is finalized**: ML-DSA was standardized by NIST in August 2024. The standard is stable with no further changes expected
- **First-mover advantage**: No major UTXO-based cryptocurrency has deployed production PQ signatures. Ravencoin can lead this critical infrastructure upgrade

---

## Specification

### 1. Algorithm Selection: ML-DSA-44

**ML-DSA** (Module-Lattice-Based Digital Signature Algorithm), standardized in NIST FIPS 204, is selected as the post-quantum signature scheme. The ML-DSA-44 parameter set provides the optimal balance for blockchain use:

| Parameter | ECDSA/secp256k1 (current) | ML-DSA-44 (proposed) |
|-----------|---------------------------|----------------------|
| Public key size | 33 bytes (compressed) | 1,312 bytes |
| Private key size | 32 bytes | 2,560 bytes |
| Signature size | ~72 bytes (DER) | 2,420 bytes |
| Security level | 128-bit classical / **0-bit quantum** | 128-bit classical / **128-bit quantum** |
| Verify time (AVX2) | ~0.035 ms | ~0.02 ms |
| Sign time (AVX2) | ~0.015 ms | ~0.08 ms |
| Stateful | No | No |

#### Why ML-DSA-44 Over Alternatives

| Scheme | Verdict | Rationale |
|--------|---------|-----------|
| **ML-DSA-44 (FIPS 204)** | **Selected** | Best balance of size, speed, implementation simplicity; FIPS standardized; stateless; mature ecosystem |
| ML-DSA-65 / ML-DSA-87 | Rejected | 192/256-bit classical security is overkill -- 128-bit matches current ECDSA level. Larger signatures penalize throughput with no practical security gain |
| FN-DSA / FALCON (FIPS 206) | Rejected | Smallest PQ signatures (~666 B) but requires high-precision floating-point arithmetic -- complex, fragile, side-channel prone. Unacceptable for consensus-critical code |
| SLH-DSA / SPHINCS+ (FIPS 205) | Rejected | Enormous signatures (7,856-49,856 B) and very slow verification. Catastrophic for blockchain throughput |
| XMSS / LMS (SP 800-208) | Rejected | **Stateful** -- signer must track monotonically increasing counter. Wallet backup/restore resets counter, causing catastrophic key reuse. Fundamentally incompatible with the UTXO wallet model |

#### Security Justification

ML-DSA-44 at NIST Level 2 provides 128-bit classical security, equivalent to secp256k1's current security level. In the hybrid scheme, an attacker must break **both** ECDSA (128-bit classical) **and** ML-DSA-44 (128-bit classical + quantum-resistant). The combined security is strictly stronger than either component alone.

ML-DSA's security rests on the Module Learning With Errors (MLWE) problem, which has been studied since Regev (2005) and survived 8 years of NIST public cryptanalysis (82 initial submissions, 3 rounds). No efficient quantum algorithm exists for lattice problems -- unlike ECDSA, where Shor's algorithm provides complete polynomial-time break.

### 2. Hybrid Signature Scheme

#### 2.1 Construction

The hybrid scheme uses **AND-composition**: a transaction input is valid if and only if **both** the ECDSA signature **and** the ML-DSA-44 signature verify against the same transaction sighash.

```
HybridVerify(sighash, ecdsa_pk, mldsa_pk, ecdsa_sig, mldsa_sig):
    valid_ecdsa = secp256k1_ecdsa_verify(ecdsa_pk, sighash, ecdsa_sig)
    valid_mldsa = ML_DSA_44_Verify(mldsa_pk, sighash, mldsa_sig)
    return valid_ecdsa AND valid_mldsa
```

Both signatures are computed over the identical `SignatureHash()` output (the transaction sighash as defined in BIP143-style hashing for witness v0, extended for witness v2). This ensures cryptographic binding -- an adversary cannot mix-and-match signatures from different transactions.

#### 2.2 Security Properties

**Theorem (Hybrid Security):** The advantage of any adversary in forging a hybrid signature is bounded by the minimum of the advantages against ECDSA and ML-DSA individually:

```
Adv_hybrid(A) <= min(Adv_ECDSA(A'), Adv_MLDSA(A''))
```

This means the hybrid scheme is **at least as secure as the stronger component**:

| Scenario | ECDSA | ML-DSA | Hybrid |
|----------|-------|--------|--------|
| Classical adversary | Secure | Secure | **Secure** |
| Quantum adversary (CRQC) | **Broken** | Secure | **Secure** (ML-DSA protects) |
| ML-DSA algorithmic break | Secure | **Broken** | **Secure** (ECDSA protects) |
| Both broken simultaneously | **Broken** | **Broken** | Broken (extremely unlikely) |

#### 2.3 Key Generation

Hybrid keys are generated from a single BIP32 master seed with domain-separated derivation:

```
master_seed (256 bits, from BIP39 mnemonic)
    |
    +-- HMAC-SHA512("ecdsa-secp256k1", master_seed) --> ECDSA key hierarchy (standard BIP32)
    |
    +-- HMAC-SHA512("ml-dsa-44-rvn", master_seed) --> ML-DSA-44 key hierarchy
```

This allows backup of a single 24-word mnemonic while ensuring cryptographic independence between the ECDSA and ML-DSA key material.

#### 2.4 Hybrid Public Key Format

```
+--------+-----------------------------------+----------------------------------+
| Byte 0 | Bytes 1-33                        | Bytes 34-1345                    |
| 0x04   | Compressed ECDSA pubkey (33 B)    | ML-DSA-44 public key (1,312 B)   |
| (type) |                                   |                                  |
+--------+-----------------------------------+----------------------------------+
Total: 1,346 bytes
```

Type byte `0x04` indicates hybrid ECDSA+ML-DSA-44. Future type bytes `0x05` (ML-DSA-65) and `0x06` (ML-DSA-87) are reserved.

### 3. Witness Version 2 Deployment

#### 3.1 Address Format

PQ-hybrid addresses use **witness version 2** with Bech32m encoding (BIP 350):

```
scriptPubKey: OP_2 <32-byte SHA256(hybrid_pubkey)>
address:      rvn1z<bech32m-encoded-data>  (approximately 62 characters)
```

The 32-byte SHA256 hash provides 128-bit collision resistance classically and ~85-bit quantum collision resistance (via the BHT algorithm), which is sufficient.

**Example address** (illustrative):
```
Legacy P2PKH:  R9wYpMKKNh5CnQz7...  (34 characters, starts with R)
PQ Hybrid:     rvn1zqw508d6qejxtdg4y5r3zarvary0c5xw7k... (62 characters)
```

The completely different encoding and length make address confusion impossible.

#### 3.2 Transaction Structure

PQ-hybrid transactions use the existing SegWit serialization format. The witness stack for a PQ-hybrid input contains:

```
Witness stack (4 elements):
  [0] ECDSA signature (71-72 bytes) + sighash type byte
  [1] ML-DSA-44 signature (2,420 bytes)
  [2] Compressed ECDSA public key (33 bytes)
  [3] ML-DSA-44 public key (1,312 bytes)
```

The `scriptSig` is empty (as with all SegWit inputs). The `scriptPubKey` is the compact 34-byte witness program.

#### 3.3 Witness Validation Rules

When a node encounters a witness version 2 program of length 32 bytes:

1. The witness stack MUST contain exactly 4 elements
2. Let `ecdsa_sig = witness[0]`, `mldsa_sig = witness[1]`, `ecdsa_pk = witness[2]`, `mldsa_pk = witness[3]`
3. Verify: `SHA256(0x04 || ecdsa_pk || mldsa_pk) == witness_program` (public key binding)
4. Compute `sighash` using BIP143-style hashing with witness v2 extensions
5. Verify: `secp256k1_ecdsa_verify(ecdsa_pk, sighash, ecdsa_sig)` (ECDSA check)
6. Verify: `ML_DSA_44_Verify(mldsa_pk, sighash, mldsa_sig)` (ML-DSA check)
7. If all checks pass, the input is valid

For unupgraded nodes, witness version 2 outputs are treated as "anyone-can-spend" per BIP141 rules, which is safe as long as a supermajority of miners enforce the new rules.

#### 3.4 Script Size Limits

The current `MAX_SCRIPT_ELEMENT_SIZE` of 520 bytes (in `src/script/script.h`) is insufficient for ML-DSA data. For witness version 2, a new limit applies:

```cpp
static const unsigned int MAX_PQ_WITNESS_ELEMENT_SIZE = 4096; // bytes
```

This limit applies only to witness v2 stack elements. Witness v0 and legacy script limits are unchanged.

### 4. Block Weight and Fee Structure

#### 4.1 PQ Witness Discount

ML-DSA signatures and public keys are pure validation overhead -- needed only for verification, not transaction identification. A **PQ witness discount** appropriately reflects this by counting PQ witness data at reduced weight.

**Weight formula (using integer scale factor 8):**

```
tx_weight = (base_size * 8) + (segwit_witness_size * 2) + (pq_witness_size * 1)
```

Where:
- `base_size` = transaction bytes excluding all witness data
- `segwit_witness_size` = existing SegWit v0 witness data (if any)
- `pq_witness_size` = witness v2 stack data (ECDSA sig + ML-DSA sig + pubkeys)

#### 4.2 Transaction Weight Analysis

| Transaction type | Base (B) | PQ Witness (B) | Weight (WU) | Virtual Size (vB) |
|-----------------|----------|----------------|-------------|-------------------|
| Legacy P2PKH (1-in, 2-out) | 226 | 0 | 1,808 | 226 |
| Current P2WPKH (1-in, 2-out) | 82 | 0 (+107 segwit) | 435 | 141 |
| **PQ Hybrid (1-in, 2-out)** | **82** | **~3,838** | **4,494** | **562** |
| **PQ Hybrid (2-in, 2-out)** | **124** | **~7,676** | **8,668** | **1,084** |

#### 4.3 Phased Block Weight Increase

| Phase | Max Block Weight | Effective Capacity | Activation |
|-------|-----------------|-------------------|------------|
| Current (RIP-2) | 8,000,000 WU | ~18,390 P2WPKH tx/block | Active |
| Phase 1: PQ Opt-in | 12,000,000 WU | ~2,670 hybrid tx/block | At PQ activation height |
| Phase 2: PQ Standard | 16,000,000 WU | ~1,847 hybrid tx/block (mixed) | 1 year after Phase 1 |

At 1-minute block times, even Phase 1 provides **~2,670 hybrid transactions per minute**, which exceeds Ravencoin's current real-world usage by a wide margin.

#### 4.4 Fee Structure

Fees are calculated on **virtual size** (vsize = weight / 8), which applies the PQ witness discount:

| Transaction | Raw Size | Virtual Size | Fee at 0.01 RVN/kvB | Fee multiplier vs legacy |
|-------------|----------|-------------|---------------------|-------------------------|
| Legacy P2PKH (2-in, 2-out) | ~374 B | ~374 vB | ~0.00374 RVN | 1.0x |
| PQ Hybrid (2-in, 2-out) | ~7,800 B | ~1,084 vB | ~0.01084 RVN | **~2.9x** |

A ~2.9x fee increase for quantum-resistant transactions is reasonable and proportional to the actual validation cost. During the first 6 months after activation, a temporary enhanced discount (PQ weight at 0.5x instead of 1x) can further reduce the fee multiplier to ~1.8x to incentivize early adoption.

#### 4.5 Dust Threshold

For PQ-hybrid outputs, the spend cost increases:

```
PQ dust threshold = (34 + virtual_spend_size) * dust_relay_fee / 1000
                  = (34 + ~550) * 3000 / 1000
                  = 1,752 satoshis
```

This is approximately 3.2x the current 546-satoshi threshold -- elevated but not prohibitive.

### 5. Performance Optimizations

#### 5.1 Batch Verification

ML-DSA-44 supports batch verification, achieving approximately **2-3x speedup** for batches of 64+ signatures:

| Verification method | 1,000 signatures | Time |
|--------------------|------------------|------|
| Sequential ECDSA | 1,000 individual | ~50 ms |
| Sequential ML-DSA-44 | 1,000 individual | ~150 ms |
| **Batched ML-DSA-44** | 1 batch of 1,000 | **~60 ms** |
| **Hybrid total (optimized)** | ECDSA sequential + ML-DSA batched | **~110 ms** |

The existing `CCheckQueue` infrastructure in `src/validation.cpp` supports deferred parallel execution. ML-DSA batch verification integrates naturally as a second-phase batch after individual ECDSA checks complete.

#### 5.2 Parallel Verification

The codebase already supports parallel script verification via `nScriptCheckThreads` (up to 16 threads). ECDSA and ML-DSA verification for the same input can run concurrently. With 8 threads:

| Block contents | Sequential | 8 threads + batch | vs. 60s block time |
|---------------|-----------|-------------------|-------------------|
| 1,000 hybrid tx | ~200 ms | ~19 ms | 0.03% of block time |
| 2,000 hybrid tx | ~400 ms | ~38 ms | 0.06% of block time |

Block validation time remains negligible relative to the 60-second block interval.

#### 5.3 Signature and Key Caching

Extended caching scheme leveraging the existing `sigcache` infrastructure:

- **PQ signature cache** (64 MiB): Caches ML-DSA verification results keyed by `HASH(pq_pubkey || message || pq_signature)`
- **PQ public key cache** (32 MiB): Caches deserialized ML-DSA public key NTT representations to avoid redundant decoding
- **Combined script+PQ cache**: Confirms both ECDSA and ML-DSA are valid for a given input

Transactions validated during mempool acceptance achieve near-100% cache hit rate during block validation.

#### 5.4 Lazy PQ Verification

During transaction relay, the ECDSA signature can be verified immediately (fast path) while ML-DSA verification is queued for background processing. Transactions with `PQ_VERIFY_PENDING` status are relayed but not eligible for block template inclusion until ML-DSA verification completes. This maintains relay latency comparable to current transactions.

### 6. Activation Mechanism

#### 6.1 BIP9 Version Bit Signaling

Activation uses BIP9-style version bit signaling, consistent with Ravencoin's existing deployment mechanism for RIP-2 (assets) and RIP-5 (messaging/restricted assets):

```
Deployment parameters:
  bit:                                    9
  nStartTime:                             <6 months after release>
  nTimeout:                               <18 months after start>
  nOverrideRuleChangeActivationThreshold: 1714  (85% of 2016 blocks)
  nOverrideMinerConfirmationWindow:       2016  (~33.6 hours)
```

The 85% threshold (higher than the existing 80%) provides additional safety margin for this cryptographically significant upgrade.

#### 6.2 Activation Sequence

```
DEFINED ──> STARTED ──> LOCKED_IN ──> ACTIVE
                |
                └──> FAILED (if timeout reached)
```

1. **DEFINED**: Software released with dormant PQ verification code
2. **STARTED**: After `nStartTime`, miners signal support via version bit 9
3. **LOCKED_IN**: 1,714 of 2,016 blocks signal support (85%)
4. **ACTIVE**: After one additional 2,016-block period, PQ rules enforced

### 7. Implementation

#### 7.1 Library Integration

The **liboqs** library (Open Quantum Safe, MIT license) is integrated as a vendored subtree, mirroring the existing `src/secp256k1/` pattern:

```
src/
  secp256k1/       (existing -- ECDSA)
  liboqs/          (new -- ML-DSA-44, vendored subtree)
  pqkey.h          (new -- CHybridKey, CHybridPubKey classes)
  pqkey.cpp        (new -- implementation)
```

liboqs provides:
- Production-quality ML-DSA-44 implementation
- Constant-time operations (side-channel resistant)
- AVX2 (x86_64) and NEON (ARM) optimizations
- MIT license (compatible with Ravencoin's MIT license)
- Active maintenance tracking NIST standard updates

#### 7.2 New Classes

```cpp
class CHybridPubKey {
    unsigned char vch[1346];  // type(1) + ECDSA(33) + ML-DSA(1312)
public:
    bool Verify(const uint256& hash, const std::vector<unsigned char>& ecdsa_sig,
                const std::vector<unsigned char>& mldsa_sig) const;
    CPubKey GetECDSAPubKey() const;
    uint256 GetWitnessProgram() const;  // SHA256(vch)
};

class CHybridKey {
    CKey ecdsaKey;
    std::vector<unsigned char, secure_allocator<unsigned char>> mldsaKey; // 2560 bytes
public:
    void MakeNewKey();
    bool Sign(const uint256& hash, std::vector<unsigned char>& ecdsa_sig,
              std::vector<unsigned char>& mldsa_sig) const;
    CHybridPubKey GetPubKey() const;
};
```

#### 7.3 Key Files Modified

| Category | Files | Changes |
|----------|-------|---------|
| **Crypto** | `key.h/cpp`, `pubkey.h/cpp`, new `pqkey.h/cpp`, new `crypto/mldsa.h/cpp` | Hybrid key classes, ML-DSA wrapper |
| **Script** | `script/interpreter.cpp`, `script/script.h` | Witness v2 validation, `MAX_PQ_WITNESS_ELEMENT_SIZE` |
| **Consensus** | `consensus/consensus.h/cpp`, `consensus/params.h` | Block weight increase, PQ deployment flag |
| **Validation** | `validation.cpp` | `GetBlockScriptFlags()`, witness v2 enforcement, PQ caching |
| **Wallet** | `wallet/wallet.h/cpp`, `wallet/walletdb.h/cpp` | Hybrid key generation/storage, PQ address default |
| **Address** | `base58.h`, new Bech32m PQ encoding | Witness v2 address encoding/decoding |
| **P2P** | `protocol.h`, `net_processing.cpp`, `net.h` | `NODE_PQ_HYBRID` service flag, increased `MAX_PROTOCOL_MESSAGE_LENGTH` |
| **Policy** | `policy/policy.h/cpp` | PQ weight calculation, fee/dust adjustments |
| **Activation** | `chainparams.cpp`, `versionbits.h` | BIP9 deployment parameters |
| **Build** | `configure.ac`, `src/Makefile.am`, `depends/packages/liboqs.mk` | liboqs integration |
| **Tests** | New `test/mldsa_tests.cpp`, `test/hybrid_tests.cpp`, extended `test/script_tests.cpp` | Comprehensive test coverage |

**Estimated total**: ~3,500 new lines + ~2,500 modified lines = ~6,000 lines of changes.

### 8. Migration Plan

#### 8.1 Phased Rollout

| Phase | Timeline | Description |
|-------|----------|-------------|
| **Phase 0: Preparation** | Months 1-6 | Software release with dormant PQ code. Community education. Testnet deployment. |
| **Phase 1: Activation** | Months 7-12 | Soft fork activates via BIP9. PQ addresses available. Block weight increases to 12 MWU. |
| **Phase 2: Encouraged** | Months 13-18 | Wallets default to PQ addresses for new keys. Enhanced PQ fee discount. Warnings for legacy addresses. |
| **Phase 3: Standard** | Months 19-24 | Block weight increases to 16 MWU. PQ fee discount settles at permanent level. |
| **Phase 4: Deprecation** | Months 25-48 | Legacy-only transactions increasingly discouraged. Higher fee floor for legacy. |
| **Phase 5: Mandatory** | TBD (if needed) | If CRQC threat becomes imminent, activate mandatory migration with grace period. |

#### 8.2 Wallet Migration

Users migrate by sending their funds from legacy addresses to their own PQ-hybrid addresses. Wallet software automates this:

1. Generate new PQ-hybrid address from same HD seed (domain-separated derivation)
2. Create transaction spending all UTXOs from legacy address to PQ address
3. Sign with existing ECDSA key (standard legacy transaction)
4. Broadcast and confirm

After migration, all new change outputs automatically go to PQ addresses. Wallet backup remains a single 24-word BIP39 mnemonic.

#### 8.3 Emergency Response Plan

If ECDSA is broken before migration completes:

1. **Immediate** (hours): Emergency alert via all channels. Miners implement soft rule: reject transactions spending from exposed-pubkey addresses unless migrating to PQ.
2. **Short-term** (days): Emergency node update. Wallet auto-migration feature.
3. **Medium-term** (weeks): Hard fork making PQ signatures mandatory, with grace period for legacy UTXO migration.

---

## Rationale

### Why Hybrid Instead of Pure Replacement

1. **Defense in depth**: ML-DSA is a newer algorithm (standardized 2024) with less cryptanalytic history than ECDSA's 20+ year track record. The hybrid approach hedges against unforeseen weaknesses in lattice cryptography.
2. **NIST guidance**: NIST SP 800-131B and CNSA 2.0 both recommend hybrid approaches during the post-quantum transition.
3. **Industry consensus**: Bitcoin (BIP-360), Ethereum, and all major blockchain PQ proposals use hybrid schemes.

### Why Soft Fork (Witness v2) Instead of Hard Fork

1. **No chain split risk**: Unupgraded nodes continue to validate the chain (they see witness v2 as "anyone-can-spend" per BIP141).
2. **Proven mechanism**: SegWit witness versioning was specifically designed for this type of extensibility.
3. **Lower coordination burden**: Does not require all nodes to upgrade simultaneously.
4. **Ravencoin already has SegWit**: The infrastructure is in place (`consensus.nSegwitEnabled = true`).

The "anyone-can-spend" concern is mitigated by the 85% activation threshold -- by the time PQ rules activate, a supermajority of miners enforce them.

### Why liboqs

1. **C with C++ compatibility**: Natural integration via `extern "C"`, same pattern as the existing `src/secp256k1/` library.
2. **MIT license**: Compatible with Ravencoin's MIT license.
3. **Active maintenance**: Regular updates tracking NIST standard changes.
4. **Constant-time implementations**: Production-quality side-channel resistance.
5. **Platform optimizations**: AVX2 (x86_64), NEON (ARM), generic C fallback.

### Comparison with Bitcoin BIP-360

| Aspect | BIP-360 (Bitcoin) | RIP-25 (Ravencoin) |
|--------|-------------------|-------------------|
| Algorithm | TBD (address format first) | ML-DSA-44 (concrete, FIPS 204) |
| Timeline | Very early stage | Concrete phased rollout |
| Block size | No increase proposed | Phased increase to 16 MWU |
| Witness discount | Relies on existing SegWit 4x | Deeper 8x PQ discount |

Ravencoin's smaller, more agile community can take a more decisive approach: **ship the actual ML-DSA cryptography from day one** rather than establishing an address format first and selecting an algorithm later.

---

## Security Considerations

### Quantum Threat Model

- **Shor's algorithm** breaks ECDSA/secp256k1 in polynomial time on a CRQC (~2,330 logical qubits for 256-bit curves)
- **Exposed public keys** (spent P2PKH, P2PK, multisig) are immediately vulnerable when a CRQC exists
- **Hash-protected addresses** (unspent P2PKH) provide temporary ~80-bit quantum security via Grover resistance
- **Genesis block** uses P2PK with exposed public key

### Hybrid Security Proof

The AND-composition ensures `Adv_hybrid <= min(Adv_ECDSA, Adv_MLDSA)`. Requirements for this bound to hold:

- Both signatures must cover the same sighash (enforced by validation rules)
- Key generation must use independent entropy (enforced by domain-separated derivation)
- Signing randomness must be independent (ECDSA uses RFC 6979 deterministic nonce; ML-DSA uses FIPS 204 deterministic signing)

### Side-Channel Considerations

- **ML-DSA signing** uses rejection sampling, creating timing variability. Constant-time implementations (as in liboqs) mitigate this.
- **Verification** is a public operation with no secret data processing -- no side-channel risk for consensus nodes.
- **Hardware wallets** must use masked ML-DSA implementations to resist power analysis.

### Implementation Risks

- **Consensus determinism**: ML-DSA verification must produce identical results across all platforms. No floating-point arithmetic, no undefined behavior, no platform-specific integer sizes. Cross-platform testing is mandatory.
- **Script size**: `MAX_SCRIPT_ELEMENT_SIZE` (520 bytes) cannot accommodate ML-DSA data. The new `MAX_PQ_WITNESS_ELEMENT_SIZE` (4,096 bytes) applies only to witness v2, leaving all existing limits unchanged.
- **DoS resistance**: Larger transactions increase bandwidth and storage. The PQ witness discount and block weight limits provide economic protection against spam.

### Audit Requirements

Before mainnet activation:

- **Minimum 2 independent security audits** covering: ML-DSA implementation correctness, hybrid construction, consensus changes, key management, P2P protocol
- **12 months minimum testnet operation** (3 months developer testnet + 6 months public testnet + 3 months mainnet staging)
- **Dedicated bug bounty program** (up to $200,000 for critical vulnerabilities)
- **Formal verification** of ML-DSA verification algorithm and hybrid validation path where practical

---

## Backwards Compatibility

This proposal is a **soft fork**. Backwards compatibility is maintained as follows:

- **Unupgraded nodes**: See witness v2 outputs as "anyone-can-spend" per BIP141 rules. They do not validate PQ signatures but still follow the longest valid chain as long as the miner majority enforces PQ rules.
- **Legacy addresses**: Continue to work indefinitely. Funds in legacy addresses can be spent normally.
- **Legacy transactions**: Continue to be valid. No existing transaction type is modified or invalidated.
- **Asset transactions**: All asset operations (issue, reissue, transfer, restrict) work with both legacy and PQ addresses.
- **Migration**: Voluntary. Users migrate funds at their own pace by sending from legacy to PQ addresses.

The only breaking change is that **new PQ-hybrid transaction outputs** cannot be validated by unupgraded nodes. This is the standard SegWit witness versioning trade-off, well-understood and widely deployed.

---

## Test Plan

### Unit Tests

- ML-DSA-44 key generation, signing, verification (including edge cases and known-answer tests from FIPS 204)
- Hybrid key generation with domain-separated derivation
- Hybrid signature construction and verification
- Rejection of partial signatures (valid ECDSA + invalid ML-DSA, and vice versa)
- Witness v2 script validation
- Address encoding/decoding round-trip
- Weight calculation correctness

### Integration Tests

- Full transaction lifecycle: create PQ address -> fund -> spend -> verify
- Mixed blocks with legacy and PQ transactions
- Mempool acceptance and relay of PQ transactions
- Block template construction with PQ transactions
- Wallet backup, restore, and migration
- Asset operations with PQ addresses (issue, reissue, transfer, restrict)

### Network Tests

- P2P propagation of PQ transactions and blocks
- Version bit signaling and activation state machine
- Behavior of unupgraded nodes during and after activation
- Compact block relay with PQ transactions

### Performance Benchmarks

- ML-DSA-44 sign/verify throughput (single-threaded and multi-threaded)
- Batch verification speedup measurement
- Block validation time with varying PQ transaction density
- Mempool acceptance rate under PQ transaction load
- IBD time with PQ-era blocks

### Testnet Deployment

- **Phase 1** (3 months): Developer testnet with accelerated activation
- **Phase 2** (6 months): Public testnet with real-world activation parameters
- **Phase 3** (3 months): Mainnet-ready release candidate on testnet

---

## Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| **Design & Specification** | 2-4 months | Finalized RIP, test vectors, detailed spec |
| **Core ML-DSA Integration** | 2-3 months | liboqs vendoring, `CMLDSA` wrapper, unit tests, benchmarks |
| **Hybrid Key & Signature** | 2-3 months | `CHybridKey`/`CHybridPubKey`, signing/verification, wallet integration |
| **Witness v2 & Consensus** | 3-4 months | Script interpreter, validation rules, activation mechanism |
| **Optimization** | 2-3 months | Batch verification, caching, PQ witness discount, weight calculations |
| **Testing & QA** | 3-6 months | Testnet deployment, security audits, bug bounty, performance testing |
| **Mainnet Activation** | 2-3 months | Release, miner signaling, activation |
| **Total** | **16-26 months** | |

---

## References

1. NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard (ML-DSA)," August 2024
2. Shor, P.W., "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," SIAM J. Comput., 26(5):1484-1509, 1997
3. Bindel, N., et al., "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange," PQCrypto 2019
4. NSA, "Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) Cybersecurity Advisory," September 2022
5. BIP 141, "Segregated Witness (Consensus layer)"
6. BIP 143, "Transaction Signature Verification for Version 0 Witness Program"
7. BIP 350, "Bech32m format for v1+ witness addresses"
8. Ducas, L., et al., "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme," TCHES 2018
9. ETSI, "Quantum Safe Cryptography and Security," White Paper No. 8, 2020
10. Global Risk Institute, "Quantum Threat Timeline Report," 2024
11. Bitcoin BIP-360, "QuBit - Pay to Quantum Resistant Hash," Hunter Beast, 2024
12. Ravencoin Whitepaper, Fenton, Black, et al., 2018
13. IETF draft-ietf-pquip-hybrid-signature, "Hybrid Signature Specifiers," 2024
14. Roetteler, M., et al., "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms," ASIACRYPT 2017

---

## Copyright

This document is licensed under the MIT License.
