# RIP-25 on Ravencoin Core 4.8.0 — Security Audit Gate

Status: **IN PROGRESS — NOT READY FOR UPSTREAM PR UPDATE**

This audit treats the approved RIP-25 design as an invariant. In particular, the following are **not to be removed or redesigned by the 4.8 port**:

- ML-DSA-44 witness v2 signatures;
- BIP9 activation at 85% miner threshold;
- PQ witness scale factor **8x**;
- block-weight progression **8 MWU -> 12 MWU -> 16 MWU**;
- existing ECDSA/witness-v0 behavior remains available during migration.

The purpose of the port is to integrate those rules with the Ravencoin Core 4.8.0 security baseline and remove implementation defects without changing the intended RIP-25 behavior.

## 4.8.0 invariants that must survive the port

- `nHeightHeaderCheckActivation = 4487776` on mainnet.
- checkpoint at height `4487775` remains present.
- the KAWPOW header-declared height is checked against the actual chain height from the activation point.
- the 4.8 asset-transfer overflow fix remains enabled.
- `DEPLOYMENT_TRANSFER_OVERFLOW` keeps version bit **11**.
- block-index/load hardening added by 4.8 remains intact.

## Findings

| ID | Severity | Finding | Status / required remediation |
|---|---|---|---|
| RIP25-V48-001 | CRITICAL | RIP-25 originally uses BIP9 bit 11, but 4.8.0 now uses bit 11 for `DEPLOYMENT_TRANSFER_OVERFLOW`. Two deployments cannot safely share the bit. | **PORT REMEDIATION:** move only the RIP-25 signaling bit to unused bit 12. Keep its threshold/window and feature logic unchanged. |
| RIP25-V48-002 | CRITICAL | `fPQHybridIsActive` is declared `static` in a header. That gives each translation unit its own copy; `validation.cpp` can set one copy while `consensus.cpp` reads a different copy. The intended 8 -> 12 MWU transition can therefore fail to activate. | **OPEN:** replace TU-local state with a single reorg-safe activation source while preserving the 8/12/16 limits. |
| RIP25-V48-003 | CRITICAL | Mainnet `GetBlockScriptFlags()` in the original RIP-25 patch only checks `nPQHybridEnabled`; mainnet initializes it to false. BIP9 reaching `ACTIVE` does not by itself turn on `SCRIPT_VERIFY_PQ_HYBRID` in that code path. | **OPEN:** derive the block's PQ script flag from `VersionBitsState(pindex->pprev, ..., DEPLOYMENT_PQ_HYBRID)`; retain force-enable behavior only where intentionally used for test chains. |
| RIP25-V48-004 | HIGH | The 16 MWU phase-2 constants exist, and the specification says phase 2 begins one year after phase 1, but the reviewed implementation does not currently consume the phase-2 constant in the active block-limit path. | **OPEN:** implement/test the already-specified 12 -> 16 MWU phase transition without changing its intended policy. Exact deterministic activation calculation must be consensus-defined and tested across reorg/restart. |
| RIP25-V48-005 | HIGH | The approved 8x PQ discount is applied by `GetTransactionWeight()` using the PQ witness shape, while the block-level `GetBlockWeight()` path still uses the normal SegWit weight formula. Miner selection/fee accounting and final block validation can therefore disagree near the block limit. | **OPEN:** make the approved 8x rule consistent in transaction selection, block construction and consensus validation, and make it activation-aware. Do not remove the 8x discount. |
| RIP25-V48-006 | HIGH | Deterministic `KeyGen(seed)` silently fell back to random key generation when liboqs internal deterministic symbols were unavailable. Identical wallet seeds could produce different keys across builds/platforms. | **FIXED ON INTEGRATION BRANCH:** deterministic derivation now fails closed instead of silently generating a random key. |
| RIP25-V48-007 | HIGH | `depends/packages/liboqs.mk` contained `TODO_REPLACE_WITH_ACTUAL_HASH`, defeating deterministic dependency verification. | **FIXED ON INTEGRATION BRANCH:** liboqs 0.12.0 archive is pinned to SHA-256 `df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08`. |
| RIP25-V48-008 | HIGH / DEPLOYMENT | Raising a consensus maximum from 8 MWU to 12/16 MWU is a rule relaxation. Nodes that still enforce the old 8 MWU ceiling can reject a larger block. | **OPEN DEPLOYMENT GATE:** preserve the approved limits, but test mixed-version behavior and document the required network-upgrade/activation strategy before mainnet activation. |
| RIP25-V48-009 | HIGH | The August-2026 exploit fix and RIP-25 both touch consensus-sensitive validation/versionbits code. A textual merge can accidentally restore the pre-4.8 behavior. | **OPEN TEST GATE:** mutation/regression tests must prove header-height mismatch and transfer-overflow attacks remain rejected after PQ activation, including reorg/reindex/restart paths. |
| RIP25-V48-010 | HIGH | PQ signature hashing, witness-program binding, wallet key persistence/encryption, malformed ML-DSA inputs and resource-exhaustion paths require adversarial review on the final merged tree. | **OPEN AUDIT GATE.** |

## Required security/consensus tests before updating upstream PR #1281

1. 4.8 exploit regression: invalid declared KAWPOW height is rejected at/after height 4,487,776.
2. 4.8 asset-transfer overflow regression remains rejected before, during and after PQ activation.
3. BIP9 states: DEFINED -> STARTED -> LOCKED_IN -> ACTIVE at the intended 85% threshold.
4. Pre-activation witness-v2 behavior remains compatible with the intended deployment model.
5. First ACTIVE block enforces ML-DSA witness-v2 signatures.
6. 8 MWU pre-activation limit; 12 MWU phase-1 limit; 16 MWU phase-2 limit.
7. Boundary tests at limit-1, limit and limit+1 for all three phases.
8. 8x PQ witness discount is identical in mempool/fee estimation, miner selection and consensus block accounting.
9. Reorg from ACTIVE/phase-2 back to earlier state restores the correct earlier block limits and script rules.
10. Restart/reindex/IBD at pre-activation, phase-1 and phase-2 heights produces the same consensus result.
11. Valid/invalid ML-DSA-44 signature, wrong pubkey, wrong pubkey hash, truncated/oversized signature/key, extra witness item and empty witness tests.
12. ECDSA -> ECDSA, ECDSA -> PQ, PQ -> ECDSA and PQ -> PQ spend paths.
13. Wallet encryption, lock/unlock, backup/restore and deterministic recovery tests for PQ keys.
14. liboqs dependency checksum and platform build reproducibility checks.
15. CPU/memory adversarial tests for blocks/transactions containing the maximum permitted number of PQ signatures.

## CI release gate

The integration branch is not eligible to replace the head of upstream PR #1281 until all of the following are true:

- security audit has no unresolved CRITICAL/HIGH code findings;
- exploit + PQ regression suite is green;
- five required fork builds are green;
- the upstream PR head is updated only after the fork gate passes;
- the five upstream required checks are green on the updated PR.
