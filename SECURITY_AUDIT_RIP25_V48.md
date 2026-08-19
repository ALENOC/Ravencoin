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
- checkpoint at height `4487775` remains present with hash `000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd`.
- the KAWPOW header-declared height is checked against the actual chain height from the activation point.
- the 4.8 asset-transfer overflow fix remains enabled.
- `DEPLOYMENT_TRANSFER_OVERFLOW` keeps version bit **11**.
- block-index/load hardening added by 4.8 remains intact.

These invariants are now enforced by `contrib/devtools/check-rip25-v48-invariants.sh`, which is wired into every required RIP-25 v4.8 build before dependency compilation.

## Findings

| ID | Severity | Finding | Status / required remediation |
|---|---|---|---|
| RIP25-V48-001 | CRITICAL | RIP-25 originally uses BIP9 bit 11, but 4.8.0 now uses bit 11 for `DEPLOYMENT_TRANSFER_OVERFLOW`. Two deployments cannot safely share the bit. | **FIXED ON INTEGRATION BRANCH:** overflow remains bit 11; only RIP-25 signaling moves to unused bit 12. Threshold/window and RIP-25 feature logic remain unchanged. The invariant gate checks both assignments. |
| RIP25-V48-002 | CRITICAL | `fPQHybridIsActive` was declared `static` in a header, giving each translation unit its own activation copy and making activation/reorg behavior unsafe. | **PARTIALLY REMEDIATED:** the TU-local/global PQ state has been removed from `consensus.h` and the CI invariant gate forbids its return. Final remediation requires the contextual `pindexPrev`/VersionBits implementation to land in `validation.cpp`. |
| RIP25-V48-003 | CRITICAL | Mainnet `GetBlockScriptFlags()` in the original RIP-25 patch checked `nPQHybridEnabled`; mainnet initializes it false, so BIP9 `ACTIVE` did not itself enable `SCRIPT_VERIFY_PQ_HYBRID`. | **OPEN — FINAL CONSENSUS MERGE BLOCKER:** final `validation.cpp` must derive the block's PQ script flag from `VersionBitsState(pindex->pprev, ..., DEPLOYMENT_PQ_HYBRID)`; force-enable remains test-chain-only. The invariant gate intentionally remains red until this is present. |
| RIP25-V48-004 | HIGH | The specification requires phase 2 at 16 MWU one year after phase 1, but the original implementation did not consume the phase-2 constant in the active block-limit path. | **OPEN — FINAL CONSENSUS MERGE BLOCKER:** audited local implementation derives the first `ACTIVE` height using `VersionBitsStateSinceHeight()` and changes 12 -> 16 MWU after one nominal year of blocks (`365*24*60*60 / nPowTargetSpacing`). This must land in `validation.cpp` and be boundary/reorg tested. |
| RIP25-V48-005 | HIGH | The approved 8x PQ discount was applied to transaction weight while block-level consensus still used normal SegWit weight, allowing miner/fee and final block validation accounting to disagree. | **PARTIALLY REMEDIATED:** `GetBlockWeight()` is now the standard/RIP-2 calculation and `GetBlockWeightRIP25()` applies the approved extra PQ discount. Policy no longer enables PQ script verification unconditionally. Final contextual selection between the two remains blocked on the `validation.cpp` merge. |
| RIP25-V48-006 | HIGH | Deterministic `KeyGen(seed)` silently fell back to random key generation when internal liboqs deterministic symbols were unavailable. Identical wallet seeds could produce different keys across builds/platforms. | **FIXED AND HARDENED:** the branch now uses the public liboqs randombytes hook under a process-local mutex, verifies exact seed consumption, restores the system RNG, and fails closed if any step fails. No weak/private-symbol random fallback remains. |
| RIP25-V48-007 | HIGH | `depends/packages/liboqs.mk` contained a placeholder checksum, defeating deterministic dependency verification. | **FIXED ON INTEGRATION BRANCH:** liboqs 0.12.0 is pinned to SHA-256 `df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08`; liboqs is included in the depends package graph. |
| RIP25-V48-008 | HIGH / DEPLOYMENT | Raising the consensus maximum from 8 MWU to 12/16 MWU is a rule relaxation. Nodes that still enforce the old 8 MWU ceiling can reject a larger block. | **OPEN DEPLOYMENT GATE:** preserve the approved 8/12/16 limits. Mixed-version testnet behavior and the required network-upgrade/activation strategy must be documented and demonstrated before mainnet activation. This is a deployment property, not permission to alter the approved limits. |
| RIP25-V48-009 | HIGH | The August-2026 exploit fix and RIP-25 both touch consensus-sensitive validation/versionbits code. A textual merge can accidentally restore pre-4.8 behavior. | **PARTIALLY REMEDIATED / TEST GATE:** current integration `chainparams`, params and VersionBits preserve height 4,487,776, checkpoint 4,487,775, overflow bit 11 and PQ bit 12. The new invariant gate also requires `bad-blk-height` and overflow enforcement to remain present. Executable attack/regression tests are still required on the final merged tree. |
| RIP25-V48-010 | HIGH | PQ signature hashing, witness-program binding, wallet key persistence/encryption, malformed ML-DSA inputs and resource-exhaustion paths require adversarial review on the final merged tree. | **IN PROGRESS:** wallet encrypted-key handling now validates secret/public-key correspondence on add, encrypt, unlock and decrypt/load paths. Crypto wrapper validation has also been tightened. Malformed-input, persistence/recovery and resource-exhaustion tests remain release gates. |

## Required security/consensus tests before updating upstream PR #1281

1. 4.8 exploit regression: invalid declared KAWPOW height is rejected at/after height 4,487,776.
2. 4.8 asset-transfer overflow regression remains rejected before, during and after PQ activation.
3. BIP9 states: DEFINED -> STARTED -> LOCKED_IN -> ACTIVE at the intended 85% threshold, with transfer-overflow bit 11 and PQ bit 12 evolving independently.
4. Pre-activation witness-v2 behavior remains compatible with the intended deployment model.
5. First ACTIVE block enforces ML-DSA witness-v2 signatures.
6. 8 MWU pre-activation limit; 12 MWU phase-1 limit; 16 MWU phase-2 limit.
7. Boundary tests at limit-1, limit and limit+1 for all three phases, including the exact phase-2 transition height.
8. 8x PQ witness discount is identical in mempool/fee estimation, miner selection and consensus block accounting when active, and is not granted to block consensus before activation.
9. Reorg from ACTIVE/phase-2 back to an earlier state restores the correct earlier block limits and script rules.
10. Restart/reindex/IBD at pre-activation, phase-1 and phase-2 heights produces the same consensus result.
11. Valid/invalid ML-DSA-44 signature, wrong pubkey, wrong pubkey hash, truncated/oversized signature/key, extra witness item and empty witness tests.
12. ECDSA -> ECDSA, ECDSA -> PQ, PQ -> ECDSA and PQ -> PQ spend paths.
13. Wallet encryption, lock/unlock, backup/restore, deterministic recovery and secret/public-key mismatch rejection tests for PQ keys.
14. liboqs dependency checksum and platform build reproducibility checks.
15. CPU/memory adversarial tests for blocks/transactions containing the maximum permitted number of PQ signatures.

## CI release gate

The integration branch is not eligible to replace the head of upstream PR #1281 until all of the following are true:

- `contrib/devtools/check-rip25-v48-invariants.sh` passes on the exact candidate commit;
- security audit has no unresolved CRITICAL/HIGH code findings;
- exploit + PQ regression suite is green;
- five required fork builds are green: `build (arm32v7-disable-wallet)`, `build (arm32v7)`, `build (linux-disable-wallet)`, `build (linux)`, `build (windows)`;
- the upstream PR head is updated only after the fork gate passes;
- the five upstream required checks are green on the updated PR.

Until those conditions are met, upstream PR #1281 must remain untouched.
