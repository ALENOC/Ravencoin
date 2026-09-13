# RIP-25 PQ Asset Extension Design Note

Status: follow-up design analysis only. This document does not define or activate a consensus rule.

## 1. Current Scope

RIP-25 witness-v2 protects native RVN outputs only. No current Ravencoin asset class can be issued, held, transferred, reissued, tagged, frozen, or spent under an ML-DSA-44 witness-v2 ownership condition.

The current spendable asset envelope is:

```
OP_DUP OP_HASH160 <20-byte-key-id> OP_EQUALVERIFY OP_CHECKSIG
OP_RVN_ASSET <serialized-asset-data> OP_DROP
```

`CScript::IsAssetScript` recognizes `OP_RVN_ASSET` only at byte offset 25. `Solver` then extracts the 20-byte key identifier from the P2PKH prefix. Wallet ownership and signing consequently resolve the output through a classical secp256k1 `CKeyID`.

The limitation applies to all current asset classes:

| Class | Current authorization | RIP-25 protection |
|---|---|---|
| Normal and sub-assets | Legacy P2PKH asset output | None |
| Owner token `ASSET!` | Legacy P2PKH asset output | None |
| Reissuable asset | Legacy owner token plus legacy destination | None |
| Unique asset | Legacy parent owner token plus legacy destination | None |
| Restricted asset `$ASSET` | Legacy root owner token `ASSET!` | None |
| Qualifier and sub-qualifier | Legacy qualifier ownership and address records | None |

The notation `$ASSET!` is not the controlling owner token for a restricted asset. The restricted asset `$ASSET` is administered through the root owner token `ASSET!`.

## 2. Security Consequence

A cryptographically relevant quantum computer that recovers a secp256k1 private key can steal an asset UTXO even if the same wallet also holds native RVN at RIP-25 addresses. Theft of `ASSET!` is especially serious because it can transfer administrative control and authorize reissuance when the asset is reissuable. Unique assets can be transferred irreversibly. Restricted and qualifier administration remains exposed through its legacy authorization outputs.

Wallet and RPC messages must not imply that generating a PQ address protects asset owner or administrator tokens. The immediate implementation guard rejects unsupported asset destinations before it constructs an invalid transaction.

## 3. Why the Proposed Concatenation Is Unsafe

One conceptual form suggested for future analysis is:

```
OP_2 <32-byte-hash> OP_RVN_ASSET <serialized-asset-data> OP_DROP
```

It must not be adopted directly.

First, a native witness program must be the entire script. Adding any suffix makes `CScript::IsWitnessProgram` return false. Second, the current asset parser requires the asset opcode at the P2PKH-specific byte offset. Third, `OP_RVN_ASSET` is a no-op in ordinary script execution. Merely teaching the asset parser to recognize the proposed concatenation would not invoke witness-v2 verification and could create an anyone-can-spend asset output.

Current nodes reject the form because the asset opcode appears in the wrong location. Changing it from invalid to valid expands the set of valid transactions. The deployment and legacy-node consequences therefore require a complete fork analysis and cannot be assumed to form a conventional soft fork.

## 4. Required Protocol Design

A follow-up proposal should define a canonical versioned asset envelope that separates:

1. the ownership or spending-condition version;
2. the asset operation type;
3. the serialized asset payload.

The spending condition must unambiguously dispatch to ML-DSA-44 witness-v2 verification. It must not depend on a parser side effect or on executing `OP_RVN_ASSET` as an opcode. The proposal must specify exact serialization lengths, canonical pushes, rejection of trailing data, and how unknown versions behave.

At minimum, the consensus design must cover:

- normal issue and transfer operations;
- owner-token creation and transfer;
- reissue authorization;
- unique-asset creation and transfer;
- restricted-asset issue, transfer, reissue, freeze, and verifier behavior;
- qualifier and sub-qualifier issue, transfer, tag, and untag behavior;
- asset input and output overflow checks from Ravencoin Core 4.8.0;
- fixed RIP-25 SIGHASH policy;
- ML-DSA network context and cross-network replay resistance;
- PQ sigop-equivalent accounting;
- contextual witness discount and block-weight accounting;
- activation boundaries and reorgs.

## 5. Recognition and Script Ambiguity

The design must replace fixed-offset assumptions with a parser that accepts exactly the intended legacy and activated PQ forms. It must prove that:

- no legacy script changes meaning;
- no script is accepted by both legacy and PQ parsers with different destinations or asset payloads;
- no malformed PQ form falls through to ordinary script execution;
- unknown ownership versions fail closed after activation;
- `IsAssetScript`, `Solver`, destination extraction, and transaction classifiers agree;
- null asset data cannot be confused with spendable asset ownership.

Parser tests need canonical and non-canonical encodings, shortened and extended programs, misplaced opcodes, extra stack elements, trailing bytes, and payload length boundaries.

## 6. Legacy-Node and Activation Analysis

The proposal must state how an unupgraded node evaluates each new output and spend. If an old node treats the new form as spendable without ML-DSA verification, activation must ensure upgraded miners and validators reject unauthorized spends. If old nodes reject the new output form, deployment has hard-fork characteristics and must be treated accordingly.

The activation design must include:

- a dedicated deployment or an explicitly justified reuse of a deployment state;
- pre-activation policy and consensus behavior;
- `DEFINED`, `STARTED`, `LOCKED_IN`, and `ACTIVE` transitions;
- activation-height minus two through activation-height plus two vectors;
- invalidate and reconsider behavior;
- reorgs across `LOCKED_IN` and `ACTIVE`;
- versionbits cache invalidation and restart behavior;
- miner-template and validator equivalence.

No asset extension should be coupled silently to an already deployed RIP-25 bit.

## 7. Wallet, RPC, and Address Encoding

The wallet needs an explicit PQ asset destination type rather than reusing a native-RVN address without a defined asset meaning. The design must decide whether the same witness-v2 address can represent both native RVN and asset ownership or whether a distinct encoding is safer.

Required wallet behavior includes:

- PQ asset ownership detection and balance attribution;
- ML-DSA signing for every asset spend path;
- PQ asset change selection;
- owner-token and reissue authorization;
- coin control and fee estimation for large witnesses;
- encrypted key persistence and recovery;
- watch-only and multisig policy, if supported;
- import, export, backup, restore, rescan, and salvage behavior;
- explicit errors on unsupported mixed legacy and PQ constructions.

All high-level and raw-transaction RPCs must construct only canonical activated forms. RPC acceptance must not be treated as proof of consensus validity.

## 8. Asset Index and Database Compatibility

Asset indexes currently derive an address identity from legacy 20-byte data. A PQ program is 32 bytes. The follow-up design must version index keys or otherwise prevent truncation and type confusion.

It must specify:

- address-index key format;
- asset cache and database serialization versions;
- reindex and downgrade behavior;
- explorer and RPC address rendering;
- restricted and qualifier database keys;
- mempool overlay behavior;
- database rebuild after chainstate recovery.

Database readers must reject malformed or unknown key versions without interpreting them as legacy records.

## 9. Owner-Token Migration

Existing `ASSET!` outputs cannot become quantum-resistant merely because RIP-25 activates. A migration mechanism must prove current authorization while moving control to a PQ asset condition. Design choices include a normal legacy-authorized transfer into the new condition or a dedicated migration transaction type.

The proposal must address:

- migration of owner tokens before a quantum emergency;
- reissuable assets whose owner token is lost or stolen;
- unique and restricted asset control;
- partial wallet migration and mixed legacy/PQ holdings;
- replay of migration transactions across networks;
- rescan and restore discovery;
- whether migration can be reversed;
- emergency behavior without creating a confiscation or inflation path.

There is no safe automatic migration after the classical private key has been compromised.

## 10. Mempool and Resource Policy

Policy must bound attacker-controlled input before expensive ML-DSA verification. It must apply exact public-key and signature sizes, exact witness stack shape, canonical asset serialization, transaction-size limits, ancestor and descendant policy, orphan limits, and explicit PQ sigop-equivalent accounting.

Consensus and policy limits must remain distinct. Policy may reject more than consensus, but miners and validators must calculate the same activated consensus cost for a block.

## 11. Required Validation Matrix

The follow-up implementation should not be proposed for activation without:

- consensus `tx_valid` and `tx_invalid` vectors for every asset class;
- correct and incorrect ML-DSA signature vectors;
- script ambiguity and parser differential tests;
- cross-network replay tests;
- activation and reorg tests;
- miner-template versus block-validation tests;
- asset input/output overflow regression tests;
- wallet encrypted-backup recovery tests;
- address-index and reindex tests;
- P2P, orphan, mempool, and block resource tests;
- real-verifier fuzzing under ASan and UBSan;
- cross-platform deterministic validation builds.

## 12. Current Decision

The current RIP-25 remediation deliberately does not implement a PQ asset consensus extension. It documents assets as out of scope, rejects witness-v2 destinations in asset construction paths, and preserves the existing consensus rules. A separate RIP and independent adversarial review are required for any future PQ asset design.
