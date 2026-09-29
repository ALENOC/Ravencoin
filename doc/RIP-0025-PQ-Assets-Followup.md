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

## 13. Experimental Compatibility Direction

The following is a research direction for a separate extension. It is not an
activated rule and must not be described as protecting assets in the current
RIP-25 implementation.

Directly appending a witness-v2 program or witness to a legacy P2PKH asset
output does not work as a compatible soft fork. The complete script is not a
native witness program, while existing witness validation rejects nonempty
witness data for a non-witness prevout as unexpected. Merely recognizing a
different `OP_RVN_ASSET` offset would not solve spending, and a bare
`OP_2 <hash> OP_RVN_ASSET` output is anyone-can-spend to older script engines.

A first suffix candidate was falsified by a unit test: an opaque
`OP_2 <32-byte program>` after `OP_DROP` is included in the old transfer
deserializer stream. The old parser mistakes it for an asset message and
rejects the output. It must not be implemented.

A second candidate encodes the program in the optional transfer-message slot
using a distinct raw marker byte, canonical CompactSize 32, and the program.
The experimental marker `0x50` is not a protocol assignment. Although the old
parser accepts this form, it consumes the genuine message field, can emit
unwanted owner-token messages, and does not cover issuance or reissuance well.
It is a compatibility probe, not the preferred extension.

A third candidate replaces the final `OP_DROP` byte of a canonical P2PKH asset
output with exactly 32 raw bytes containing the PQ program. The old script
engine treats all bytes after `OP_RVN_ASSET` as opaque. Old transfer and reissue
deserializers ignore exactly 32 residual bytes when no optional message or
metadata hash exists. When a genuine transfer message exists, the protected
form must serialize an explicit eight-byte expiry (zero if absent) before the
32-byte tail; the old parser then retains the original message and expiry and
ignores the tail. Initial issuance and owner-token parsers also ignore the
tail. Local unit tests prove parsing and existing transaction/asset checks for
representative transfer, issue, owner, and reissue scripts, including normal,
unique, restricted, and qualifier transfer names. This is evidence of parser
compatibility, not evidence that the proposed new consensus rule is safe.

A research-only helper recognizes the narrow canonical envelope and rejects
short/long tails, nonminimal pushes, malformed payloads, and transfer messages
without an explicit expiry field. Its classification is deliberately not used
by consensus. An old-valid script ending in `OP_DROP` plus 31 arbitrary bytes
is byte-identical to a candidate with a 32-byte program beginning `OP_DROP`.
The helper necessarily classifies it as a candidate. Any later spend rule
must therefore check the creating UTXO's height against the asset extension's
activation height. Applying the rule only at spending height would retroactively
lock historical coins and could split nodes after reorg or reindex.

The proposed new rule would not put an unexpected witness on the asset input.
Instead, the spending transaction would also consume a native RIP-25
witness-v2 UTXO whose program equals the program committed in the asset output.
Its fixed `SIGHASH_ALL` ML-DSA signature commits to every asset input and
output in the same transaction. A quantum attacker with only the P2PKH
private key could not create the required PQ input.

This construction is a candidate, not yet a specification. Before activation
it needs an exact per-type canonical parser, protection against
historical lookalike scripts, explicit creation-height semantics, a separate
activation decision, asset-change and owner-token no-downgrade rules, anchor
UTXO funding and refresh behavior, wallet coin selection, restricted-address
checks, miner and mempool equivalence, sigop and weight accounting, and
cross-network and reorg vectors. A separate BIP9 bit must not be assigned or
enabled on mainnet without protocol-owner review. Until these are proved, the
current native-RVN-only security claim remains unchanged.

## 14. Contextual Enforcement Map (Research, Not Activated)

The current code offers a UTXO-aware block hook in `ConnectBlock` before
`UpdateCoins`: `CheckTxInputs` and `Consensus::CheckTxAssets` run with the
candidate block's coins view. `Coin::nHeight` is available there. Mempool
admission has a separate `CCoinsViewMemPool` path, where an unconfirmed parent
uses `MEMPOOL_HEIGHT`. A future rule must define that sentinel's behavior and
must mirror block checks in mempool policy without making consensus depend on
mempool state.

The block script flags come from the candidate block's `pindex->pprev`, while
mempool flags come from `chainActive.Tip()`. A future asset deployment must use
the candidate context in `ConnectBlock`; using the global active tip would
permit two nodes validating the same side chain to apply different rules.
The parser's historical `OP_DROP` lookalike requires a creation-height check
against the asset extension activation height, not merely a spend-height
check. Reorgs across activation must evict or revalidate affected mempool
transactions. Reusing the existing RIP-25 bit 12 would be unsafe because it
would make the newly upgraded nodes enforce a rule older RIP-25 nodes do not.

`CheckInputs` may skip ordinary script checks under assumevalid or return from
its script cache. Existing code selectively verifies native witness-v2
scripts even when ordinary checks are skipped. Any anchor construction must
prove that this protection applies to every matching native witness-v2 input,
and must enforce the asset-to-anchor relationship in a UTXO-aware path outside
any script-cache early return. `TestBlockValidity` is the miner's final
template check, but direct template selection and package policy still need
boundary tests. `Consensus::CheckTxAssets` is also called during mempool
revalidation and consistency checks; a new parameter defaulting to inactive
could silently omit the rule at those sites.

The precise matching rule remains undecided: whether one matching native
witness-v2 anchor input can authorize several tagged asset inputs with the
same program, and whether creating an asset output must create a funded anchor
output. Those choices affect wallet funding, UTXO availability, migration,
fee estimation, and duplicate-program resource limits. They require a protocol
decision before any consensus patch. No BIP9 bit is assigned by this research.

## 15. 4.8.1 Integration Candidate and Release Gate

The 4.8.1 integration request expands RIP-25 to assets. The native-RVN
implementation and its bit 12 deployment must remain unchanged. This section
records a candidate for review, not a consensus rule already in force.

Let `H` be the first height at which a separate, dependent PQ asset deployment
is active on the candidate chain. A safe soft-fork direction requires both:

1. Every spendable asset output created at height `h >= H`, including an owner
   token, has one canonical 32-byte PQ program in the validated legacy-compatible
   envelope. Null asset metadata outputs remain governed by their existing
   rules. An asset output without the canonical program is invalid at `h >= H`.
2. A transaction spending an asset UTXO created at `h >= H` must also spend a
   native RIP-25 witness-v2 UTXO whose 32-byte program equals that asset
   output's committed program. One valid anchor input may authorize several
   tagged asset inputs only when their programs match. The native witness-v2
   fixed `SIGHASH_ALL` signature then binds every input and output of the
   transaction. Classical asset-script authorization remains required too.

The candidate block's previous index, not the global active tip, must select
the BIP9 state. Mempool admission uses the current tip and treats an unconfirmed
parent as created after activation. The check must run outside script-cache and
assumevalid shortcuts. Native witness-v2 signature verification must still run
under assumevalid when the asset anchor is needed. A transaction may not remove
the PQ condition by sending its asset to a legacy-only output after activation.

The creation-height rule is essential. A pre-activation script ending in
`OP_DROP` plus 31 bytes can be byte-identical to a tagged candidate. Requiring
an anchor from such a historical coin would retroactively make old-valid
spends invalid. Conversely, a pre-activation tagged-looking output cannot be
advertised as PQ-protected merely because its spend happens after activation.

This construction still does not retroactively secure existing owner tokens.
Their classical key holder must authorize a migration into a newly tagged
output before that classical key is compromised. A quantum attacker who obtains
the old key can race that migration. Software cannot distinguish the rightful
holder from the attacker using the old signature alone.

The following decisions remain release-blocking and must be proved before
assigning mainnet activation parameters or publishing a 4.8.1 artifact as
asset-PQ-qualified: exact hybrid asset address encoding, wallet ownership and
coin selection, anchor funding and refresh, restricted/qualifier address
identity and indexes, same-block and mempool-parent creation heights, all
asset-class vectors, miner and mempool equivalence, BIP9 reorgs, and migration
of existing holdings. Reusing bit 12 would change the meaning of an already
active deployment on testnet/regtest and is excluded from this candidate.
