# RIP-25 PQ Asset Extension Design Note

Status: dormant bit 13 consensus candidate for the 4.8.1 working branch.
Default public-network parameters do not activate it. Wallet and release
qualification remain open.

## 1. Current Scope

On the default public-network parameters, RIP-25 witness-v2 protects native RVN outputs only. No current Ravencoin asset class is yet qualified for issuance, custody, transfer, reissue, tagging, freezing, or spending under an ML-DSA-44 ownership condition. The 4.8.1 candidate assigns a separate, dormant bit 13 for a dependent asset rule and exercises it on regtest. That candidate is not a deployed public-network protection or a wallet-complete feature.

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

The approved native-RVN RIP-25 rules remain unchanged. The 4.8.1 working
branch includes a dependent, dormant bit 13 asset-consensus candidate. Wallet
asset builders still reject a bare witness-v2 destination, since a native PQ
address alone is not a hybrid asset destination. The candidate is not ready
for public-network activation or a 4.8.1 asset-PQ release claim. An
independent adversarial review and an explicit protocol decision remain
required.

## 13. Experimental Compatibility Direction

The following records the compatibility research behind the dormant bit 13
candidate. It must not be described as protecting assets on the default
public-network parameters.

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

A canonical helper recognizes the narrow envelope and rejects
short/long tails, nonminimal pushes, malformed payloads, and transfer messages
without an explicit expiry field. The dormant bit 13 candidate uses this
helper in consensus only after its effective activation height. An old-valid
script ending in `OP_DROP` plus 31 arbitrary bytes
is byte-identical to a candidate with a 32-byte program beginning `OP_DROP`.
The helper necessarily classifies it as a candidate. The spend rule therefore
checks the creating UTXO's height against the asset extension's
activation height. Applying the rule only at spending height would retroactively
lock historical coins and could split nodes after reorg or reindex.

The proposed new rule would not put an unexpected witness on the asset input.
Instead, the spending transaction would also consume a native RIP-25
witness-v2 UTXO whose program equals the program committed in the asset output.
Its fixed `SIGHASH_ALL` ML-DSA signature commits to every asset input and
output in the same transaction. A quantum attacker with only the P2PKH
private key could not create the required PQ input.

This construction remains a candidate rather than a release-qualified
specification. The 4.8.1 working branch assigns BIP9 bit 13 but leaves its
start and timeout equal and far in the future on every network, so default
nodes do not activate it. Its tested consensus prototype uses the canonical
parser and creation-height gate described below. Before public-network
activation it still needs wallet asset-change and owner-token no-downgrade
paths, anchor funding and refresh, restricted-address checks, all asset-class
vectors, miner and mempool equivalence, and independent review. Bit 13 timing
must not be enabled without protocol-owner review.

## 14. Contextual Enforcement Map (Dormant Candidate)

The candidate's UTXO-aware hook runs in `ConnectBlock` before `UpdateCoins`.
`Consensus::CheckTxPQAssets` requires canonical tagged asset outputs at the
effective height and a matching native witness-v2 input for each distinct
program of a protected asset input. A coin created before the effective
height remains under historical rules, even if its script looks tagged. A
mempool parent has `MEMPOOL_HEIGHT` and is treated as newly created. The same
check runs at mempool admission and after a reorg, with a per-transaction coin
cache to avoid retaining every mempool input in memory.

The block script flags and effective asset height come from the candidate
block's `pindex->pprev`, while mempool policy uses `chainActive.Tip()`.
Effective asset enforcement requires bit 13, the historical bit 8 transfer
parser, and native RIP-25 bit 12 all to be active. Its first enforcement
height is the maximum of their activation heights. This prevents a node
validating a side branch from borrowing the global active tip's state.
The parser's historical `OP_DROP` lookalike requires a creation-height check
against the asset extension activation height, not merely a spend-height
check. Reorgs across activation revalidate affected mempool transactions
through staged removal so asset reissue reservations and compact-block
indexes stay consistent. Reusing the existing RIP-25 bit 12 would be unsafe
because it
would make the newly upgraded nodes enforce a rule older RIP-25 nodes do not.

`CheckTxPQAssets` runs outside the script cache. When it finds an asset input
created after activation, `ConnectBlock` forces both the classical and PQ
script checks even under assumevalid. A native witness-v2 input is verified
under the contextual RIP-25 flag, not by treating the asset envelope itself
as a witness program. `TestBlockValidity` is the miner's final template
check, but template selection and package policy still need boundary tests.

The candidate permits one valid native witness-v2 anchor input to authorize
several protected asset inputs with the identical program. A different
program requires a different anchor input. An output does not itself have to
create a funded anchor, so wallet design must guarantee that the recipient
can obtain and refresh one before a protected spend. This is a release-blocking
funding and usability question. Bit 13 is assigned but dormant.

## 15. 4.8.1 Integration Candidate and Release Gate

The 4.8.1 integration request expands RIP-25 to assets. The native-RVN
implementation and its bit 12 deployment remain unchanged. This section
records the dormant bit 13 consensus candidate, not a public-network rule
already in force or a wallet-complete release feature.

Let `H` be the first candidate-block height at which bit 13, bit 8, and
native RIP-25 bit 12 are all active. A safe soft-fork direction requires both:

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
assigning public-network activation times or publishing a 4.8.1 artifact as
asset-PQ-qualified: exact hybrid asset address encoding, wallet ownership and
coin selection, anchor funding and refresh, restricted/qualifier address
identity and indexes, same-block and mempool-parent creation heights, all
asset-class vectors, miner and mempool equivalence, BIP9 reorgs, and migration
of existing holdings. Reusing bit 12 would change the meaning of an already
active deployment on testnet/regtest and is excluded from this candidate.
