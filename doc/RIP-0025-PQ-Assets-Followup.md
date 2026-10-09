# RIP-25 PQ Asset Extension Design Note

Status: dormant bit 13 consensus candidate for the 4.8.1 working branch.
Default public-network parameters do not activate it. Wallet construction
and recovery paths have local tests; public activation and release
qualification remain open.

## 1. Current Scope

On the default public-network parameters, RIP-25 witness-v2 protects native RVN outputs only. No current Ravencoin asset class is yet qualified for issuance, custody, transfer, reissue, tagging, freezing, or spending under an ML-DSA-44 ownership condition. The 4.8.1 candidate assigns a separate, dormant bit 13 for a dependent asset rule and exercises it on regtest. That candidate is not a deployed public-network protection or a release-qualified feature.

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

Wallet and RPC messages must not imply that a native-RVN PQ address alone
protects asset owner or administrator tokens. The asset builder rejects
that bare address and, at active bit 13, requires a canonical
classical|PQ asset descriptor.

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

The wallet uses a distinct composite PQ asset destination rather than
reusing a native-RVN address without a defined asset meaning.

The working branch defines a wallet-facing, network-bound descriptor of
the form `<classical-P2PKH-address>|<PQ-witness-v2-address>`. Its decoder
requires exactly one separator, the expected destination types, and exact
canonical re-encoding on the selected network. The descriptor is not a
consensus script and not a native RVN payment address. At active bit 13,
the wallet uses it for root, subasset, unique, restricted, qualifier,
reissue, transfer, and administrative outputs. The raw asset constructor
accepts it for corresponding output forms. `getnewpqassetaddress` generates
both keys only after the dependent rule is active, persists the pairing,
and `listpqassetaddresses` retrieves owned pairs after reload and validated
key-only salvage. A single Bech32m address cannot be used
for the two independent keys without defining a new encoding and changing
the existing address-length assumptions. The descriptor is split before
restricted-asset verifier or qualifier-index lookups: those indexes remain
keyed by the classical address. The wallet selects a matching funded native
PQ anchor and returns protected asset change or owner authority. For one
consumed program, ordinary positive native change can refresh the anchor at
the same PQ address. Exact-fee, dust, multiple-program, or explicit native
change can omit that refresh. Ordinary RVN payments can also consume an
anchor without spending the asset. In either case the holder must send native
RVN to the affected PQ address before another protected spend. Raw callers
must provide matching funded native anchor inputs themselves. The local
full-chain suite covers representative operations for every named class,
nontrivial restricted verification, encrypted backup recovery, and GUI
compilation; it does not certify public deployment.

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

Asset indexes currently derive an address identity from legacy 20-byte data. A PQ program is 32 bytes. The current candidate still indexes protected outputs under their classical address. `listaddressesbyasset` and `listassetbalancesbyaddress` therefore aggregate distinct PQ programs that share one classical key. Their classical address value is accounting data, not a complete protected destination. The follow-up design must version index keys or otherwise prevent truncation and type confusion.

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

Existing `ASSET!` outputs cannot become quantum-resistant merely because RIP-25 activates. The current candidate permits a normal legacy-authorized transfer of a historical asset or owner-token UTXO into a new tagged output. The old input remains under its creation-height rules; the new output must meet the active bit-13 rule. A migration mechanism must prove current authorization while moving control to a PQ asset condition.

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
address alone is not a hybrid asset destination. The candidate has passed
local unit, functional, invariant, and Qt compilation checks but is not
qualified for public-network activation or a 4.8.1 asset-PQ release claim.
Cross-platform exact-SHA CI, release artifacts, a second independent audit,
and an explicit protocol-owner activation decision remain required.

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
activation it still needs a documented, fail-safe anchor funding policy, cross-platform
exact-SHA qualification, independent review, and an explicit migration and
activation decision. The wallet now has tested protected owner returns,
asset change, restricted-address checks, and representative all-class
vectors. Bit 13 timing must not be enabled without protocol-owner review.

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
program requires a different anchor input. The wallet selects a funded
matching anchor and signs it. A newly received asset output does not itself
fund its matching native anchor: the recipient must send RVN to the
descriptor's PQ address. A single-program spend can refresh that anchor
from ordinary native change, but the edge cases listed in Section 7 still
require manual top-up. Bit 13 is assigned but dormant.

## 15. 4.8.1 Integration Candidate and Release Gate

The 4.8.1 integration request expands RIP-25 to assets. The native-RVN
implementation and its bit 12 deployment remain unchanged. This section
records the dormant bit 13 consensus candidate, not a public-network rule
already in force or a release-qualified feature.

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

The following remain release-blocking before assigning public-network
activation times or publishing a 4.8.1 artifact as asset-PQ-qualified:
independent protocol review of the hybrid address and anchor construction,
the manual-funding and refresh policy, exact-SHA cross-platform CI and
artifacts, miner and mempool equivalence, BIP9 reorg evidence, and an
operator-visible migration plan for existing owner and administrative
holdings. The local tests cover ownership, selection, output classes,
restricted indexes, same-block and mempool-parent heights, and reorgs, but
do not replace independent deployment review. Reusing bit 12 would change
the meaning of an already active deployment on testnet/regtest and is
excluded from this candidate.

## 16. Proposed Operator Activation Sequence

This is a sequence for review, not a scheduled public-network activation.
The default public-network bit-13 start and timeout values remain dormant.

1. Deploy and review the native RIP-25 bit-12 implementation. Its BIP9
   transition enables witness-v2 ML-DSA-44 script validation, the 12 MWU
   first block-weight phase, and the contextual 8x witness discount.
   The 16 MWU phase follows the specified later height. Existing RVN
   outputs remain classically spendable until their owners transfer them
   to native witness-v2 addresses.
2. Keep the historical transfer-script deployment on bit 8 effective.
   The proposed bit-13 asset rule also requires bit 12; its effective
   height `H` is the maximum of the three activation heights. Tests must
   cover the `H-2` through `H+2` boundary, restart, invalidate/reconsider,
   and reorgs across BIP9 `LOCKED_IN` and `ACTIVE`.
3. Before assigning public bit-13 parameters, obtain an independent
   consensus and wallet review, reproducible cross-platform builds, and
   a migration communication plan. Updating software without a network
   deployment does not protect assets.
4. At or after `H`, newly created spendable asset outputs of every class,
   including `ASSET!` owner authority, must carry the canonical PQ program.
   A spend of such an output requires its classical signature and a native
   witness-v2 input with the matching program and valid network-context
   ML-DSA-44 signature. The asset itself is not a witness program.
5. Holders of older asset and owner-token outputs must explicitly transfer
   them into tagged outputs with their existing classical authorization.
   They should obtain a canonical classical|PQ descriptor and fund its PQ
   native address with RVN for the first protected spend. There is no
   automatic or retroactive migration, and a compromised classical key
   can race a migration.
6. After each protected asset spend, inspect the native PQ anchor balance.
   Ordinary single-program native change can replenish it, but exact-fee,
   dust, explicit-change, and multiple-program cases may need a manual
   RVN top-up before another spend. Backup and verify both private keys
   and their descriptor association before moving administrative tokens.

## 17. Current Anchor Funding Procedure

This procedure documents FINDING-148, FINDING-150, and FINDING-151 while the
automatic refresh and raw-funding gaps remain open. A protected asset UTXO is
not lost when its native anchor is spent. Consensus still requires a matching
native witness-v2 input for its next spend, and the wallet rejects a protected
spend when it cannot find one. The owner can restore availability by sending
native RVN to the PQ address in the asset's original descriptor. Confirm that
payment, then retry the asset spend. Check every distinct PQ program involved
in a transaction. A payment to a different PQ address cannot authorize it.

The following situations can leave no reusable anchor even when a protected
asset or owner token returns to the wallet:

- an exact-fee or dust remainder with no native change output;
- a spend that consumes assets under multiple PQ programs, since one native
  change output cannot refresh them all;
- an explicit native RVN change destination other than the relevant PQ
  address;
- an ordinary RVN payment that selects the last funded asset anchor.

For a raw protected asset spend, `fundrawtransaction` can add fee funding but
does not discover the required anchors from the asset inputs. Construct it
with these steps:

1. Identify each protected asset outpoint being spent and record its committed
   32-byte PQ program and associated native witness-v2 address.
2. Select at least one funded native witness-v2 UTXO with the same program for
   each distinct protected program. Include those outpoints explicitly in
   the raw transaction's input list beside the asset outpoints.
3. Use a canonical `classical|PQ` descriptor for each new asset output. Add a
   positive, spendable native RVN output back to every PQ address whose last
   anchor is being consumed. Reserve enough RVN for fees and future spends.
4. If using `fundrawtransaction` for the remaining fee, inspect its resulting
   inputs and outputs. It neither supplies a missing matching anchor nor
   guarantees that its change replenishes one. Sign the complete transaction,
   inspect it again, then broadcast it. An unanchored protected spend is
   rejected with `bad-pq-asset-anchor`.

## 18. Interpreting the Current Asset Index

FINDING-153 is an address-index limitation. Two outputs can commit to different
PQ programs while using the same classical P2PKH key. The index reports one
classical-address row and their combined asset balance. The row cannot tell a
spender which PQ anchor or private key a particular outpoint needs.
`listassetbalancesbyaddress` accepts the classical address, not the composite
descriptor. Copying an index row as an active asset recipient fails because a
new output requires the canonical `classical|PQ` descriptor. Use the actual
output's program and the recorded descriptor for custody and transfers;
retain both keys and their association in backups. A descriptor assembled
manually from two owned keys is not necessarily listed by
`listpqassetaddresses`, which lists persisted wallet pairings.

## 19. Migrating Historical Assets and Owner Tokens

FINDING-155 concerns partial movement of a historical asset UTXO. Activation
does not add a PQ program to outputs created earlier. Their classical key can
still authorize a spend, but every spendable asset output newly created after
activation needs a canonical PQ tag. Migrate before the old classical key can
be compromised:

1. Back up the wallet and verify that both keys in each destination descriptor
   can be recovered. Inventory historical asset and `ASSET!` owner-token
   outpoints, including their quantities and classical addresses.
2. For a single legacy asset UTXO, transfer its entire quantity to a new
   canonical `classical|PQ` descriptor. Transfer an owner token's full unit
   the same way. If a source address holds several UTXOs, use explicit
   outpoint selection when exact UTXO control is needed.
3. For a partial transfer through `transferfromaddress` or
   `transferfromaddresses`, supply the canonical descriptor in the final
   `asset_change_address` argument as well as a protected recipient. Without
   it, the wallet rejects the transaction rather than creating classical-only
   asset change. The GUI path has no equivalent explicit asset-change field.
4. Verify that every newly created spendable asset and owner-token output has
   its intended PQ program. Fund each destination's native PQ address with
   RVN before its first protected spend. Keep the original descriptor and
   both private keys available for recovery.

No software can distinguish the rightful owner from an attacker who already
controls the old classical key. Migration does not retroactively protect the
historical UTXO, and a compromised holder can be raced before confirmation.
