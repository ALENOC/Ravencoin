# Raven Core 4.8.1 release notes (draft)

Status: release qualification in progress. These notes are for review and
must be updated with the final source SHA, artifact checksums, and release
date before publication.

## Upgrade before bit 12 activates

RIP-25 adds ML-DSA-44 signatures for native RVN witness-v2 outputs. The
same activation changes the block limit from 8 to 12 million weight units
(MWU) and applies a contextual discount to PQ witness data. Core 4.8.0
can reject blocks accepted by upgraded nodes after activation. This is an
incompatible consensus upgrade. Miners, pools, full nodes, exchanges,
custodians, explorers, and other validating services must install a
qualified 4.8.1 release before bit 12 becomes ACTIVE. A miner's signal
does not upgrade any other validator.

Back up wallets, stop the old node cleanly, install the release artifact
for the platform, verify its published checksum, and allow the upgraded
node to synchronize. Before relying on it for validation, confirm the
running version and inspect `getblockchaininfo.bip9_softforks.pq_hybrid`.
Do not downgrade a validator to Core 4.8.0 after bit 12 is ACTIVE: it may
follow a different chain once a newly allowed block appears.

## Mainnet signaling and block limits

| Rule | Value |
|------|-------|
| Bit 12 STARTED threshold | Median time past reaches 2027-07-01 00:00 UTC (1814400000) at a window boundary |
| Timeout | 2029-01-01 00:00 UTC (1861920000), 18 months after start |
| Signaling threshold | At least 1714 of 2016 blocks in one STARTED window |
| Lock-in | One complete LOCKED_IN window follows a successful signaling window |
| Activation | ACTIVE begins at the following window boundary, at height `H12` |
| Block limit at `H12` | 12 MWU, with the contextual PQ witness discount |
| Later block limit | 16 MWU at `H12 + 525600` blocks, one nominal year at the 60-second target spacing |

The start timestamp is not the date when the new rules take effect. BIP9
uses chain median time past and full 2016-block windows. If the timeout
is reached before lock-in, bit 12 fails and these rules do not activate
through this deployment. The 16 MWU phase is height-based, not tied to
a calendar date. There is no automatic return to Core 4.8.0 validation
rules after activation.

Testnet differs from this mainnet schedule. Its native RIP-25 rule is
force-enabled from genesis by `nPQHybridEnabled=true`. At the reviewed
2026-10-14 testnet tip, `getblocktemplate` therefore advertises the later
16 MWU limit, even while the raw bit-12 BIP9 state reads STARTED. This
does not imply that mainnet has activated bit 12. The testnet override
cannot demonstrate the public 8-to-12-MWU BIP9 transition; controlled
regtest boundary tests cover that transition. Testnet miners and node
operators should account for the already active PQ and block-weight
rules when comparing with Core 4.8.0.

Before miners begin signaling, the complete shared testnet history must
be checked against the network-bound ML-DSA rule, the old and new binaries
must be retested on both sides of the 8 MWU boundary, and the final 4.8.1
SHA must pass mandatory `make check`, Final Gate, and all five Build Raven
targets. Operators must have time to upgrade before ACTIVE. If these
conditions are not met before STARTED, a reviewed release must move the
start and timeout before the original window begins.

## Migration to PQ custody

Native RVN in historical classical outputs remains spendable with the
existing signature. Owners migrate voluntarily by generating a witness-v2
PQ address with `getnewpqaddress` and sending RVN to it. Its later spend
uses ML-DSA-44 without an ECDSA signature. Existing classical outputs
are not converted by activation.

The separate bit-13 mainnet deployment is scheduled to start no earlier
than 2029-01-01 00:00 UTC by median time past, with a 1714/2016 threshold
and 2030-07-01 timeout. It cannot enforce its PQ-only asset rule until
bit 12 and the transfer-script deployment on bit 8 are ACTIVE. Once all
three deployments are ACTIVE, newly created asset and owner-token outputs
use the PQ asset format: spending requires a matching native RVN
witness-v2 input signed with ML-DSA-44 and no classical asset signature.
Historical asset and owner-token outputs retain their classical spending
condition until their owners move them to new protected outputs. Activation
does not retroactively protect them. If bit 12 fails or activates too late,
the bit-13 window must be reviewed before it starts.

There is no automatic network-wide point at which only PQ keys can spend
all existing holdings. Each owner reaches PQ-only custody after moving every
historical RVN, asset, and owner-token UTXO they hold. Unmigrated historical
outputs remain spendable with their original classical keys.

For the asset format, wallet recovery routes, and current limitations in
automatic anchor refresh and raw transaction funding, see
[RIP-25 PQ Asset Extension Design Note](../RIP-0025-PQ-Assets-Followup.md).

## Known asset limitations

An asset PQ anchor is native RVN at the protected output's matching PQ
address. Some asset spends and ordinary RVN payments consume the last
anchor without creating a replacement. Exact-fee, dust, multiple-program,
and explicit native-change cases need the owner to fund the matching PQ
address again before the next protected asset spend. The asset output
remains unspent; consensus rejects a spend without its anchor.

`fundrawtransaction` does not discover or select anchors for protected
asset inputs. Raw transaction callers must supply matching funded PQ
inputs and check the final transaction before broadcast.

## Release qualification still required

The available testnet active chain was replayed from genesis by a clean
4.8.1 candidate with `-assumevalid=0`, then synchronized with public
peers; the exact snapshot and limits are in the remediation register.
The scanned chain contained no native witness-v2 outputs or spends, so
the replay checks historical compatibility rather than an on-chain PQ
signature. It does not test unknown side branches or future bit-13
activation.
CRITICAL FINDING-104 through FINDING-107 remain open for release
qualification because their mined activation and side-branch regression
matrix is incomplete. FINDING-112 remains open for intermittent wallet
test-gate diagnosis. Final-SHA artifacts, operator readiness, manual
GUI checks, checksums, and signatures still require qualification.
The release will be tagged and published only after those checks and
the owner's separate release approval.
