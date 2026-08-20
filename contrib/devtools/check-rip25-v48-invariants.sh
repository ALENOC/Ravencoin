#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "RIP-25/v4.8 invariant failure: $*" >&2
  exit 1
}

require_fixed() {
  local needle="$1" file="$2" message="$3"
  grep -Fq -- "$needle" "$file" || fail "$message"
}

reject_fixed() {
  local needle="$1" file="$2" message="$3"
  if grep -Fq -- "$needle" "$file"; then fail "$message"; fi
}

# Ravencoin 4.8 exploit/overflow invariants.
require_fixed 'nHeightHeaderCheckActivation = 4487776' src/chainparams.cpp '4.8 KAWPOW header-height activation missing'
require_fixed '4487775' src/chainparams.cpp '4.8 checkpoint height missing'
require_fixed 'DEPLOYMENT_TRANSFER_OVERFLOW' src/consensus/params.h '4.8 transfer-overflow deployment missing'
require_fixed 'vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].bit = 11' src/chainparams.cpp 'transfer-overflow must remain on BIP9 bit 11'
require_fixed 'if (nHeight >= consensusParams.nHeightHeaderCheckActivation &&' src/validation.cpp '4.8 KAWPOW height gate predicate missing'
require_fixed 'block.nTime >= nKAWPOWActivationTime &&' src/validation.cpp '4.8 KAWPOW time gate predicate missing'
require_fixed 'block.nHeight != (uint32_t)nHeight)' src/validation.cpp '4.8 declared-vs-contextual height comparison missing'
require_fixed 'REJECT_INVALID, "bad-blk-height"' src/validation.cpp '4.8 KAWPOW bad-blk-height rejection missing'
require_fixed 'IsTransferOverflowCheckDeployed' src/validation.cpp '4.8 transfer-overflow validation gate missing'

# RIP-25 approved consensus invariants.
require_fixed 'vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].bit = 12' src/chainparams.cpp 'PQ deployment must use BIP9 bit 12'
require_fixed '  bit:                                    12' doc/RIP-0025-PQ-Signatures.md 'RIP-25 specification must document BIP9 bit 12 after the v4.8 port'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE1 = 12000000' src/consensus/consensus.h 'RIP-25 phase-1 must remain 12 MWU'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE2 = 16000000' src/consensus/consensus.h 'RIP-25 phase-2 must remain 16 MWU'
require_fixed 'PQ_WITNESS_SCALE_FACTOR = 8' src/consensus/consensus.h 'approved PQ witness discount must remain 8x'
reject_fixed 'fPQHybridIsActive' src/consensus/consensus.h 'forbidden mutable/static PQ activation state'
reject_fixed 'SetPQHybridBlockLimitsActive' src/consensus/consensus.h 'forbidden mutable block-limit state'

# Contextual, reorg-safe activation/resource enforcement.
require_fixed 'IsPQHybridActiveLocked' src/validation.cpp 'missing contextual RIP-25 activation helper'
require_fixed 'IsPQWitnessDiscountActive' src/validation.cpp 'missing contextual RIP-25 discount activation helper'
require_fixed 'GetMaxBlockWeightForPrev' src/validation.cpp 'missing contextual 8/12/16 block-weight helper'
require_fixed 'VersionBitsStateSinceHeight' src/validation.cpp 'missing deterministic phase-2 boundary'
require_fixed 'SCRIPT_VERIFY_PQ_HYBRID' src/validation.cpp 'missing consensus/mempool PQ script gate'
require_fixed 'IsPQWitnessV2Prevout' src/validation.cpp 'PQ discount is not bound to the spent witness-v2 prevout'
require_fixed 'GetContextualPQWitnessDiscount' src/validation.cpp 'missing UTXO-bound PQ discount calculation'
require_fixed 'GetMaxBlockWeightForPrev(pindexPrev, chainparams.GetConsensus())' src/miner.cpp 'miner is not clamped to the active 8/12/16 MWU consensus phase'

# Policy/wallet activation boundaries.
if grep -A30 'STANDARD_SCRIPT_VERIFY_FLAGS' src/policy/policy.h | grep -Fq 'SCRIPT_VERIFY_PQ_HYBRID'; then
  fail 'SCRIPT_VERIFY_PQ_HYBRID must not be unconditional in STANDARD_SCRIPT_VERIFY_FLAGS'
fi
require_fixed 'NODE_PQ_HYBRID' src/init.cpp 'PQ service capability is not advertised'
require_fixed 'IsPQHybridDeployed()' src/wallet/rpcwallet.cpp 'wallet must check RIP-25 activation before generating witness-v2 addresses'
require_fixed 'refusing to generate an unprotected witness-v2 address' src/wallet/rpcwallet.cpp 'wallet pre-activation safety gate missing'

# liboqs is consensus-critical: pinned/cross-aware and linked by every target.
require_fixed 'liboqs' depends/packages/packages.mk 'liboqs missing from depends package graph'
require_fixed '$(package)_version=0.12.0' depends/packages/liboqs.mk 'liboqs depends version must remain 0.12.0'
require_fixed 'df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08' depends/packages/liboqs.mk 'liboqs checksum changed'
require_fixed '$(package)_build_subdir=build' depends/packages/liboqs.mk 'liboqs must use out-of-tree depends build'
require_fixed '$($(package)_cmake) ..' depends/packages/liboqs.mk 'liboqs must use cross-aware depends CMake wrapper'
require_fixed 'RIP-25 requires liboqs >= 0.12.0' configure.ac 'configure must fail closed on liboqs < 0.12.0 or disabled'
require_fixed '--without-liboqs is not supported' configure.ac 'configure must reject disabling consensus-critical liboqs'
require_fixed 'liboqs >= 0.12.0' configure.ac 'configure must require liboqs >= 0.12.0'
require_fixed 'AC_SUBST(LIBOQS_LIBS)' configure.ac 'LIBOQS_LIBS not exported by configure'
require_fixed 'AC_SUBST(LIBOQS_CFLAGS)' configure.ac 'LIBOQS_CFLAGS not exported by configure'

if ! grep -A4 'libravenconsensus_la_LIBADD' src/Makefile.am | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'libravenconsensus must link LIBOQS_LIBS'
fi
if ! grep -A8 'qt_raven_qt_LDADD' src/Makefile.qt.include | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'raven-qt must link LIBOQS_LIBS'
fi

echo 'RIP-25/v4.8 invariants: OK'
