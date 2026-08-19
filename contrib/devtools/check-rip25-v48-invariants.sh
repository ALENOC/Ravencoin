#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "RIP-25/v4.8 invariant failure: $*" >&2
  exit 1
}

require_fixed() {
  local needle="$1" file="$2" label="$3"
  grep -Fq -- "$needle" "$file" || fail "$label ($file)"
}

reject_fixed() {
  local needle="$1" file="$2" label="$3"
  if grep -Fq -- "$needle" "$file"; then
    fail "$label ($file)"
  fi
}

# Ravencoin Core 4.8.0 exploit/overflow protections must survive the RIP-25 port.
require_fixed 'consensus.nHeightHeaderCheckActivation = 4487776;' src/chainparams.cpp 'missing v4.8 header-height activation'
require_fixed 'DEPLOYMENT_TRANSFER_OVERFLOW].bit = 11' src/chainparams.cpp 'transfer-overflow must remain on BIP9 bit 11'
require_fixed '4487775, uint256S("0x000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd")' src/chainparams.cpp 'missing v4.8 checkpoint 4,487,775'
require_fixed 'bad-blk-height' src/validation.cpp 'missing v4.8 forged-header-height rejection'
require_fixed 'IsTransferOverflowCheckDeployed' src/consensus/tx_verify.cpp 'missing v4.8 transfer-overflow enforcement'

# RIP-25 deployment must not collide with the v4.8 overflow deployment.
require_fixed 'DEPLOYMENT_PQ_HYBRID].bit = 12' src/chainparams.cpp 'RIP-25 must use BIP9 bit 12'
require_fixed '"transfer_overflow"' src/versionbits.cpp 'missing transfer_overflow VersionBits metadata'
require_fixed '"pq_hybrid"' src/versionbits.cpp 'missing pq_hybrid VersionBits metadata'
require_fixed 'bit:                                    12' doc/RIP-0025-PQ-Signatures.md 'RIP-25 specification still advertises the pre-v4.8 signaling bit'

# TronBlack-approved RIP-25 resource policy is invariant: 8 -> 12 -> 16 MWU and 8x PQ witness discount.
require_fixed 'MAX_BLOCK_WEIGHT_RIP2 = 8000000' src/consensus/consensus.h 'RIP-2 8 MWU baseline changed'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE1 = 12000000' src/consensus/consensus.h 'RIP-25 phase 1 must remain 12 MWU'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE2 = 16000000' src/consensus/consensus.h 'RIP-25 phase 2 must remain 16 MWU'
require_fixed 'PQ_WITNESS_SCALE_FACTOR = 8' src/consensus/consensus.h 'RIP-25 PQ witness discount must remain 8x'
require_fixed 'GetBlockWeightRIP25' src/consensus/validation.h 'missing RIP-25 block-weight accounting'

# Activation/reorg safety: no translation-unit/global mutable PQ activation cache.
reject_fixed 'fPQHybridIsActive' src/consensus/consensus.h 'forbidden static PQ activation state'
reject_fixed 'SetPQHybridBlockLimitsActive' src/consensus/consensus.h 'forbidden mutable block-limit state'

# These markers are deliberately required from the final contextual validation merge.
# The gate MUST stay red until validation.cpp uses pindexPrev/VersionBits for both
# script activation and phased block resource limits.
require_fixed 'IsPQWitnessDiscountActive' src/validation.cpp 'missing contextual RIP-25 activation helper'
require_fixed 'GetMaxBlockWeightForPrev' src/validation.cpp 'missing contextual 8/12/16 block-weight helper'
require_fixed 'VersionBitsStateSinceHeight' src/validation.cpp 'missing deterministic phase-2 boundary'
require_fixed 'SCRIPT_VERIFY_PQ_HYBRID' src/validation.cpp 'missing consensus/mempool PQ script gate'

# Policy must not enforce witness-v2 unconditionally before BIP9 activation.
if grep -A30 'STANDARD_SCRIPT_VERIFY_FLAGS' src/policy/policy.h | grep -Fq 'SCRIPT_VERIFY_PQ_HYBRID'; then
  fail 'SCRIPT_VERIFY_PQ_HYBRID must not be unconditional in STANDARD_SCRIPT_VERIFY_FLAGS'
fi

# liboqs must be a first-class build dependency, not an ad-hoc CI linker flag.
require_fixed 'AC_ARG_WITH([liboqs]' configure.ac 'missing --with-liboqs configure option'
require_fixed 'liboqs >= 0.12.0' configure.ac 'configure must require the pinned liboqs API baseline'
require_fixed 'AC_SUBST(LIBOQS_LIBS)' configure.ac 'LIBOQS_LIBS is not exported by configure'
require_fixed 'AC_SUBST(LIBOQS_CFLAGS)' configure.ac 'LIBOQS_CFLAGS is not exported by configure'
require_fixed 'liboqs' depends/packages/packages.mk 'liboqs missing from depends package graph'

if ! grep -A4 'libravenconsensus_la_LIBADD' src/Makefile.am | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'libravenconsensus must link LIBOQS_LIBS'
fi
if ! grep -A6 'qt_raven_qt_LDADD' src/Makefile.qt.include | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'raven-qt must link LIBOQS_LIBS'
fi

# Security regressions must actually be part of the test binary after staging.
require_fixed 'test/rip25_versionbits_tests.cpp' src/Makefile.test.include 'RIP-25 VersionBits regression suite is not wired'
require_fixed 'test/kawpow_v48_hardening_tests.cpp' src/Makefile.test.include 'v4.8 KAWPOW exploit regression suite is not wired'

echo 'RIP-25 / Ravencoin 4.8 invariants: OK'
