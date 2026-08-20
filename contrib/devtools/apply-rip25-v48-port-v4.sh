#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
patch_dir="contrib/devtools/patches"

apply_exact() {
  local path="$1" pre="$2" post="$3" patch="$4"
  local current
  current="$(git hash-object "$path")"
  if [[ "$current" == "$post" ]]; then
    echo "[rip25-v48] already materialized: $path"
    return 0
  fi
  if [[ "$current" != "$pre" ]]; then
    echo "[rip25-v48] unexpected preimage for $path: $current (expected $pre)" >&2
    exit 1
  fi
  git apply --check "$patch_dir/$patch"
  git apply "$patch_dir/$patch"
  current="$(git hash-object "$path")"
  if [[ "$current" != "$post" ]]; then
    echo "[rip25-v48] postimage mismatch for $path: $current (expected $post)" >&2
    exit 1
  fi
  echo "[rip25-v48] materialized: $path -> $post"
}

# Consensus first. The postimage preserves the original Ravencoin 4.8
# bad-blk-height code while adding reorg-safe BIP9 activation, 8/12/16 MWU,
# and the approved 8x discount bound to real witness-v2 prevouts.
apply_exact src/validation.cpp \
  5f6db7d536d12f1d23e426c8d42287c7a70d759c \
  7ad7ff00aa1753fbc030754357b4404a192f4cb6 \
  rip25-v48-final-validation.patch

# liboqs is consensus-critical. Refuse builds that disable it or provide <0.12.
apply_exact configure.ac \
  7a657d5526f6fa57c5920a123622df54c77e5405 \
  ba2ea6e6bae23553ddb76a54dca1c9f408e367f9 \
  rip25-v48-final-configure.patch

# Miner must construct only blocks valid under the currently active phase.
apply_exact src/miner.cpp \
  d50501f287e269735abec979eb63167b559a2255 \
  2f8a9a509befbb674b541aaf475c4c9409e29459 \
  rip25-v48-final-miner.patch

# Advertise binary capability without changing BIP9 consensus activation.
apply_exact src/init.cpp \
  b3d5ea58568d771bdc9ded808a2bd2118a65ee99 \
  1ec012e076abacf0a02978bd55fe30e02220d026 \
  rip25-v48-final-init.patch

# Wallet policy needs an active-chain query and must not create unprotected
# witness-v2 addresses before RIP-25 is ACTIVE.
apply_exact src/validation.h \
  68bad0a088a443641dbfa6c516d81ee073ab50fd \
  979ec5da5b0708fcae0b1ef444a7264536def9de \
  rip25-v48-final-validation-h.patch
apply_exact src/wallet/rpcwallet.cpp \
  a1997356c100c6b66a9999ab2244f579d2a7d5a9 \
  dcb5bc3e496cbec53c79c63dfc25e2c8d0d3fea7 \
  rip25-v48-final-rpcwallet.patch

# 4.8 owns bit 11 for TRANSFER_OVERFLOW, therefore RIP-25 documentation must
# describe the ported deployment on bit 12. Preserve the approved 8x and
# 8 -> 12 -> 16 MWU design unchanged.
python3 - <<'PY'
from pathlib import Path
p = Path('doc/RIP-0025-PQ-Signatures.md')
s = p.read_text()
old = '  bit:                                    11'
new = '  bit:                                    12'
if old in s:
    if s.count(old) != 1:
        raise SystemExit('RIP-25 spec: unexpected bit-11 occurrence count')
    s = s.replace(old, new, 1)
elif new not in s:
    raise SystemExit('RIP-25 spec: neither expected bit 11 nor bit 12 deployment line found')
p.write_text(s)
PY

# Automake forbids raw linker flags such as -Wl,* in *_LIBADD. Keep the
# winpthread import library in LIBADD for correct link ordering, but use the
# explicit MinGW import-library archive path instead of -Wl,-Bdynamic/-Bstatic.
python3 - <<'PY'
from pathlib import Path
p = Path('src/Makefile.am')
s = p.read_text()
old = 'libravenconsensus_la_LIBADD += -Wl,-Bdynamic -lwinpthread -Wl,-Bstatic'
new = 'libravenconsensus_la_LIBADD += /usr/$(host)/lib/libwinpthread.dll.a'
if old in s:
    s = s.replace(old, new, 1)
elif new not in s:
    raise SystemExit('Makefile.am: expected winpthread LIBADD line not found')
p.write_text(s)
PY

git diff --check
grep -Fq '  bit:                                    12' doc/RIP-0025-PQ-Signatures.md
grep -Fq 'PQ_WITNESS_SCALE_FACTOR = 8' src/consensus/consensus.h
grep -Fq 'MAX_BLOCK_WEIGHT_RIP25_PHASE1 = 12000000' src/consensus/consensus.h
grep -Fq 'MAX_BLOCK_WEIGHT_RIP25_PHASE2 = 16000000' src/consensus/consensus.h
grep -Fq 'libravenconsensus_la_LIBADD += /usr/$(host)/lib/libwinpthread.dll.a' src/Makefile.am
if grep -Fq 'libravenconsensus_la_LIBADD += -Wl,-Bdynamic -lwinpthread -Wl,-Bstatic' src/Makefile.am; then
  echo '[rip25-v48] stale Automake-invalid winpthread LIBADD line remains' >&2
  exit 1
fi

echo '[rip25-v48] final audited port materialized successfully'
