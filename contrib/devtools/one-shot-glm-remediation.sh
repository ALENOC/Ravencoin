#!/usr/bin/env bash
set -euo pipefail

# One-shot remediation for findings from SECURITY_AUDIT_GLM_RIP25_V48.md.
# This script intentionally preserves the approved RIP-25 architecture:
# witness v2 + ML-DSA-44, BIP9, 8x PQ witness discount and 8 -> 12 -> 16 MWU.

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

chmod +x contrib/devtools/apply-rip25-v48-port-v4.sh
./contrib/devtools/apply-rip25-v48-port-v4.sh

python3 - <<'PY'
from pathlib import Path


def replace_once(path, old, new, label):
    p = Path(path)
    s = p.read_text()
    if new in s:
        return
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected one {label}, found {n}")
    p.write_text(s.replace(old, new, 1))

# HIGH: encrypted wallets must never persist the ML-DSA private key in plaintext.
replace_once(
    'src/wallet/wallet.cpp',
    '''    uint256 witnessProgram = pubkey.GetWitnessProgram();
    std::vector<unsigned char> keyData(key.GetKeyData().begin(), key.GetKeyData().end());
    return CWalletDB(*dbw).WritePQKey(witnessProgram, pubkey, keyData);''',
    '''    // CCryptoKeyStore::AddPQKeyPubKey() dispatches encrypted wallets through
    // virtual AddCryptedPQKey(), which has already persisted ciphertext.
    // Do not fall through and write the same ML-DSA secret in plaintext.
    if (IsCrypted())
        return true;

    uint256 witnessProgram = pubkey.GetWitnessProgram();
    std::vector<unsigned char> keyData(key.GetKeyData().begin(), key.GetKeyData().end());
    return CWalletDB(*dbw).WritePQKey(witnessProgram, pubkey, keyData);''',
    'PQ plaintext persistence block')

# HIGH: require version-proven liboqs >=0.12.0. The old AC_CHECK_LIB fallback
# could silently accept pre-FIPS liboqs with size-compatible but incompatible ML-DSA.
p = Path('configure.ac')
s = p.read_text()
old = '''        PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.12.0],
          [AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
          [
            dnl Fallback: check for header and library directly
            AC_CHECK_HEADER([oqs/oqs.h],
              [AC_CHECK_LIB([oqs], [OQS_SIG_new],
                [LIBOQS_LIBS=-loqs; AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
                [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs library not found])])],
              [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs headers not found])])
          ])'''
new = '''        PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.12.0],
          [AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
          [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0 discoverable via pkg-config; refusing an unversioned system-library fallback])])'''
if new not in s:
    if s.count(old) != 1:
        raise SystemExit('configure.ac: versioned liboqs pkg-config block not found exactly once')
    s = s.replace(old, new, 1)

old = '''  dnl RIP-25: liboqs fallback check (non-pkg-config path)
  if test "x$use_liboqs" = "xyes"; then
    AC_CHECK_HEADER([oqs/oqs.h],
      [AC_CHECK_LIB([oqs], [OQS_SIG_new],
        [LIBOQS_LIBS=-loqs; AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
        [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs library not found])])],
      [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs headers not found])])
    AC_SUBST(LIBOQS_LIBS)
    AC_SUBST(LIBOQS_CFLAGS)
  fi'''
new = '''  dnl RIP-25: consensus-critical ML-DSA must have a version-proven liboqs.
  if test "x$use_liboqs" = "xyes"; then
    AC_MSG_ERROR([RIP-25 requires pkg-config so liboqs >= 0.12.0 can be version-verified; unversioned fallback linkage is forbidden])
  fi'''
if new not in s:
    if s.count(old) != 1:
        raise SystemExit('configure.ac: non-pkg-config liboqs fallback not found exactly once')
    s = s.replace(old, new, 1)
p.write_text(s)

# MEDIUM/test-quality: the existing dedicated suites must actually be part of make check.
p = Path('src/Makefile.test.include')
s = p.read_text()
if '  test/rip25_versionbits_tests.cpp \\\n' not in s:
    anchor = '  test/pqkey_hardening_tests.cpp \\\n'
    if s.count(anchor) != 1:
        raise SystemExit('Makefile.test.include: PQ hardening anchor missing')
    s = s.replace(anchor, anchor + '  test/rip25_versionbits_tests.cpp \\\n', 1)
if '  test/kawpow_v48_hardening_tests.cpp \\\n' not in s:
    anchor = '  test/kawpow_tests.cpp \\\n'
    if s.count(anchor) != 1:
        raise SystemExit('Makefile.test.include: KAWPOW anchor missing')
    s = s.replace(anchor, anchor + '  test/kawpow_v48_hardening_tests.cpp \\\n', 1)
p.write_text(s)

# Documentation only: preserve approved 8->12->16 MWU architecture while stating
# accurately that the higher limits require coordinated adoption by legacy nodes.
p = Path('doc/RIP-0025-PQ-Signatures.md')
s = p.read_text()
old = 'The upgrade is deployed as a **soft fork** following the SegWit extensibility model. A phased block weight increase from 8 MWU to 16 MWU, combined with a PQ witness discount factor, ensures that network throughput remains adequate during and after migration.'
new = 'Witness-v2 ML-DSA enforcement is activated through **BIP9** following the SegWit extensibility model. The approved phased block-weight expansion from 8 MWU to 12 MWU and then 16 MWU, together with the 8x PQ witness discount, is preserved unchanged. Because the higher block-weight limits relax validity relative to legacy 8-MWU nodes, those phases require coordinated network adoption. This clarification changes no RIP-25 consensus parameter.'
if new not in s:
    if s.count(old) != 1:
        raise SystemExit('RIP-25 documentation deployment paragraph missing')
    s = s.replace(old, new, 1)
p.write_text(s)

# CRITICAL release-engineering finding: final CI must test the checked-in source,
# never materialize a different consensus tree after checkout.
p = Path('.github/workflows/rip25-v48-final-gate.yml')
s = p.read_text()
if '  pull_request:\n    branches:\n      - integration/rip25-v4.8.0\n' not in s:
    s = s.replace('  workflow_dispatch:\n', '  pull_request:\n    branches:\n      - integration/rip25-v4.8.0\n  workflow_dispatch:\n', 1)
s = s.replace('uses: actions/checkout@v4', 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683')
s = s.replace('''      - id: materialize
        name: Materialize audited RIP-25 port
        run: |
          chmod +x contrib/devtools/apply-rip25-v48-port-v4.sh
          ./contrib/devtools/apply-rip25-v48-port-v4.sh''', '''      - id: materialize
        name: Verify committed RIP-25 source tree is pristine
        run: |
          git diff --exit-code
          test -z "$(git status --porcelain)"''')
s = s.replace('''      - id: materialize
        name: Materialize audited RIP-25 port
        shell: bash
        run: |
          chmod +x contrib/devtools/apply-rip25-v48-port-v4.sh
          ./contrib/devtools/apply-rip25-v48-port-v4.sh''', '''      - id: materialize
        name: Verify committed RIP-25 source tree is pristine
        shell: bash
        run: |
          git diff --exit-code
          test -z "$(git status --porcelain)"''')
if 'apply-rip25-v48-port-v4.sh' in s:
    raise SystemExit('final gate still invokes the materializer')
p.write_text(s)

# Supply-chain hardening for the manual/legacy build workflow; no consensus semantics changed.
p = Path('.github/workflows/build-raven.yml')
s = p.read_text()
s = s.replace('uses: fkirc/skip-duplicate-actions@master', 'uses: fkirc/skip-duplicate-actions@a09bf677ad5e5dedb31a42070b6a180fde0ab6ce')
s = s.replace('uses: actions/checkout@v1', 'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683')
s = s.replace('uses: actions/cache@v4', 'uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684')
s = s.replace('uses: actions/upload-artifact@master', 'uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')
s = s.replace('name: Build Evrmore', 'name: Build Ravencoin')
if '\npermissions:\n' not in s:
    s = s.replace('\nenv:\n', '\npermissions:\n  contents: read\n\nenv:\n', 1)
p.write_text(s)

# Harden the invariant checker so these failures cannot regress silently.
p = Path('contrib/devtools/check-rip25-v48-invariants.sh')
s = p.read_text()
anchor = "require_fixed 'AC_SUBST(LIBOQS_CFLAGS)' configure.ac 'LIBOQS_CFLAGS not exported by configure'\n"
extra = """require_fixed 'refusing an unversioned system-library fallback' configure.ac 'configure must reject unversioned liboqs fallback linkage'\nreject_fixed 'AC_CHECK_LIB([oqs], [OQS_SIG_new]' configure.ac 'unversioned liboqs fallback must not exist'\nrequire_fixed 'if (IsCrypted())' src/wallet/wallet.cpp 'encrypted PQ wallet keys must not fall through to plaintext WritePQKey'\nrequire_fixed 'test/rip25_versionbits_tests.cpp' src/Makefile.test.include 'RIP-25 versionbits tests are not wired into make check'\nrequire_fixed 'test/kawpow_v48_hardening_tests.cpp' src/Makefile.test.include 'v4.8 KAWPOW hardening tests are not wired into make check'\n"""
if extra not in s:
    if s.count(anchor) != 1:
        raise SystemExit('invariant liboqs anchor missing')
    s = s.replace(anchor, anchor + extra, 1)
p.write_text(s)
PY

git diff --check
chmod +x contrib/devtools/check-rip25-v48-invariants.sh
./contrib/devtools/check-rip25-v48-invariants.sh

# Guard against the original GLM-001 release-engineering failure.
! grep -Fq 'apply-rip25-v48-port-v4.sh' .github/workflows/rip25-v48-final-gate.yml

echo 'GLM remediation source pass: OK'
