#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(path, old, new, label):
    p = Path(path)
    s = p.read_text()
    if new in s:
        return
    if old not in s:
        raise SystemExit(f"{path}: cannot locate {label}")
    if s.count(old) != 1:
        raise SystemExit(f"{path}: non-unique {label}: {s.count(old)}")
    p.write_text(s.replace(old, new, 1))


# RVN-GLM-002: keep the approved unknown-witness pre-activation consensus
# semantics, but upgraded policy must not relay/mine new unprotected v2 outputs.
p = Path("src/validation.cpp")
s = p.read_text()
anchor = '''    if (!gArgs.GetBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
'''
replacement = '''    if (!gArgs.GetBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // RIP-25: before BIP9 activation witness-v2 is deliberately an unknown
    // witness program to legacy consensus. Upgraded policy must not relay or
    // mine newly-created v2 outputs until ML-DSA enforcement is ACTIVE.
    if (!pqEnabled) {
        for (const CTxOut& txout : tx.vout) {
            int witnessVersion = -1;
            std::vector<unsigned char> witnessProgram;
            if (txout.scriptPubKey.IsWitnessProgram(witnessVersion, witnessProgram) &&
                witnessVersion == 2 && witnessProgram.size() == 32) {
                return state.DoS(0, false, REJECT_NONSTANDARD, "premature-pq-witness", true);
            }
        }
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
'''
if "premature-pq-witness" not in s:
    if anchor not in s:
        raise SystemExit("src/validation.cpp: pre-activation policy insertion point missing")
    p.write_text(s.replace(anchor, replacement, 1))

replace_once(
    "src/policy/policy.cpp",
    "        return true; // RIP-25: PQ witness v2 outputs are always standard when solved",
    "        return true; // RIP-25: structurally standard; activation relay policy is enforced in validation.cpp",
    "witness-v2 policy comment",
)

# Wallet HIGH: encrypted PQ secrets must never fall through to plaintext pqkey.
replace_once(
    "src/wallet/wallet.cpp",
    '''    uint256 witnessProgram = pubkey.GetWitnessProgram();
    std::vector<unsigned char> keyData(key.GetKeyData().begin(), key.GetKeyData().end());
    return CWalletDB(*dbw).WritePQKey(witnessProgram, pubkey, keyData);
}''',
    '''    // CCryptoKeyStore::AddPQKeyPubKey routes encrypted+unlocked wallets
    // through virtual AddCryptedPQKey(), which already persists ciphertext.
    if (IsCrypted())
        return true;

    uint256 witnessProgram = pubkey.GetWitnessProgram();
    std::vector<unsigned char> keyData(key.GetKeyData().begin(), key.GetKeyData().end());
    return CWalletDB(*dbw).WritePQKey(witnessProgram, pubkey, keyData);
}''',
    "encrypted PQ wallet persistence guard",
)

# liboqs HIGH: compile-time final-FIPS-204 version guard in addition to configure.
replace_once(
    "src/crypto/mldsa.cpp",
    "#include <oqs/oqs.h>\n",
    '''#include <oqs/oqs.h>

#if !defined(OQS_VERSION_MAJOR) || !defined(OQS_VERSION_MINOR) || \
    (OQS_VERSION_MAJOR == 0 && OQS_VERSION_MINOR < 12)
#error "RIP-25 requires liboqs >= 0.12.0 (final FIPS 204 ML-DSA)"
#endif
''',
    "liboqs compile-time version guard",
)

# liboqs HIGH: remove unversioned direct-library fallback. A consensus build must
# prove >=0.12.0 through pkg-config; the pinned depends package is exactly 0.12.0.
p = Path("configure.ac")
s = p.read_text()
old_pkg = '''        PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.12.0],
          [AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
          [
            dnl Fallback: check for header and library directly
            AC_CHECK_HEADER([oqs/oqs.h],
              [AC_CHECK_LIB([oqs], [OQS_SIG_new],
                [LIBOQS_LIBS=-loqs; AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
                [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs library not found])])],
              [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs headers not found])])
          ])'''
new_pkg = '''        PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.12.0],
          [AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
          [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0 discoverable via pkg-config; refusing an unversioned system-library fallback])])'''
if new_pkg not in s:
    if old_pkg not in s:
        raise SystemExit("configure.ac: versionless pkg-config fallback block missing")
    s = s.replace(old_pkg, new_pkg, 1)

old_nopkg = '''  dnl RIP-25: liboqs fallback check (non-pkg-config path)
  if test "x$use_liboqs" = "xyes"; then
    AC_CHECK_HEADER([oqs/oqs.h],
      [AC_CHECK_LIB([oqs], [OQS_SIG_new],
        [LIBOQS_LIBS=-loqs; AC_DEFINE([HAVE_LIBOQS], [1], [Define to 1 if liboqs is available])],
        [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs library not found])])],
      [AC_MSG_ERROR([RIP-25 requires liboqs >= 0.12.0; liboqs headers not found])])
    AC_SUBST(LIBOQS_LIBS)
    AC_SUBST(LIBOQS_CFLAGS)
  fi'''
new_nopkg = '''  dnl RIP-25: consensus-critical ML-DSA requires a version-proven liboqs.
  if test "x$use_liboqs" = "xyes"; then
    AC_MSG_ERROR([RIP-25 requires pkg-config so liboqs >= 0.12.0 can be version-verified; unversioned fallback linkage is forbidden])
  fi'''
if new_nopkg not in s:
    if old_nopkg not in s:
        raise SystemExit("configure.ac: non-pkg-config liboqs fallback block missing")
    s = s.replace(old_nopkg, new_nopkg, 1)
p.write_text(s)

# Dedicated security suites existed but were not linked into make check.
p = Path("src/Makefile.test.include")
s = p.read_text()
if "test/kawpow_v48_hardening_tests.cpp" not in s:
    s = s.replace("  test/kawpow_tests.cpp \\\n", "  test/kawpow_tests.cpp \\\n  test/kawpow_v48_hardening_tests.cpp \\\n", 1)
if "test/rip25_versionbits_tests.cpp" not in s:
    s = s.replace("  test/versionbits_tests.cpp \\\n", "  test/versionbits_tests.cpp \\\n  test/rip25_versionbits_tests.cpp \\\n", 1)
p.write_text(s)

# Preserve the approved architecture verbatim; correct only terminology around
# the approved 8 -> 12 -> 16 MWU consensus-capacity increase.
replace_once(
    "doc/RIP-0025-PQ-Signatures.md",
    "The upgrade is deployed as a **soft fork** following the SegWit extensibility model. A phased block weight increase from 8 MWU to 16 MWU, combined with a PQ witness discount factor, ensures that network throughput remains adequate during and after migration.",
    "Witness-v2 ML-DSA enforcement is activated through **BIP9** following the SegWit extensibility model. The separately approved phased block-weight expansion (8 -> 12 -> 16 MWU) and 8x PQ witness discount are preserved unchanged; because the higher limits relax block validity relative to legacy 8-MWU nodes, deployment of those phases requires coordinated network adoption. This clarification changes no RIP-25 consensus parameter.",
    "RIP-25 deployment terminology",
)
replace_once(
    "src/chainparams.cpp",
    "// RIP-25: Post-Quantum Hybrid Signatures (ECDSA + ML-DSA-44)",
    "// RIP-25: ML-DSA-44 witness-v2 deployment (historical DEPLOYMENT_PQ_HYBRID enum name retained)",
    "stale hybrid-signature comment",
)

# CI structural CRITICAL: test the committed source tree directly. The legacy
# step id remains only so status reporting does not need risky expression edits.
p = Path(".github/workflows/rip25-v48-final-gate.yml")
s = p.read_text()
if "      - fix/rip25-v48-glm-remediation\n" not in s:
    s = s.replace(
        "      - integration/rip25-v4.8.0\n  workflow_dispatch:\n",
        "      - integration/rip25-v4.8.0\n      - fix/rip25-v48-glm-remediation\n  pull_request:\n    branches:\n      - integration/rip25-v4.8.0\n  workflow_dispatch:\n",
        1,
    )
materializer = re.compile(
    r"\n      - id: materialize\n"
    r"        name: Materialize audited RIP-25 port\n"
    r"(?:        shell: bash\n)?"
    r"        run: \|\n"
    r"          chmod \+x contrib/devtools/apply-rip25-v48-port-v4\.sh\n"
    r"          \./contrib/devtools/apply-rip25-v48-port-v4\.sh\n"
)
source_step = '''
      - id: materialize
        name: Verify committed RIP-25 source tree is pristine
        shell: bash
        run: |
          set -euo pipefail
          git diff --exit-code
          git diff --cached --exit-code
          test -z "$(git status --porcelain)"
'''
s, count = materializer.subn(source_step, s)
if count not in (0, 2):
    raise SystemExit(f"final gate: expected 2 materializer steps or already-remediated 0, got {count}")
if "Materialize audited RIP-25 port" in s or "./contrib/devtools/apply-rip25-v48-port-v4.sh" in s:
    raise SystemExit("final gate still mutates source before testing")
s = s.replace("uses: actions/checkout@v4", "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
s = s.replace("            \"materialize:$MATERIALIZE\" \\\n", "            \"source-integrity:$MATERIALIZE\" \\\n")
p.write_text(s)

# Pin third-party actions in the legacy/manual build workflow.
p = Path(".github/workflows/build-raven.yml")
s = p.read_text()
s = s.replace("uses: fkirc/skip-duplicate-actions@master", "uses: fkirc/skip-duplicate-actions@a09bf677ad5e5dedb31a42070b6a180fde0ab6ce")
s = re.sub(r"uses: actions/checkout@v[0-9]+", "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", s)
s = s.replace("uses: actions/cache@v4", "uses: actions/cache@3edfce9056124e459a23f683a21433670d47daca")
s = s.replace("uses: actions/upload-artifact@master", "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a")
s = s.replace("name: Build Evrmore", "name: Build Ravencoin")
if "\npermissions:\n" not in s:
    s = s.replace("\nenv:\n", "\npermissions:\n  contents: read\n\nenv:\n", 1)
p.write_text(s)

# Extend invariant gate to prevent recurrence of the GLM findings.
p = Path("contrib/devtools/check-rip25-v48-invariants.sh")
s = p.read_text()
marker = "echo 'RIP-25/v4.8 invariants: OK'"
extra = r'''
# GLM remediation invariants: the exact committed source must be release-ready.
require_fixed 'premature-pq-witness' src/validation.cpp 'pre-activation PQ output relay gate missing'
require_fixed 'OQS_VERSION_MINOR' src/crypto/mldsa.cpp 'compile-time liboqs >=0.12 gate missing'
require_fixed 'refusing an unversioned system-library fallback' configure.ac 'configure still permits unversioned liboqs fallback'
reject_fixed 'AC_CHECK_LIB([oqs], [OQS_SIG_new]' configure.ac 'unversioned liboqs direct-link fallback remains'
require_fixed 'if (IsCrypted())' src/wallet/wallet.cpp 'encrypted PQ wallet path can fall through to plaintext WritePQKey'
require_fixed 'test/rip25_versionbits_tests.cpp' src/Makefile.test.include 'RIP-25 versionbits tests are not wired into make check'
require_fixed 'test/kawpow_v48_hardening_tests.cpp' src/Makefile.test.include '4.8 KAWPOW hardening tests are not wired into make check'
reject_fixed 'Materialize audited RIP-25 port' .github/workflows/rip25-v48-final-gate.yml 'CI still materializes a different source tree'
reject_fixed './contrib/devtools/apply-rip25-v48-port-v4.sh' .github/workflows/rip25-v48-final-gate.yml 'CI still executes the source materializer'
require_fixed 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' .github/workflows/rip25-v48-final-gate.yml 'security checkout action is not immutable-pinned'
'''
if "pre-activation PQ output relay gate missing" not in s:
    if marker not in s:
        raise SystemExit("invariant checker terminal marker missing")
    s = s.replace(marker, extra + "\n" + marker, 1)
p.write_text(s)
