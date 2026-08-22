#!/usr/bin/env python3
from pathlib import Path


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


# This follow-up runs AFTER one-shot-glm-remediation.sh. That first pass already
# commits the approved RIP-25 materialized postimage and fixes wallet persistence,
# liboqs configure fallback, make-check wiring, docs wording and CI hardening.
# Keep this script intentionally narrow and idempotent.

# RVN-GLM-002 defense-in-depth policy: preserve the approved pre-activation
# unknown-witness consensus semantics, but upgraded nodes must not relay/mine
# newly-created witness-v2 outputs until BIP9 ML-DSA enforcement is ACTIVE.
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

# Make policy.cpp's structural-standardness comment match the contextual relay gate.
p = Path("src/policy/policy.cpp")
s = p.read_text()
old = "        return true; // RIP-25: PQ witness v2 outputs are always standard when solved"
new = "        return true; // RIP-25: structurally standard; activation relay policy is enforced in validation.cpp"
if new not in s:
    if old not in s:
        raise SystemExit("src/policy/policy.cpp: witness-v2 policy comment missing")
    p.write_text(s.replace(old, new, 1))

# RVN-GLM liboqs HIGH defense-in-depth: configure already requires a
# version-proven >=0.12.0 package after the first pass. Also make the compiler
# reject pre-final-FIPS-204 headers even if configure is bypassed.
p = Path("src/crypto/mldsa.cpp")
s = p.read_text()
guard = '''#include <oqs/oqs.h>

#if !defined(OQS_VERSION_MAJOR) || !defined(OQS_VERSION_MINOR) || \
    (OQS_VERSION_MAJOR == 0 && OQS_VERSION_MINOR < 12)
#error "RIP-25 requires liboqs >= 0.12.0 (final FIPS 204 ML-DSA)"
#endif
'''
if "RIP-25 requires liboqs >= 0.12.0 (final FIPS 204 ML-DSA)" not in s:
    if "#include <oqs/oqs.h>\n" not in s:
        raise SystemExit("src/crypto/mldsa.cpp: liboqs include missing")
    p.write_text(s.replace("#include <oqs/oqs.h>\n", guard, 1))

# Terminology only. The historical enum name remains ABI/source compatible;
# architecture and deployment parameters are unchanged.
p = Path("src/chainparams.cpp")
s = p.read_text()
old = "// RIP-25: Post-Quantum Hybrid Signatures (ECDSA + ML-DSA-44)"
new = "// RIP-25: ML-DSA-44 witness-v2 deployment (historical DEPLOYMENT_PQ_HYBRID enum name retained)"
if new not in s:
    if old not in s:
        raise SystemExit("src/chainparams.cpp: RIP-25 deployment comment missing")
    p.write_text(s.replace(old, new, 1))

# Add only source-level recurrence guards here. The first pass already adds
# wallet/liboqs-configure/test-wiring guards. Workflow invariants are published
# separately through the GitHub connector because Actions tokens cannot update
# workflow files.
p = Path("contrib/devtools/check-rip25-v48-invariants.sh")
s = p.read_text()
marker = "echo 'RIP-25/v4.8 invariants: OK'"
extra = r'''
# GLM follow-up source invariants.
require_fixed 'premature-pq-witness' src/validation.cpp 'pre-activation PQ output relay gate missing'
require_fixed 'OQS_VERSION_MINOR' src/crypto/mldsa.cpp 'compile-time liboqs >=0.12 gate missing'
'''
if "pre-activation PQ output relay gate missing" not in s:
    if marker not in s:
        raise SystemExit("invariant checker terminal marker missing")
    p.write_text(s.replace(marker, extra + "\n" + marker, 1))
