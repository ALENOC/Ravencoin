# RIP-25 / Ravencoin Core 4.8.0 integration

This branch is the working integration line for rebasing RIP-25 on the Ravencoin Core 4.8.0 security baseline.

Baseline: `b60f50e04f1fba425b28804e61be2694faaf3469`.

Required consensus merge:
- preserve `DEPLOYMENT_TRANSFER_OVERFLOW` on BIP9 bit 11;
- move `DEPLOYMENT_PQ_HYBRID` from bit 11 to bit 12;
- preserve `nHeightHeaderCheckActivation = 4487776` and the 4.8.0 checkpoint/security logic;
- preserve all RIP-25 witness-v2 / ML-DSA-44 functionality.

The original PR branch `feature/rip25-pq-hybrid` is intentionally left unchanged while this integration is validated.
