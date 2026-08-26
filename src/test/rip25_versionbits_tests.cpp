// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "test/test_raven.h"
#include "validation.h"
#include "versionbits.h"

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

namespace {

class SyntheticVersionBitsChain
{
private:
    CBlockIndex* base;
    std::vector<std::unique_ptr<CBlockIndex>> blocks;

public:
    explicit SyntheticVersionBitsChain(CBlockIndex* baseIn = nullptr) : base(baseIn) {}

    CBlockIndex* Tip() const
    {
        return blocks.empty() ? base : blocks.back().get();
    }

    void Mine(unsigned int count, int32_t version)
    {
        for (unsigned int i = 0; i < count; ++i) {
            auto block = std::make_unique<CBlockIndex>();
            block->pprev = Tip();
            block->nHeight = block->pprev ? block->pprev->nHeight + 1 : 0;
            block->nTime = 100000 + block->nHeight;
            block->nVersion = version;
            block->BuildSkip();
            blocks.emplace_back(std::move(block));
        }
    }
};

Consensus::Params MakeRIP25VersionBitsParams()
{
    Consensus::Params params;
    params.nMinerConfirmationWindow = 4;
    params.nRuleChangeActivationThreshold = 3;

    auto& overflow = params.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW];
    overflow.bit = 11;
    overflow.nStartTime = 0;
    overflow.nTimeout = std::numeric_limits<int64_t>::max();
    overflow.nOverrideRuleChangeActivationThreshold = 3;
    overflow.nOverrideMinerConfirmationWindow = 4;

    auto& pq = params.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID];
    pq.bit = 12;
    pq.nStartTime = 0;
    pq.nTimeout = std::numeric_limits<int64_t>::max();
    pq.nOverrideRuleChangeActivationThreshold = 3;
    pq.nOverrideMinerConfirmationWindow = 4;

    return params;
}

} // namespace

BOOST_AUTO_TEST_SUITE(rip25_versionbits_tests)

BOOST_AUTO_TEST_CASE(pq_bit12_activates_independently_from_v48_overflow_bit11)
{
    Consensus::Params params = MakeRIP25VersionBitsParams();
    VersionBitsCache cache;
    SyntheticVersionBitsChain chain;

    const uint32_t overflowMask = VersionBitsMask(params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW);
    const uint32_t pqMask = VersionBitsMask(params, Consensus::DEPLOYMENT_PQ_HYBRID);

    BOOST_CHECK_EQUAL(overflowMask, (1U << 11));
    BOOST_CHECK_EQUAL(pqMask, (1U << 12));
    BOOST_CHECK_EQUAL(overflowMask & pqMask, 0U);

    // Genesis/first period is DEFINED. After the first four-block period,
    // both deployments enter STARTED because their start time is zero.
    BOOST_CHECK_EQUAL(VersionBitsState(nullptr, params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_DEFINED);
    BOOST_CHECK_EQUAL(VersionBitsState(nullptr, params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_DEFINED);

    chain.Mine(4, VERSIONBITS_TOP_BITS);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_STARTED);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_STARTED);

    // Signal only bit 12 in 3/4 blocks. PQ locks in; the v4.8 overflow
    // deployment remains STARTED. This detects any accidental bit collision.
    chain.Mine(3, VERSIONBITS_TOP_BITS | pqMask);
    chain.Mine(1, VERSIONBITS_TOP_BITS);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_LOCKED_IN);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_STARTED);

    // LOCKED_IN becomes ACTIVE for the next period regardless of further
    // signaling. StateSinceHeight must identify the first ACTIVE block exactly.
    chain.Mine(4, VERSIONBITS_TOP_BITS);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_ACTIVE);
    BOOST_CHECK_EQUAL(VersionBitsStateSinceHeight(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), 12);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_STARTED);
}

BOOST_AUTO_TEST_CASE(overflow_bit11_does_not_signal_pq_bit12)
{
    Consensus::Params params = MakeRIP25VersionBitsParams();
    VersionBitsCache cache;
    SyntheticVersionBitsChain chain;

    const uint32_t overflowMask = VersionBitsMask(params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW);

    chain.Mine(4, VERSIONBITS_TOP_BITS);
    BOOST_REQUIRE_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_STARTED);

    chain.Mine(3, VERSIONBITS_TOP_BITS | overflowMask);
    chain.Mine(1, VERSIONBITS_TOP_BITS);

    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_LOCKED_IN);
    BOOST_CHECK_EQUAL(VersionBitsState(chain.Tip(), params, Consensus::DEPLOYMENT_PQ_HYBRID, cache), THRESHOLD_STARTED);
}

BOOST_AUTO_TEST_CASE(transfer_overflow_state_rewinds_across_forks)
{
    Consensus::Params params = MakeRIP25VersionBitsParams();
    VersionBitsCache cache;
    SyntheticVersionBitsChain common;
    const uint32_t overflowMask = VersionBitsMask(params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW);

    common.Mine(4, VERSIONBITS_TOP_BITS);

    SyntheticVersionBitsChain activeBranch(common.Tip());
    activeBranch.Mine(3, VERSIONBITS_TOP_BITS | overflowMask);
    activeBranch.Mine(1, VERSIONBITS_TOP_BITS);
    activeBranch.Mine(4, VERSIONBITS_TOP_BITS);

    SyntheticVersionBitsChain startedBranch(common.Tip());
    startedBranch.Mine(8, VERSIONBITS_TOP_BITS);

    // Query ACTIVE first using the same cache, then rewind to the alternate
    // STARTED fork.  Activation must be a property of pindexPrev, not history.
    BOOST_REQUIRE_EQUAL(VersionBitsState(activeBranch.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_ACTIVE);
    BOOST_CHECK_EQUAL(VersionBitsState(startedBranch.Tip(), params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW, cache), THRESHOLD_STARTED);
    BOOST_CHECK(IsTransferOverflowCheckActive(activeBranch.Tip(), params));
    BOOST_CHECK(!IsTransferOverflowCheckActive(startedBranch.Tip(), params));
}

struct TransferOverflowRegtestSetup : BasicTestingSetup
{
    TransferOverflowRegtestSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_CASE(transfer_overflow_active_tip_policy_is_not_sticky, TransferOverflowRegtestSetup)
{
    const Consensus::Params& params = GetParams().GetConsensus();
    const uint32_t overflowMask = VersionBitsMask(params, Consensus::DEPLOYMENT_TRANSFER_OVERFLOW);
    const unsigned int period = params.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideMinerConfirmationWindow;
    const unsigned int threshold = params.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideRuleChangeActivationThreshold;
    BOOST_REQUIRE(period > 0);
    BOOST_REQUIRE(threshold > 0);
    BOOST_REQUIRE(threshold <= period);

    SyntheticVersionBitsChain common;
    common.Mine(period, VERSIONBITS_TOP_BITS);

    SyntheticVersionBitsChain activeBranch(common.Tip());
    activeBranch.Mine(threshold, VERSIONBITS_TOP_BITS | overflowMask);
    activeBranch.Mine(period - threshold, VERSIONBITS_TOP_BITS);
    activeBranch.Mine(period, VERSIONBITS_TOP_BITS);

    SyntheticVersionBitsChain startedBranch(common.Tip());
    startedBranch.Mine(2 * period, VERSIONBITS_TOP_BITS);

    CBlockIndex* originalTip = nullptr;
    {
        LOCK(cs_main);
        originalTip = chainActive.Tip();
        chainActive.SetTip(activeBranch.Tip());
    }
    BOOST_REQUIRE(IsTransferOverflowCheckDeployed());

    {
        LOCK(cs_main);
        chainActive.SetTip(startedBranch.Tip());
    }
    BOOST_CHECK(!IsTransferOverflowCheckDeployed());

    {
        LOCK(cs_main);
        chainActive.SetTip(originalTip);
    }
}

BOOST_AUTO_TEST_SUITE_END()
