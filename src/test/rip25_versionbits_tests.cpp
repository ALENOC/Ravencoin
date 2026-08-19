// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "consensus/params.h"
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
    std::vector<std::unique_ptr<CBlockIndex>> blocks;

public:
    const CBlockIndex* Tip() const
    {
        return blocks.empty() ? nullptr : blocks.back().get();
    }

    void Mine(unsigned int count, int32_t version)
    {
        for (unsigned int i = 0; i < count; ++i) {
            auto block = std::make_unique<CBlockIndex>();
            block->nHeight = static_cast<int>(blocks.size());
            block->pprev = blocks.empty() ? nullptr : blocks.back().get();
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

BOOST_AUTO_TEST_SUITE_END()
