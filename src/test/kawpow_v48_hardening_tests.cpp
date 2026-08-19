// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "test/test_raven.h"

#include <boost/test/unit_test.hpp>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(kawpow_v48_hardening_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(kawpow_declared_header_height_gate)
{
    std::unique_ptr<CChainParams> mainParams = CreateChainParams("main");
    BOOST_REQUIRE(mainParams);

    const Consensus::Params& consensus = mainParams->GetConsensus();
    const int activationHeight = consensus.nHeightHeaderCheckActivation;
    BOOST_REQUIRE_EQUAL(activationHeight, 4487776);
    BOOST_REQUIRE(nKAWPOWActivationTime > 0);

    CBlockHeader header;
    header.nTime = nKAWPOWActivationTime;

    // Exact height at the first protected block is valid.
    header.nHeight = static_cast<uint32_t>(activationHeight);
    BOOST_CHECK(IsKAWPOWHeaderHeightValid(header,
                                          activationHeight,
                                          activationHeight,
                                          nKAWPOWActivationTime));

    // The exploit primitive: a forged declared KAWPOW height at/after the 4.8
    // gate must be rejected by the same predicate used by validation.cpp.
    header.nHeight = static_cast<uint32_t>(activationHeight - 1);
    BOOST_CHECK(!IsKAWPOWHeaderHeightValid(header,
                                           activationHeight,
                                           activationHeight,
                                           nKAWPOWActivationTime));

    // Legacy blocks before the 4.8 activation height retain historical rules.
    header.nHeight = 1;
    BOOST_CHECK(IsKAWPOWHeaderHeightValid(header,
                                          activationHeight - 1,
                                          activationHeight,
                                          nKAWPOWActivationTime));

    // The declared KAWPOW height is not enforced before KAWPOW itself activates.
    header.nTime = nKAWPOWActivationTime - 1;
    BOOST_CHECK(IsKAWPOWHeaderHeightValid(header,
                                          activationHeight,
                                          activationHeight,
                                          nKAWPOWActivationTime));
}

BOOST_AUTO_TEST_SUITE_END()
