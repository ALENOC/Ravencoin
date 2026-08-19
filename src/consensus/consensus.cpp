// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus.h"

unsigned int GetMaxBlockWeight()
{
    // RIP-25 structural upper bound. The active 8/12/16 MWU rule is enforced
    // contextually from BIP9 state and chain height in validation.cpp.
    return MAX_BLOCK_WEIGHT_RIP25_PHASE2;
}

unsigned int GetMaxBlockSerializedSize()
{
    // RIP-25 phase-2 is also the absolute serialized-size ceiling.
    return MAX_BLOCK_SERIALIZED_SIZE_RIP25_PHASE2;
}
