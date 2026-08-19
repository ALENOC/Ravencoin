// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus.h"

unsigned int GetMaxBlockWeight()
{
    // Structural upper bound. The exact 8/12/16 MWU consensus limit is
    // derived from pindexPrev and RIP-25 BIP9 state in ContextualCheckBlock.
    return MAX_BLOCK_WEIGHT_RIP25_PHASE2;
}

unsigned int GetMaxBlockSerializedSize()
{
    // Buffer/import upper bound for all RIP-25 phases.
    return MAX_BLOCK_SERIALIZED_SIZE_RIP25_PHASE2;
}
