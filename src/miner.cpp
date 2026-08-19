// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include "wallet/wallet.h"
//#include "wallet/rpcwallet.h"


#include <boost/thread.hpp>
#include <algorithm>
#include <queue>
#include <utility>


extern std::vector<CWalletRef> vpwallets;
//////////////////////////////////////////////////////////////////////////////
//
// RavenMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;
uint64_t nMiningTimeStart = 0;
uint64_t nHashesPerSec = 0;
uint64_t nHashesDone = 0;


int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = GetMaxBlockWeight() - 4000;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(GetMaxBlockWeight() - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions(const CChainParams& params)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight",  GetMaxBlockWeight() - 4000);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions(params)) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    // RIP-25: clamp template construction to the consensus phase governing
    // the next block (8/12/16 MWU). The constructor only knows the structural
    // upper bound.
    const size_t activeMaxWeight = GetMaxBlockWeightForPrev(pindexPrev, chainparams.GetConsensus());
    nBlockMaxWeight = std::min<size_t>(nBlockMaxWeight, activeMaxWeight - 4000);

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblock->nNonce64         = 0;
    pblock->nHeight          = nHeight;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        if (state.IsTransactionError()) {
            if (gArgs.GetBoolArg("-autofixmempool", false)) {
                {
                    TRY_LOCK(mempool.cs, fLockMempool);
                    if (fLockMempool) {
                        LogPrintf("%s failed because of a transaction %s. -autofixmempool is set to true. Clearing the mempool\n", __func__,
                                  state.GetFailedTransaction().GetHex());
                        mempool.clear();
                    }
                }
            } else {
                {
                    TRY_LOCK(mempool.cs, fLockMempool);
                    if (fLockMempool) {
                        auto mempoolTx = mempool.get(state.GetFailedTransaction());
                        if (mempoolTx) {
                            LogPrintf("%s : Failed because of a transaction %s. Trying to remove the transaction from the mempool\n", __func__, state.GetFailedTransaction().GetHex());
                            mempool.removeRecursive(*mempoolTx, MemPoolRemovalReason::CONFLICT);
                        }
                    }
                }
            }
        }
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (const CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());

    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();

    inBlock.insert(iter);
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    indexed_modified_transaction_set mapModifiedTx;
    CTxMemPool::setEntries failedTx;

    for (CTxMemPool::txiter iter = mempool.mapTx.get<ancestor_score>().begin();
         iter != mempool.mapTx.get<ancestor_score>().end(); ++iter) {
        if (inBlock.count(iter))
            continue;

        bool fUsingModified = false;
        modtxiter modit = mapModifiedTx.get<ancestor_score>().begin();

        while (iter != mempool.mapTx.get<ancestor_score>().end() || modit != mapModifiedTx.get<ancestor_score>().end()) {
            CTxMemPool::txiter iterBest;
            if (iter == mempool.mapTx.get<ancestor_score>().end()) {
                iterBest = modit->iter;
                fUsingModified = true;
            } else if (modit == mapModifiedTx.get<ancestor_score>().end()) {
                iterBest = iter;
                fUsingModified = false;
            } else {
                if (CompareTxMemPoolEntryByAncestorFee()(*modit, *iter)) {
                    iterBest = iter;
                    fUsingModified = false;
                } else {
                    iterBest = modit->iter;
                    fUsingModified = true;
                }
            }

            if (!fUsingModified && mapModifiedTx.count(iterBest)) {
                ++iter;
                continue;
            }
            if (failedTx.count(iterBest)) {
                if (fUsingModified)
                    mapModifiedTx.get<ancestor_score>().erase(modit);
                else
                    ++iter;
                continue;
            }

            uint64_t packageSize = fUsingModified ? modit->nSizeWithAncestors : iterBest->GetSizeWithAncestors();
            CAmount packageFees = fUsingModified ? modit->nModFeesWithAncestors : iterBest->GetModFeesWithAncestors();
            int64_t packageSigOpsCost = fUsingModified ? modit->nSigOpCostWithAncestors : iterBest->GetSigOpCostWithAncestors();

            if (packageFees < blockMinFeeRate.GetFee(packageSize))
                return;

            if (!TestPackage(packageSize, packageSigOpsCost)) {
                if (fUsingModified) {
                    mapModifiedTx.get<ancestor_score>().erase(modit);
                    failedTx.insert(iterBest);
                } else {
                    ++iter;
                }
                continue;
            }

            CTxMemPool::setEntries ancestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            mempool.CalculateMemPoolAncestors(*iterBest, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
            onlyUnconfirmed(ancestors);
            ancestors.insert(iterBest);

            if (!TestPackageTransactions(ancestors)) {
                if (fUsingModified) {
                    mapModifiedTx.get<ancestor_score>().erase(modit);
                    failedTx.insert(iterBest);
                }
                continue;
            }

            nConsecutiveFailed = 0;

            std::vector<CTxMemPool::txiter> sortedEntries;
            SortForBlock(ancestors, iterBest, sortedEntries);

            for (size_t i=0; i<sortedEntries.size(); ++i) {
                AddToBlock(sortedEntries[i]);
                mapModifiedTx.erase(sortedEntries[i]);
            }

            ++nPackagesSelected;
            nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
        }
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1;
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}


static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("ProcessBlockFound -- generated block is stale");
    }

    GetMainSignals().BlockFound(pblock->GetHash());

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(chainparams, shared_pblock, true, nullptr))
        return error("ProcessBlockFound -- ProcessNewBlock() failed, block not accepted");

    return true;
}

CWallet *GetFirstWallet() {
#ifdef ENABLE_WALLET
    while(vpwallets.size() == 0){
        MilliSleep(100);

    }
    if (vpwallets.size() == 0)
        return(NULL);
    return(vpwallets[0]);
#endif
    return(NULL);
}

void static RavenMiner(const CChainParams& chainparams)
{
    LogPrintf("RavenMiner -- started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("raven-miner");

    unsigned int nExtraNonce = 0;


    CWallet * pWallet = NULL;

#ifdef ENABLE_WALLET
    pWallet = GetFirstWallet();


    if (!EnsureWalletIsAvailable(pWallet, false)) {
        LogPrintf("RavenMiner -- Wallet not available\n");
    }
#endif

    if (pWallet == NULL)
    {
        LogPrintf("pWallet is NULL\n");
        return;
    }


    std::shared_ptr<CReserveScript> coinbaseScript;

    pWallet->GetScriptForMining(coinbaseScript);

    if (!coinbaseScript)
        LogPrintf("coinbaseScript is NULL\n");

    if (coinbaseScript->reserveScript.empty())
        LogPrintf("coinbaseScript is empty\n");

    try {
        if (!coinbaseScript || coinbaseScript->reserveScript.empty())
        {
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");
        }


        while (true) {

            if (chainparams.MiningRequiresPeers()) {
                do {
                    break;
                    if ((g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) > 0) && !IsInitialBlockDownload()) {
                        break;
                    }

                    MilliSleep(1000);
                } while (true);
            }


            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.Tip();
            if(!pindexPrev) break;



            std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(GetParams()).CreateNewBlock(coinbaseScript->reserveScript));

            if (!pblocktemplate.get())
            {
                LogPrintf("RavenMiner -- Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("RavenMiner -- Running miner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            int64_t nStart = GetTime();
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            while (true)
            {

                uint256 hash;
                uint256 mix_hash;
                while (true)
                {
                    hash = pblock->GetHashFull(mix_hash);
                    if (UintToArith256(hash) <= hashTarget)
                    {
                        pblock->mix_hash = mix_hash;
                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
                        LogPrintf("RavenMiner:\n  proof-of-work found\n  hash: %s\n  target: %s\n", hash.GetHex(), hashTarget.GetHex());
                        ProcessBlockFound(pblock, chainparams);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        coinbaseScript->KeepScript();

                        if (chainparams.MineBlocksOnDemand())
                            throw boost::thread_interrupted();

                        break;
                    }
                    pblock->nNonce += 1;
                    nHashesDone += 1;
                    if (nHashesDone % 500000 == 0) {
                        nHashesPerSec = nHashesDone / (((GetTimeMicros() - nMiningTimeStart) / 1000000) + 1);
                    } 
                    if ((pblock->nNonce & 0xFF) == 0)
                        break;
                }

                boost::this_thread::interruption_point();
                if (pblock->nNonce >= 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0)
                    break;
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks)
                {
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("RavenMiner -- terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("RavenMiner -- runtime error: %s\n", e.what());
        return;
    }
}

int GenerateRavens(bool fGenerate, int nThreads, const CChainParams& chainparams)
{

    static boost::thread_group* minerThreads = NULL;

    int numCores = GetNumCores();
    if (nThreads < 0)
        nThreads = numCores;

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return numCores;

    minerThreads = new boost::thread_group();
    
    nMiningTimeStart = GetTimeMicros();
    nHashesDone = 0;
    nHashesPerSec = 0;

    for (int i = 0; i < nThreads; i++){
        minerThreads->create_thread(boost::bind(&RavenMiner, boost::cref(chainparams)));
    }

    return(numCores);
}
