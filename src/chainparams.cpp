// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

//TODO: Take these out
extern double algoHashTotal[16];
extern int algoHashHits[16];


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2018 Bitcoin is name of the game for new generation of firms";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {
	consensus.nSegwitEnabled = false;
}

void CChainParams::TurnOffCSV() {
	consensus.nCSVEnabled = false;
}

void CChainParams::TurnOffBIP34() {
	consensus.nBIP34Enabled = false;
}

void CChainParams::TurnOffBIP65() {
	consensus.nBIP65Enabled = false;
}

void CChainParams::TurnOffBIP66() {
	consensus.nBIP66Enabled = false;
}

bool CChainParams::BIP34() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP65() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP66() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::CSVEnabled() const{
	return consensus.nCSVEnabled;
}


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 * + Contains no strange transactions
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.nHeightHeaderCheckActivation = 4487776;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60;
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1613;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1540944000;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1572480000;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1578920400;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1610542800;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1714;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1588788000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1620324000;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1714;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1593453600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1624989600;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1597341600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1628877600;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].bit = 11;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nStartTime = 1781222401;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nTimeout = 1812844799;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideRuleChangeActivationThreshold = 1411;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].bit = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nStartTime = 1798761600;
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nTimeout = 1830297600;
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nOverrideRuleChangeActivationThreshold = 1714;
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nOverrideMinerConfirmationWindow = 2016;
        consensus.nPQHybridEnabled = false;
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000355cd0ac1503c83052");
        consensus.defaultAssumeValid = uint256S("0x0000000000018d2fdcf4ac8eaac8db059584bd2840be5629562bb8599d39998c");
        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0x41;
        pchMessageStart[2] = 0x56;
        pchMessageStart[3] = 0x4e;
        nDefaultPort = 8767;
        nPruneAfterHeight = 100000;
        genesis = CreateGenesisBlock(1514999494, 25023712, 0x1e00ffff, 4, 5000 * COIN);
        consensus.hashGenesisBlock = genesis.GetX16RHash();
        assert(consensus.hashGenesisBlock == uint256S("0000006b444bc2f2ffe627be9d9e7e7a0730000870ef6eb6da46c8eae389df90"));
        assert(genesis.hashMerkleRoot == uint256S("28ff00a867739a352523808d301f504bc4547699398d70faf2266a8bae5f3516"));
        vSeeds.emplace_back("seed-raven.bitactivate.com", false);
        vSeeds.emplace_back("seed-raven.ravencoin.com", false);
        vSeeds.emplace_back("seed-raven.ravencoin.org", false);
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        strBech32PQHrp = "rvn";
        nExtCoinType = 175;
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;
        checkpointData = (CCheckpointData) {
            {
                { 535721, uint256S("0x000000000001217f58a594ca742c8635ecaaaf695d1a63f6ab06979f1c159e04")},
                { 697376, uint256S("0x000000000000499bf4ebbe61541b02e4692b33defc7109d8f12d2825d4d2dfa0")},
                { 740000, uint256S("0x00000000000027d11bf1e7a3b57d3c89acc1722f39d6e08f23ac3a07e16e3172")},
                { 909251, uint256S("0x000000000000694c9a363eff06518aa7399f00014ce667b9762f9a4e7a49f485")},
                { 1040000, uint256S("0x000000000000138e2690b06b1ddd8cf158c3a5cf540ee5278debdcdffcf75839")},
                { 1186833, uint256S("0x0000000000000d4840d4de1f7d943542c2aed532bd5d6527274fc0142fa1a410")},
                { 2383550, uint256S("0x0000000000008927ed21a1e3bb87d3e1020646e8cc94354a1f8fc608395e15dc")},
                { 4487775, uint256S("0x000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd")}
            }
        };
        chainTxData = ChainTxData{1659045742, 20969961, 5.7};
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;
        strIssueAssetBurnAddress = "RXissueAssetXXXXXXXXXXXXXXXXXhhZGt";
        strReissueAssetBurnAddress = "RXReissueAssetXXXXXXXXXXXXXXVEFAWu";
        strIssueSubAssetBurnAddress = "RXissueSubAssetXXXXXXXXXXXXXWcwhwL";
        strIssueUniqueAssetBurnAddress = "RXissueUniqueAssetXXXXXXXXXXWEAe58";
        strIssueMsgChannelAssetBurnAddress = "RXissueMsgChanneLAssetXXXXXXSjHvAY";
        strIssueQualifierAssetBurnAddress = "RXissueQuaLifierXXXXXXXXXXXXUgEDbC";
        strIssueSubQualifierAssetBurnAddress = "RXissueSubQuaLifierXXXXXXXXXVTzvv5";
        strIssueRestrictedAssetBurnAddress = "RXissueRestrictedXXXXXXXXXXXXzJZ1q";
        strAddNullQualifierTagBurnAddress = "RXaddTagBurnXXXXXXXXXXXXXXXXZQm5ya";
        strGlobalBurnAddress = "RXBurnXXXXXXXXXXXXXXXXXXXXXXWUo9FV";
        nDGWActivationBlock = 338778;
        nMaxReorganizationDepth = 60;
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;
        nAssetActivationHeight = 435456;
        nMessagingActivationBlock = 1092672;
        nRestrictedActivationBlock = 1092672;
        nKAAAWWWPOWActivationTime = 1588788000;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
    }
};

class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.nHeightHeaderCheckActivation = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60;
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1310;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {28, 1199145601, 1230767999, 2016, 1310};
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS] = {5, 1533924000, 1577257200, 2016, 1310};
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS] = {6, 1570428000, 1577257200, 2016, 1310};
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE] = {8, 1586973600, 1618509600, 2016, 1310};
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE] = {9, 1593453600, 1624989600, 2016, 1411};
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS] = {10, 1597341600, 1628877600, 2016, 1411};
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW] = {11, 1781222401, 1812844799, 2016, 1411};
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID] = {12, 1199145601, 1893456000, 2016, 1310};
        consensus.nPQHybridEnabled = true;
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000168050db560b4");
        consensus.defaultAssumeValid = uint256S("0x000000006272208605c4df3b54d4d5515759105e7ffcb258e8cd8077924ffef1");
        pchMessageStart[0] = 0x52; pchMessageStart[1] = 0x56; pchMessageStart[2] = 0x4E; pchMessageStart[3] = 0x54;
        nDefaultPort = 18770;
        nPruneAfterHeight = 1000;
        uint32_t nGenesisTime = 1537466400;
        genesis = CreateGenesisBlock(nGenesisTime, 15615880, 0x1e00ffff, 2, 5000 * COIN);
        consensus.hashGenesisBlock = genesis.GetX16RHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000ecfc5e6324a079542221d00e10362bdc894d56500c414060eea8a3ad5a"));
        assert(genesis.hashMerkleRoot == uint256S("28ff00a867739a352523808d301f504bc4547699398d70faf2266a8bae5f3516"));
        vFixedSeeds.clear(); vSeeds.clear();
        vSeeds.emplace_back("seed-testnet-raven.bitactivate.com", false);
        vSeeds.emplace_back("seed-testnet-raven.ravencoin.com", false);
        vSeeds.emplace_back("seed-testnet-raven.ravencoin.org", false);
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04,0x35,0x83,0x94};
        strBech32PQHrp = "trvn";
        nExtCoinType = 1;
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;
        checkpointData = (CCheckpointData) {{
            {225, uint256S("0x000003465e3e0167322eb8269ce91246bbc211e293bc5fbf6f0a0d12c1ccb363")},
            {223408, uint256S("0x000000012a0c09dd6456ab19018cc458648dec762b04f4ddf8ef8108eae69db9")},
            {232980, uint256S("0x000000007b16ae547fce76c3308dbeec2090cde75de74ab5dfcd6f60d13f089b")},
            {257610, uint256S("0x000000006272208605c4df3b54d4d5515759105e7ffcb258e8cd8077924ffef1")}
        }};
        chainTxData = ChainTxData{1543633332,146666,0.02};
        nIssueAssetBurnAmount = 500 * COIN; nReissueAssetBurnAmount = 100 * COIN; nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN; nIssueMsgChannelAssetBurnAmount = 100 * COIN; nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN; nIssueRestrictedAssetBurnAmount = 1500 * COIN; nAddNullQualifierTagBurnAmount = .1 * COIN;
        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";
        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";
        nDGWActivationBlock = 1;
        nMaxReorganizationDepth = 60; nMinReorganizationPeers = 4; nMinReorganizationAge = 60 * 60 * 12;
        nAssetActivationHeight = 6048; nMessagingActivationBlock = 10080; nRestrictedActivationBlock = 10080;
        nKAAAWWWPOWActivationTime = 1585159200; nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
    }
};

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nBIP34Enabled = true; consensus.nBIP65Enabled = true; consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true; consensus.nCSVEnabled = true; consensus.nHeightHeaderCheckActivation = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016*60; consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true; consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY] = {28,0,999999999999ULL,144,108};
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS] = {6,0,999999999999ULL,144,108};
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS] = {7,0,999999999999ULL,144,108};
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE] = {8,0,999999999999ULL,288,208};
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE] = {9,0,999999999999ULL,144,108};
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS] = {10,0,999999999999ULL,500,400};
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW] = {11,0,999999999999ULL,500,400};
        consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID] = {12,0,999999999999ULL,144,108};
        consensus.nPQHybridEnabled = true;
        consensus.nMinimumChainWork = uint256S("0x00"); consensus.defaultAssumeValid = uint256S("0x00");
        pchMessageStart[0]=0x43; pchMessageStart[1]=0x52; pchMessageStart[2]=0x4F; pchMessageStart[3]=0x57;
        nDefaultPort=18444; nPruneAfterHeight=1000;
        genesis = CreateGenesisBlock(1524179366,1,0x207fffff,4,5000*COIN);
        consensus.hashGenesisBlock = genesis.GetX16RHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0b2c703dc93bb63a36c4e33b85be4855ddbca2ac951a7a0a29b8de0408200a3c "));
        assert(genesis.hashMerkleRoot == uint256S("0x28ff00a867739a352523808d301f504bc4547699398d70faf2266a8bae5f3516"));
        vFixedSeeds.clear(); vSeeds.clear();
        fDefaultConsistencyChecks=true; fRequireStandard=false; fMineBlocksOnDemand=true;
        checkpointData=(CCheckpointData){{}}; chainTxData=ChainTxData{0,0,0};
        base58Prefixes[PUBKEY_ADDRESS]=std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS]=std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY]=std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY]={0x04,0x35,0x87,0xCF}; base58Prefixes[EXT_SECRET_KEY]={0x04,0x35,0x83,0x94};
        strBech32PQHrp="rcrt"; nExtCoinType=1;
        nIssueAssetBurnAmount=500*COIN; nReissueAssetBurnAmount=100*COIN; nIssueSubAssetBurnAmount=100*COIN;
        nIssueUniqueAssetBurnAmount=5*COIN; nIssueMsgChannelAssetBurnAmount=100*COIN; nIssueQualifierAssetBurnAmount=1000*COIN;
        nIssueSubQualifierAssetBurnAmount=100*COIN; nIssueRestrictedAssetBurnAmount=1500*COIN; nAddNullQualifierTagBurnAmount=.1*COIN;
        strIssueAssetBurnAddress="n1issueAssetXXXXXXXXXXXXXXXXWdnemQ"; strReissueAssetBurnAddress="n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress="n1issueSubAssetXXXXXXXXXXXXXbNiH6v"; strIssueUniqueAssetBurnAddress="n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress="n1issueMsgChanneLAssetXXXXXXT2PBdD"; strIssueQualifierAssetBurnAddress="n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress="n1issueSubQuaLifierXXXXXXXXXYffPLh"; strIssueRestrictedAssetBurnAddress="n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress="n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH"; strGlobalBurnAddress="n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";
        nDGWActivationBlock=200; nMaxReorganizationDepth=60; nMinReorganizationPeers=4; nMinReorganizationAge=60*60*12;
        nAssetActivationHeight=0; nMessagingActivationBlock=0; nRestrictedActivationBlock=0;
        nKAAAWWWPOWActivationTime=3582830167; nKAWPOWActivationTime=nKAAAWWWPOWActivationTime;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;
const CChainParams &GetParams() { assert(globalChainParams); return *globalChainParams; }
std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET) return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST) return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}
void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network); if (fForceBlockNetwork) bNetwork.SetNetwork(network); globalChainParams = CreateChainParams(network);
}
void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) { globalChainParams->UpdateVersionBitsParameters(d,nStartTime,nTimeout); }
void TurnOffSegwit(){ globalChainParams->TurnOffSegwit(); }
void TurnOffCSV(){ globalChainParams->TurnOffCSV(); }
void TurnOffBIP34(){ globalChainParams->TurnOffBIP34(); }
void TurnOffBIP65(){ globalChainParams->TurnOffBIP65(); }
void TurnOffBIP66(){ globalChainParams->TurnOffBIP66(); }
