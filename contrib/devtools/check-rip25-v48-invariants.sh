#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "RIP-25/v4.8 invariant failure: $*" >&2
  exit 1
}

require_fixed() {
  local needle="$1" file="$2" message="$3"
  grep -Fq -- "$needle" "$file" || fail "$message"
}

reject_fixed() {
  local needle="$1" file="$2" message="$3"
  if grep -Fq -- "$needle" "$file"; then fail "$message"; fi
}

require_text() {
  local text="$1" needle="$2" message="$3"
  grep -Fq -- "$needle" <<<"$text" || fail "$message"
}

require_min_count() {
  local needle="$1" file="$2" minimum="$3" message="$4"
  local count
  count="$(grep -Fc -- "$needle" "$file" || true)"
  (( count >= minimum )) || fail "$message"
}

mode="${1:---run-tests}"
if (( $# > 1 )); then
  fail 'usage: check-rip25-v48-invariants.sh [--structural-only|--run-tests]'
fi
case "$mode" in
  --structural-only|--run-tests) ;;
  *) fail 'usage: check-rip25-v48-invariants.sh [--structural-only|--run-tests]' ;;
esac

# Approved RIP-25 protocol architecture.
require_fixed 'DEPLOYMENT_PQ_HYBRID' src/consensus/params.h 'PQ BIP9 deployment missing'
require_fixed 'vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].bit = 12' src/chainparams.cpp 'PQ deployment must remain on BIP9 bit 12'
require_fixed '  bit:                                    12' doc/RIP-0025-PQ-Signatures.md 'RIP-25 specification must document BIP9 bit 12'
require_fixed 'MAX_BLOCK_WEIGHT_RIP2 = 8000000' src/consensus/consensus.h 'pre-RIP-25 limit must remain 8 MWU'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE1 = 12000000' src/consensus/consensus.h 'RIP-25 phase 1 must remain 12 MWU'
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE2 = 16000000' src/consensus/consensus.h 'RIP-25 phase 2 must remain 16 MWU'
require_fixed 'PQ_WITNESS_SCALE_FACTOR = 8' src/consensus/consensus.h 'PQ witness discount must remain 8x'
require_fixed 'witversion == 2 && (flags & SCRIPT_VERIFY_PQ_HYBRID)' src/script/interpreter.cpp 'witness-v2 ML-DSA verifier missing'
require_fixed 'mldsa::PUBLICKEY_BYTES' src/script/interpreter.cpp 'ML-DSA-44 public-key size check missing'
require_fixed 'mldsa::SIGNATURE_BYTES' src/script/interpreter.cpp 'ML-DSA-44 signature size check missing'
reject_fixed 'fPQHybridIsActive' src/consensus/consensus.h 'forbidden mutable/static PQ activation state'
reject_fixed 'SetPQHybridBlockLimitsActive' src/consensus/consensus.h 'forbidden mutable block-limit state'

# GLM-002: contextual BIP9 activation must reach consensus script flags.
block_flags="$(sed -n '/^static unsigned int GetBlockScriptFlags(/,/^[[:space:]]*return flags;/p' src/validation.cpp)"
require_text "$block_flags" 'IsPQHybridActiveLocked(pindex->pprev, consensusparams)' 'GetBlockScriptFlags is not driven by contextual PQ BIP9 state'
require_text "$block_flags" 'flags |= SCRIPT_VERIFY_PQ_HYBRID' 'GetBlockScriptFlags does not enable PQ verification after activation'
require_fixed 'unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus())' src/validation.cpp 'ConnectBlock does not use contextual script flags'
require_fixed 'scriptVerifyFlags |= SCRIPT_VERIFY_PQ_HYBRID' src/validation.cpp 'active mempool validation does not enable PQ verification'
require_fixed 'premature-pq-witness' src/validation.cpp 'pre-activation witness-v2 output relay rejection missing'
require_fixed 'witness.stack.size() != 2' src/script/interpreter.cpp 'active witness-v2 must require exactly two witness elements'
require_fixed 'SCRIPT_ERR_PQ_SIGNATURE_VERIFY_FAILED' src/script/interpreter.cpp 'invalid ML-DSA signatures are not rejected'
sigop_function="$(sed -n '/^size_t static WitnessSigOps(/,/^}/p' src/script/interpreter.cpp)"
require_text "$sigop_function" '(flags & SCRIPT_VERIFY_PQ_HYBRID)' 'witness-v2 sigops are not activation-gated'
if grep -A30 'STANDARD_SCRIPT_VERIFY_FLAGS' src/policy/policy.h | grep -Fq 'SCRIPT_VERIFY_PQ_HYBRID'; then
  fail 'SCRIPT_VERIFY_PQ_HYBRID must not be unconditional in standard flags'
fi

# GLM-003: contextual 8 -> 12 -> 16 MWU and UTXO-bound 8x discount.
require_fixed 'VersionBitsStateSinceHeight' src/validation.cpp 'deterministic RIP-25 phase boundary missing'
require_fixed 'return MAX_BLOCK_WEIGHT_RIP2;' src/validation.cpp '8 MWU pre-activation branch missing'
require_fixed 'return MAX_BLOCK_WEIGHT_RIP25_PHASE1' src/validation.cpp '12 MWU phase-1 branch missing'
require_fixed 'return MAX_BLOCK_WEIGHT_RIP25_PHASE2' src/validation.cpp '16 MWU phase-2 branch missing'
require_fixed 'IsPQWitnessV2Prevout' src/validation.cpp 'PQ discount is not bound to a witness-v2 prevout'
require_fixed 'GetContextualPQWitnessDiscount' src/validation.cpp 'UTXO-bound PQ discount calculation missing'
require_fixed 'contextualBlockWeight -= GetContextualPQWitnessDiscount(tx, view)' src/validation.cpp 'ConnectBlock does not apply the contextual PQ discount'
require_fixed 'contextualBlockWeight > activeBlockWeightLimit' src/validation.cpp 'ConnectBlock does not enforce the active contextual limit'
require_fixed 'preliminaryWeight > activeWeightLimit' src/validation.cpp 'contextual preliminary block-weight check missing'
require_fixed 'const size_t activeMaxWeight = GetMaxBlockWeightForPrev(pindexPrev, chainparams.GetConsensus())' src/miner.cpp 'miner does not query the active contextual limit'
require_fixed 'std::min<size_t>(nBlockMaxWeight, activeMaxWeight - 4000)' src/miner.cpp 'miner is not clamped below the active contextual limit'
require_fixed 'GetMaxBlockSerializedSizeForPrev(pindexPrev, chainparams.GetConsensus())' src/miner.cpp 'miner does not query the contextual serialized-size limit'
require_fixed 'GetContextualTransactionWeight(tx, view, fApplyPQDiscount)' src/miner.cpp 'miner weight is not bound to the UTXO context'
require_fixed 'nBlockSerializedSize + resources.serializedSize' src/miner.cpp 'miner does not enforce serialized bytes while selecting packages'
gbt_function="$(sed -n '/^UniValue getblocktemplate(/,/^class submitblock_StateCatcher/p' src/rpc/mining.cpp)"
require_text "$gbt_function" 'GetMaxBlockSerializedSizeForPrev(pindexPrev, consensusParams)' 'GBT size limit is not derived from the template parent'
require_text "$gbt_function" 'GetMaxBlockWeightForPrev(pindexPrev, consensusParams)' 'GBT weight limit is not derived from the template parent'
if grep -Fq 'nSizeLimit = GetMaxBlockSerializedSize()' <<<"$gbt_function" ||
   grep -Fq '"weightlimit", (int64_t)GetMaxBlockWeight()' <<<"$gbt_function"; then
  fail 'GBT advertises structural ceilings instead of contextual next-block limits'
fi

# Remediated high-risk resource paths. These checks are structural lint; the
# executable tests below are the security evidence.
require_fixed 'MAX_BLOCK_WEIGHT_RIP25_PHASE2 / MIN_TRANSACTION_INPUT_WEIGHT' src/undo.h 'undo deserialization does not use the structural 16-MWU bound'
reject_fixed 'fCheckTransferOverflowIsActive' src/consensus/consensus.h 'forbidden sticky transfer-overflow activation state'
require_fixed 'const bool fTransferOverflowActive' src/consensus/tx_verify.h 'asset overflow validation lacks an explicit contextual gate'
require_fixed 'IsTransferOverflowCheckActiveLocked(pindex->pprev' src/validation.cpp 'block validation does not derive transfer-overflow state from the candidate parent'
require_fixed 'mapOwnerUsage' src/net.h 'P2P receive accounting lacks per-owner fairness'
require_fixed 'nMaxProtectedBulkSize' src/net.h 'P2P receive accounting lacks a protected outbound class'
require_fixed 'DEFAULT_OWNER_HEADROOM = 64 * 1024' src/net.h 'P2P owners lack bounded control-message headroom'
require_fixed 'memoryBuffer.TryReserve(memoryOwner, memoryProtected' src/net.cpp 'P2P message allocations bypass owner-aware accounting'
require_fixed 'memusage::MallocUsage(sizeof(CNetMessage) + 2 * sizeof(void*))' src/net.cpp 'P2P message/list objects are not globally charged'
require_fixed 'memusage::MallocUsage(hdrbuf.capacity())' src/net.cpp 'P2P header allocations are not globally charged'
require_fixed 'memusage::MallocUsage(vRecv.capacity())' src/net.cpp 'P2P payload capacity is not charged at allocator size'
require_fixed 'memoryBuffer.Release(memoryOwner, memoryProtected, GetMemoryUsage())' src/net.cpp 'P2P message RAII ownership does not release on destruction'
require_fixed 'MoveCompletedMessagesToProcessQueue' src/net.cpp 'P2P receive-to-process ownership handoff is missing'
require_fixed 'nProcessQueueSize -= msgs.front().GetMemoryUsage()' src/net_processing.cpp 'P2P processing queue does not use the owned memory charge'
reject_fixed 'recvBuffer.Release(msg.vRecv.capacity())' src/net.cpp 'P2P payload ownership is released before processing'
reject_fixed 'nCopy + 256 * 1024' src/net.cpp 'one-byte P2P input still receives speculative 256-KiB allocation'
require_fixed 'CWitnessStack stack;' src/script/script.h 'witness parsing still uses one vector object per wire element'
require_fixed 'CHECKPOINT_INTERVAL = 256' src/script/witness.h 'compact witness representation lacks bounded random-access checkpoints'
require_fixed 'READ_CHUNK_SIZE = 64 * 1024' src/script/witness.h 'witness elements can allocate from an unreceived advertised length'
require_fixed 'parsed.m_compactSize = ReadCompactSize(stream)' src/script/witness.h 'witness stack is not parsed into an atomic compact destination'
require_fixed 'm_serializedElements.capacity() * sizeof(unsigned char)' src/script/witness.h 'compact witness memory is absent from transaction accounting'
require_fixed 'MAX_INITIAL_WITNESS_STACK' src/script/interpreter.cpp 'P2WSH can expand an unconditionally invalid compact witness count'
reject_fixed 'std::vector<std::vector<unsigned char> > stack;' src/script/script.h 'nested witness vector allocation amplification was reintroduced'
require_fixed 'MAX_BLOCK_TRANSACTION_COUNT = MAX_BLOCK_WEIGHT_RIP25_PHASE2 / MIN_TRANSACTION_WEIGHT' src/consensus/consensus.h 'block-family parser bound is not derived from the phase-2 consensus ceiling'
require_fixed 'Block transaction count exceeds structural limit' src/primitives/block.h 'full block count is not rejected before transaction allocation'
require_fixed 'BlockTransactions count exceeds structural limit' src/blockencodings.h 'BLOCKTXN count is not rejected before transaction allocation'
require_fixed 'Compact block transaction count exceeds structural limit' src/blockencodings.h 'compact block combined count is not bounded before prefilled allocation'
require_fixed 'vRecv >> resp.blockhash' src/net_processing.cpp 'BLOCKTXN request ownership is not preflighted before its transaction body'
require_fixed 'TryGetMissingTxCount' src/blockencodings.cpp 'consumed compact-block state is not checked without assertions'
require_min_count 'partialBlock.reset()' src/net_processing.cpp 2 'compact-block fallback leaves partial state reachable'
orphan_function="$(sed -n '/^bool AddOrphanTx(/,/^}/p' src/net_processing.cpp)"
require_text "$orphan_function" 'GetSerializeSize(*tx, SER_NETWORK, PROTOCOL_VERSION)' 'orphan admission is not bounded by retained raw bytes'
require_text "$orphan_function" 'MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR' 'orphan raw-byte limit is not the documented 100-kB bound'
if grep -Fq 'GetTransactionWeight(*tx)' <<<"$orphan_function"; then
  fail 'orphan admission grants an attacker-controlled structural PQ discount'
fi
reorg_function="$(sed -n '/^void CTxMemPool::removeForReorg(/,/^}/p' src/txmempool.cpp)"
require_text "$reorg_function" '!fPQHybridActive' 'mempool reorg cleanup is not gated by contextual PQ activation'
require_text "$reorg_function" 'HasPQWitnessV2Output(tx)' 'pre-activation reorg cleanup retains witness-v2 creators'
require_text "$reorg_function" 'SpendsPQWitnessV2Program(txin, prevScriptPubKey)' 'pre-activation reorg cleanup retains native or P2SH witness-v2 spends'
require_fixed 'IsPQHybridActiveLocked(chainActive.Tip(), GetParams().GetConsensus())' src/validation.cpp 'reorg cleanup does not derive PQ policy from the new active tip'
pq_spend_function="$(sed -n '/^bool SpendsPQWitnessV2Program(/,/^}/p' src/policy/policy.cpp)"
require_text "$pq_spend_function" 'txin.scriptSig != CScript() << redeemBytes' 'P2SH witness-v2 detection does not require the canonical single-push scriptSig'
if grep -Fq 'EvalScript' <<<"$pq_spend_function"; then
  fail 'mempool reorg cleanup executes attacker-controlled scriptSig while scanning'
fi

# Encrypted PQ wallet persistence: ciphertext path must return before plaintext.
wallet_pq_function="$(sed -n '/^bool CWallet::AddPQKeyPubKey(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$wallet_pq_function" 'CCryptoKeyStore::AddPQKeyPubKey' 'wallet PQ insertion bypasses the crypto keystore'
require_text "$wallet_pq_function" 'if (IsCrypted())' 'encrypted PQ wallet path lacks an early return'
require_text "$wallet_pq_function" 'WritePQKey' 'unencrypted PQ wallet persistence missing'
if ! grep -A1 -F 'if (IsCrypted())' <<<"$wallet_pq_function" | grep -Fq 'return true;'; then
  fail 'encrypted PQ wallet path can fall through instead of returning'
fi
encrypted_line="$(grep -nF 'if (IsCrypted())' <<<"$wallet_pq_function" | head -n1 | cut -d: -f1 || true)"
plaintext_line="$(grep -nF 'WritePQKey' <<<"$wallet_pq_function" | head -n1 | cut -d: -f1 || true)"
[[ -n "$encrypted_line" && -n "$plaintext_line" ]] || fail 'cannot locate wallet PQ persistence branches'
(( encrypted_line < plaintext_line )) || fail 'encrypted-wallet return must precede plaintext PQ persistence'
require_fixed 'wallet/test/pq_wallet_tests.cpp' src/Makefile.test.include 'PQ wallet persistence regressions are not wired into make check'
require_fixed 'encrypted_pq_keys_are_ciphertext_only_after_reload_and_backup' src/wallet/test/pq_wallet_tests.cpp 'encrypted PQ wallet reload/backup regression missing'
require_fixed 'std::string("pqkey")' src/wallet/test/pq_wallet_tests.cpp 'PQ wallet regression does not inspect plaintext DB records'
require_fixed 'std::string("cpqkey")' src/wallet/test/pq_wallet_tests.cpp 'PQ wallet regression does not inspect ciphertext DB records'
require_fixed 'if (!EraseIC(std::make_pair(std::string("pqkey")' src/wallet/walletdb.cpp 'encrypted PQ persistence ignores plaintext erase failure'
require_fixed 'HasPlaintextPQKeys' src/wallet/wallet.cpp 'encrypted backup does not scan for plaintext PQ records'
require_fixed 'if (!dbw->Rewrite())' src/wallet/wallet.cpp 'wallet encryption/backup does not propagate rewrite failure'
require_fixed '!mapKeys.empty() || !mapPQKeys.empty()' src/wallet/crypter.cpp 'crypted mode permits resident plaintext PQ keys'

# Wallet encryption must return immediately after any failure that follows
# live-keystore mutation. Assertions are diagnostics, never control flow.
encrypt_wallet_function="$(sed -n '/^bool CWallet::EncryptWallet(/,/^DBErrors CWallet::ReorderTransactions(/p' src/wallet/wallet.cpp)"
if grep -Fq 'assert(false)' <<<"$encrypt_wallet_function"; then
  fail 'EncryptWallet still relies on assert(false) after a recoverable failure'
fi
require_text "$encrypt_wallet_function" 'return failEncryptionAfterKeyMutation(true)' 'post-mutation wallet encryption failures do not return through centralized cleanup'
require_text "$encrypt_wallet_function" 'return failEncryptionAfterKeyMutation(false)' 'wallet transaction commit failure can fall through cleanup'
require_fixed 'pwalletdbEncryption = nullptr' src/wallet/wallet.cpp 'wallet encryption cleanup leaves a dangling database pointer'
require_fixed 'const bool wasCrypted = pwallet->IsCrypted()' src/wallet/rpcwallet.cpp 'RPC encryption failure does not snapshot the pre-call encryption state'
require_fixed '!wasCrypted && pwallet->IsCrypted()' src/wallet/rpcwallet.cpp 'RPC encryption failure can confuse an already encrypted wallet with newly mutated live state'
require_fixed 'Wallet encryption failed after the live key state changed' src/wallet/rpcwallet.cpp 'RPC encryption failure does not distinguish mutated live state'
require_fixed '!wasCrypted && !encryptedSuccessfully && wallet->IsCrypted()' src/qt/walletmodel.cpp 'Qt encryption failure does not distinguish a newly mutated live state'
require_text "$encrypt_wallet_function" '!pwalletdbEncryption->EraseBip39Words(false)' 'BIP39 words erase failure is ignored during encryption'
require_text "$encrypt_wallet_function" '!pwalletdbEncryption->EraseBip39Passphrase(false)' 'BIP39 passphrase erase failure is ignored during encryption'
require_text "$encrypt_wallet_function" '!pwalletdbEncryption->EraseBip39VchSeed(false)' 'BIP39 seed erase failure is ignored during encryption'
require_fixed 'HasPlaintextBip39(hasPlaintextBip39)' src/wallet/wallet.cpp 'encrypted backup does not scan for plaintext BIP39 records'

# BIP39 rows are private-key material. Salvage/load must preserve a complete
# lineage, and key derivation must never substitute the deterministic empty seed.
to_seed_function="$(sed -n '/^bool CMnemonic::ToSeedWithPbkdf2(/,/^}/p' src/wallet/bip39.cpp)"
require_text "$to_seed_function" 'SecureVector derivedSeed(BIP39_SEED_SIZE)' 'BIP39 PBKDF2 does not derive into a secure temporary'
require_text "$to_seed_function" 'derivedSeed.data()) != 1' 'BIP39 PBKDF2 does not accept only the documented success return'
require_text "$to_seed_function" 'SecureVector().swap(seedRet)' 'BIP39 PBKDF2 failure does not cleanse prior output'
require_text "$to_seed_function" 'seedRet.swap(derivedSeed)' 'BIP39 PBKDF2 publishes output before full success'
require_fixed 'return ToSeedWithPbkdf2(mnemonic, passphrase, seedRet, PKCS5_PBKDF2_HMAC)' src/wallet/bip39.cpp 'production BIP39 derivation bypasses the checked PBKDF2 adapter'
set_mnemonic_function="$(sed -n '/^bool CHDChain::SetMnemonic(/,/^}/p' src/wallet/walletdb.cpp)"
require_text "$set_mnemonic_function" 'if (!CMnemonic::ToSeed' 'HD chain ignores BIP39 derivation failure'
generate_seed_function="$(sed -n '/^CPubKey CWallet::GenerateNewSeed(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$generate_seed_function" 'throw std::runtime_error(std::string(__func__) + ": SetMnemonic failed")' 'wallet creation does not abort after BIP39 derivation failure'
kdf_failure_line="$(grep -nF 'if (!newHdChain.SetMnemonic' <<<"$generate_seed_function" | cut -d: -f1 || true)"
seed_publish_line="$(grep -nF 'if (!AddVchSeed(vchSeed))' <<<"$generate_seed_function" | cut -d: -f1 || true)"
chain_persist_line="$(grep -nF 'SetHDChain(newHdChain' <<<"$generate_seed_function" | cut -d: -f1 || true)"
[[ -n "$kdf_failure_line" && -n "$seed_publish_line" && -n "$chain_persist_line" ]] || fail 'cannot locate BIP39 wallet-creation failure boundary'
(( kdf_failure_line < seed_publish_line && kdf_failure_line < chain_persist_line )) || fail 'BIP39 seed can be published or persisted before KDF failure is checked'
is_key_type_function="$(sed -n '/^bool CWalletDB::IsKeyType(/,/^}/p' src/wallet/walletdb.cpp)"
for bip39_type in bip39words bip39passphrase bip39vchseed cbip39words cbip39passphrase cbip39vchseed; do
  require_text "$is_key_type_function" "strType == \"$bip39_type\"" "BIP39 record type $bip39_type is not classified as key-critical"
done
require_text "$is_key_type_function" 'strType == "hdchain"' 'HD chain record is not classified as key-critical'
load_wallet_function="$(sed -n '/^DBErrors CWalletDB::LoadWallet(/,/^DBErrors CWalletDB::FindWalletTx(/p' src/wallet/walletdb.cpp)"
require_text "$load_wallet_function" 'incomplete or mixed BIP39 key material' 'BIP44 load lacks an end-of-scan completeness check'
recovery_filter_function="$(sed -n '/^bool CWalletDB::RecoverKeysOnlyFilter(/,/^}/p' src/wallet/walletdb.cpp)"
require_text "$recovery_filter_function" 'if (!IsKeyType(strType))' 'key-only recovery parses discarded records before classifying them'
derive_child_function="$(sed -n '/^void CWallet::DeriveNewChildKey(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$derive_child_function" 'AssertLockHeld(cs_wallet)' 'BIP44 derivation does not serialize seed access with wallet locking'
require_text "$derive_child_function" 'if (!GetBip39Seed(seed))' 'BIP44 derivation bypasses the locked, size-checked seed snapshot'
if grep -Fq 'g_vchSeed' <<<"$derive_child_function"; then
  fail 'BIP44 derivation reads mutable plaintext seed storage directly'
fi
topup_keypool_function="$(sed -n '/^bool CWallet::TopUpKeyPool(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$topup_keypool_function" 'IsBip44Enabled() && !HasValidBip39Seed()' 'keypool state can mutate before BIP39 seed validation'
first_run_function="$(sed -n '/^bool CWallet::IsFirstRun(/,/^}/p' src/wallet/wallet.cpp)"
for first_run_state in mapPQKeys mapCryptedPQKeys mapMasterKeys IsCrypted IsHDEnabled g_vchSeed vchCryptedBip39VchSeed; do
  require_text "$first_run_function" "$first_run_state" "first-run detection ignores existing $first_run_state wallet state"
done
wallet_load_function="$(sed -n '/^DBErrors CWallet::LoadWallet(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$wallet_load_function" 'fFirstRunRet = IsFirstRun()' 'wallet load duplicates an incomplete first-run predicate'

# Locked encrypted wallets must not retain allocated plaintext BIP39 buffers.
for secure_field in vchWords vchPassphrase g_vchSeed; do
  require_fixed "SecureVector $secure_field;" src/keystore.h "plaintext $secure_field storage does not use the secure allocator"
done
lock_keystore_function="$(sed -n '/^bool CCryptoKeyStore::LockKeyStore(/,/^}/p' src/wallet/crypter.cpp)"
for released_field in vMasterKey vchWords vchPassphrase g_vchSeed; do
  require_text "$lock_keystore_function" "swap($released_field)" "wallet lock does not release plaintext $released_field storage"
done
wallet_lock_function="$(sed -n '/^bool CWallet::Lock(/,/^}/p' src/wallet/wallet.cpp)"
require_text "$wallet_lock_function" 'if (!LockKeyStore())' 'wallet lock bypasses centralized secret release'
require_text "$wallet_lock_function" 'hdChain.ClearSensitiveData()' 'wallet lock retains transient HD-chain BIP39 copies'
require_text "$wallet_lock_function" 'NotifyStatusChanged(this)' 'wallet lock does not publish the completed state transition'
lock_release_line="$(grep -nF 'if (!LockKeyStore())' <<<"$wallet_lock_function" | cut -d: -f1 || true)"
hd_release_line="$(grep -nF 'hdChain.ClearSensitiveData()' <<<"$wallet_lock_function" | cut -d: -f1 || true)"
lock_notify_line="$(grep -nF 'NotifyStatusChanged(this)' <<<"$wallet_lock_function" | cut -d: -f1 || true)"
[[ -n "$lock_release_line" && -n "$hd_release_line" && -n "$lock_notify_line" ]] || fail 'cannot locate wallet locked-state publication boundary'
(( lock_release_line < hd_release_line && hd_release_line < lock_notify_line )) || fail 'wallet publishes locked state before all plaintext BIP39 copies are released'
require_fixed 'SecureVector().swap(vchMnemonic)' src/wallet/walletdb.h 'HD-chain mnemonic storage is only resized, not released'
require_fixed 'SecureVector().swap(vchMnemonicPassphrase)' src/wallet/walletdb.h 'HD-chain passphrase storage is only resized, not released'
require_fixed 'SecureVector().swap(vchSeed)' src/wallet/walletdb.h 'HD-chain seed storage is only resized, not released'
require_fixed 'lock_cleanses_and_releases_plaintext_secret_storage' src/wallet/test/crypto_tests.cpp 'encrypted-wallet secret-release regression is missing'
require_fixed 'wallet_lock_releases_transient_hd_chain_secrets' src/wallet/test/pq_wallet_tests.cpp 'HD-chain secret-release regression is missing'

# Wallet salvage must build and durably close a replacement before atomically
# renaming either database. A reported failure must not publish a backup name.
recovery_function="$(sed -n '/^bool CDB::RecoverInternal(/,/^bool CDB::VerifyEnvironment(/p' src/wallet/db.cpp)"
require_text "$recovery_function" 'if (!bitdb.CloseDb(filename))' 'wallet recovery ignores source database close failure'
require_text "$recovery_function" 'bitdb.Salvage(filename, true, salvagedData)' 'wallet recovery renames the source before salvage'
require_text "$recovery_function" 'DB_CREATE | DB_EXCL | DB_AUTO_COMMIT' 'wallet recovery temporary database is not created exclusively and transactionally'
require_text "$recovery_function" 'putResult != 0' 'wallet recovery ignores a nonzero Berkeley DB row-write result'
require_text "$recovery_function" 'if (!activeTxn)' 'wallet recovery dereferences a null Berkeley DB transaction'
require_text "$recovery_function" 'activeTxn->commit(DB_TXN_SYNC)' 'wallet recovery does not request a synchronous durability boundary'
require_text "$recovery_function" 'bitdb.dbenv->dbrename(' 'wallet recovery lacks the transactional namespace installation'
require_text "$recovery_function" 'activeTxn, filename.c_str(), nullptr, backupFilename.c_str(), 0' 'wallet recovery source rename is not bound to the installation transaction'
require_text "$recovery_function" 'newFilename = backupFilename' 'wallet recovery does not publish the retained original after success'
reject_fixed 'dbrename(nullptr, filename.c_str()' src/wallet/db.cpp 'wallet recovery can still rename the source outside a transaction'
write_commit_line="$(grep -nF 'writeCommitResult = activeTxn->commit(DB_TXN_SYNC)' <<<"$recovery_function" | cut -d: -f1 || true)"
temp_close_line="$(grep -nF 'const int actualCloseResult = closeRecoveryDb()' <<<"$recovery_function" | cut -d: -f1 || true)"
source_rename_line="$(grep -nF 'const int backupRenameResult = bitdb.dbenv->dbrename(' <<<"$recovery_function" | cut -d: -f1 || true)"
install_commit_line="$(grep -nF 'installCommitResult = activeTxn->commit(DB_TXN_SYNC)' <<<"$recovery_function" | cut -d: -f1 || true)"
publish_backup_line="$(grep -nF 'newFilename = backupFilename' <<<"$recovery_function" | cut -d: -f1 || true)"
[[ -n "$write_commit_line" && -n "$temp_close_line" && -n "$source_rename_line" && -n "$install_commit_line" && -n "$publish_backup_line" ]] || fail 'cannot locate atomic wallet-recovery boundaries'
(( write_commit_line < temp_close_line && temp_close_line < source_rename_line && source_rename_line < install_commit_line && install_commit_line < publish_backup_line )) || fail 'wallet recovery publishes or renames before its durability boundaries'
require_fixed 'SalvageResult { FAILED, PARTIAL, COMPLETE }' src/wallet/db.h 'wallet recovery cannot distinguish partial salvage output'
require_fixed 'recovery_faults_preserve_original_database' src/wallet/test/pq_wallet_tests.cpp 'atomic wallet-recovery fault regression is missing'
require_fixed 'recovery_exclusive_temp_open_failure_preserves_source' src/wallet/test/pq_wallet_tests.cpp 'exclusive temporary-database regression is missing'
require_fixed 'partial_recovery_installs_atomically_and_preserves_backup' src/wallet/test/pq_wallet_tests.cpp 'partial wallet-recovery regression is missing'
require_fixed 'recovery_handles_zero_length_raw_rows' src/wallet/test/pq_wallet_tests.cpp 'zero-length Berkeley DB recovery regression is missing'

# PQ secret material must never cross a production API backed by the ordinary
# allocator. The behavioral test also proves byte-for-byte wallet compatibility.
require_fixed 'using KeyData = SecureVector' src/pqkey.h 'CPQKey secret storage lacks a secure-allocator type barrier'
reject_fixed 'SetKeyData(const std::vector<unsigned char>' src/pqkey.h 'CPQKey exposes an ordinary-heap secret import API'
reject_fixed 'SetKeyData(const std::vector<unsigned char>' src/pqkey.cpp 'CPQKey implements an ordinary-heap secret import API'
reject_fixed 'std::vector<unsigned char> keyData(key.GetKeyData()' src/keystore.h 'keystore copies a PQ secret into ordinary heap memory'
reject_fixed 'std::vector<unsigned char> keyData(vchSecret' src/wallet/crypter.cpp 'wallet decryption copies a PQ secret into ordinary heap memory'
reject_fixed 'std::vector<unsigned char> keyData(key.GetKeyData()' src/wallet/wallet.cpp 'wallet persistence copies a PQ secret into ordinary heap memory'
require_fixed 'CPQKey::KeyData pqKeyData' src/wallet/walletdb.cpp 'wallet loader deserializes PQ secrets into ordinary heap memory'
require_fixed 'const uint64_t pqKeySize = ReadCompactSize(ssValue)' src/wallet/walletdb.cpp 'wallet loader allocates a secure PQ buffer before validating its encoded size'
require_fixed 'pqKeySize != mldsa::SECRETKEY_BYTES' src/wallet/walletdb.cpp 'wallet loader does not enforce the fixed ML-DSA-44 secret-key size before allocation'
require_min_count 'Hash(pqPubKey.begin(), pqPubKey.end(),' src/wallet/walletdb.cpp 2 'wallet PQ hash compatibility is not computed without a concatenated secret buffer'
reject_fixed 'std::vector<unsigned char> pqKeyData' src/wallet/walletdb.cpp 'wallet DB uses ordinary heap memory for PQ secrets'
require_fixed 'pq_secret_material_uses_secure_allocator_and_legacy_encoding' src/test/pqkey_hardening_tests.cpp 'PQ secure-allocator/legacy-format regression is missing'
require_fixed 'oversized_plaintext_pq_record_is_rejected_before_secure_allocation' src/wallet/test/pq_wallet_tests.cpp 'oversized PQ wallet secret regression is missing'

# liboqs is consensus-critical and must be version-proven.
require_fixed 'liboqs' depends/packages/packages.mk 'liboqs missing from depends package graph'
require_fixed '$(package)_version=0.12.0' depends/packages/liboqs.mk 'pinned liboqs version must remain 0.12.0'
require_fixed 'df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08' depends/packages/liboqs.mk 'pinned liboqs checksum changed'
require_fixed 'PKG_PROG_PKG_CONFIG' configure.ac 'configure does not require pkg-config'
require_fixed 'PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.12.0]' configure.ac 'configure does not prove liboqs >= 0.12.0'
require_fixed 'refusing an unversioned system-library fallback' configure.ac 'configure does not document fail-closed liboqs behavior'
require_fixed '--without-liboqs is not supported' configure.ac 'configure permits disabling consensus-critical liboqs'
reject_fixed 'AC_CHECK_LIB([oqs]' configure.ac 'unversioned liboqs symbol fallback is forbidden'
reject_fixed 'AC_CHECK_HEADER([oqs/oqs.h]' configure.ac 'unversioned liboqs header fallback is forbidden'
reject_fixed 'LIBOQS_LIBS=-loqs' configure.ac 'manual unversioned liboqs linker fallback is forbidden'
require_fixed 'PKG_CONFIG_LIBDIR=$depends_prefix/share/pkgconfig:$depends_prefix/lib/pkgconfig' depends/config.site.in 'depends does not isolate target pkg-config metadata'
reject_fixed 'PKGCONFIG_LIBDIR' depends/config.site.in 'misspelled PKG_CONFIG_LIBDIR defeats cross-build isolation'
require_fixed '!defined(OQS_VERSION_MAJOR)' src/crypto/mldsa.cpp 'compile-time liboqs major-version guard missing'
require_fixed '!defined(OQS_VERSION_MINOR)' src/crypto/mldsa.cpp 'compile-time liboqs minor-version guard missing'
require_fixed 'OQS_VERSION_MAJOR == 0 && OQS_VERSION_MINOR < 12' src/crypto/mldsa.cpp 'compile-time liboqs >=0.12 guard missing'
require_fixed 'OQS_SIG_ml_dsa_44_length_public_key' src/crypto/mldsa.cpp 'ML-DSA-44 interface size guard missing'
if ! grep -A4 'libravenconsensus_la_LIBADD' src/Makefile.am | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'libravenconsensus must link LIBOQS_LIBS'
fi
if ! grep -A8 'qt_raven_qt_LDADD' src/Makefile.qt.include | grep -Fq '$(LIBOQS_LIBS)'; then
  fail 'raven-qt must link LIBOQS_LIBS'
fi

# Security regression tests must compile and execute through make check.
require_fixed 'test/bip39_tests.cpp' src/Makefile.test.include 'BIP39 vectors are not wired into make check'
require_fixed 'test/data/bip39_vectors.json' src/Makefile.test.include 'BIP39 vector data is not generated for make check'
require_fixed 'test/rip25_versionbits_tests.cpp' src/Makefile.test.include 'RIP-25 versionbits test is not wired into make check'
require_fixed 'test/kawpow_v48_hardening_tests.cpp' src/Makefile.test.include 'KAWPOW v4.8 hardening test is not wired into make check'
require_fixed 'witness_v2_active_rules_accept_valid_and_reject_invalid_mldsa' src/test/pqkey_hardening_tests.cpp 'active witness-v2 regression missing'
require_fixed 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH' src/test/pqkey_hardening_tests.cpp 'empty active witness-v2 rejection is untested'
require_fixed 'SCRIPT_ERR_PQ_SIGNATURE_VERIFY_FAILED' src/test/pqkey_hardening_tests.cpp 'malformed ML-DSA rejection is untested'
require_fixed 'verifyFlags |= SCRIPT_VERIFY_PQ_HYBRID' src/script/sign.cpp 'PQ transaction signing does not self-check under witness-v2 rules'

# Ravencoin Core 4.8.0 security and recovery protections.
require_fixed 'nHeightHeaderCheckActivation = 4487776' src/chainparams.cpp '4.8 KAWPOW height activation missing'
require_fixed '4487775, uint256S("0x000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd")' src/chainparams.cpp '4.8 checkpoint baseline changed'
require_fixed 'IsKAWPOWHeaderHeightValid(block, nHeight,' src/validation.cpp 'production validation bypasses the tested KAWPOW predicate'
require_fixed 'block.nHeight == static_cast<uint32_t>(actualHeight)' src/consensus/validation.h 'KAWPOW declared-height predicate changed'
require_fixed 'REJECT_INVALID, "bad-blk-height"' src/validation.cpp 'KAWPOW bad-height rejection missing'
require_fixed 'vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].bit = 11' src/chainparams.cpp 'transfer-overflow deployment must remain on bit 11'
require_fixed 'bad-txns-input-asset-totalInputs-toolarge' src/consensus/tx_verify.cpp 'asset input overflow protection missing'
require_fixed 'bad-txns-transfer-asset-totalOutputs-toolarge' src/consensus/tx_verify.cpp 'asset output overflow protection missing'
require_fixed 'fRetryWithChainStateRebuild' src/init.cpp 'chainstate-ahead automatic rebuild handling missing'
require_fixed 'fCoinsAheadOfIndex = !mapBlockIndex.count(pcoinsTip->GetBestBlock())' src/init.cpp 'chainstate-ahead detection missing'
require_fixed 'passetsdb = new CAssetsDB(nBlockTreeDBCache, false, fReset || fReindexChainState)' src/init.cpp 'asset DB is not wiped on chainstate rebuild'
require_fixed 'prestricteddb = new CRestrictedDB(nBlockTreeDBCache, false, fReset || fReindexChainState)' src/init.cpp 'restricted-asset DB is not wiped on chainstate rebuild'

# GLM-001 and CI supply-chain integrity: checkout commit is the tested tree.
final_gate=.github/workflows/rip25-v48-final-gate.yml
require_min_count 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5' "$final_gate" 2 'final gate checkout is not immutably pinned in every job'
require_min_count 'persist-credentials: false' "$final_gate" 2 'final gate checkout credentials are not disabled'
require_min_count 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' "$final_gate" 2 'final gate does not bind checkout HEAD to the reported SHA'
require_min_count 'test -z "$(git status --porcelain)"' "$final_gate" 2 'final gate does not assert a pristine checkout'
require_min_count 'id: prebuild_integrity' "$final_gate" 2 'final gate does not recheck tracked source before compilation'
require_min_count 'run: ./contrib/devtools/check-rip25-v48-invariants.sh --structural-only' "$final_gate" 2 'final gate does not run structural lint in every job'
require_fixed 'run: ./contrib/devtools/check-rip25-v48-invariants.sh --run-tests' "$final_gate" 'final gate does not run the behavioral invariant suite'
reject_fixed 'statuses: write' "$final_gate" 'final gate has unnecessary status write permission'
reject_fixed 'pull_request_target' "$final_gate" 'final gate must not execute branch code via pull_request_target'
reject_fixed 'secrets.' "$final_gate" 'final gate must not expose repository secrets'
reject_fixed 'apply-rip25-v48-port' "$final_gate" 'final gate must not materialize source'
reject_fixed 'materializ' "$final_gate" 'final gate still describes source materialization'

if grep -RFn -- 'apply-rip25-v48-port' .github/workflows; then
  fail 'a workflow still invokes or references the RIP-25 materializer'
fi
if grep -RFin -- 'materializ' .github/workflows; then
  fail 'a workflow still contains remediation materialization machinery'
fi
if grep -ERn --include='*.yml' --include='*.yaml' 'uses:[[:space:]]+[^[:space:]#]+@(master|main|v[0-9]+)([[:space:]#]|$)' .github/workflows; then
  fail 'a workflow action still uses a mutable branch or version tag'
fi
reject_fixed 'fkirc/skip-duplicate-actions' .github/workflows/build-raven.yml 'redundant third-party duplicate-skip action remains'
reject_fixed 'actions/cache@' .github/workflows/build-raven.yml 'release builds must not restore unauthenticated dependency caches'
reject_fixed 'Cache Dependencies' .github/workflows/build-raven.yml 'release dependency cache step was reintroduced'
reject_fixed 'depends/built' .github/workflows/build-raven.yml 'release workflow restores compiled depends artifacts'
reject_fixed 'depends/work' .github/workflows/build-raven.yml 'release workflow restores unverified depends work state'
reject_fixed 'restore-keys:' .github/workflows/build-raven.yml 'release workflow permits fallback to an unrelated cache key'
require_fixed 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' .github/workflows/build-raven.yml 'actions/upload-artifact pin changed'
require_fixed 'permissions:' .github/workflows/build-raven.yml 'build workflow lacks explicit permissions'
require_fixed '  contents: read' .github/workflows/build-raven.yml 'build workflow permissions are not read-only'
release_workflow=.github/workflows/build-raven.yml
require_fixed '      - fix/rip25-v48-glm-remediation' "$release_workflow" 'release workflow does not build remediation-branch pushes'
require_fixed 'runs-on: ubuntu-22.04' "$release_workflow" 'release workflow uses an unsupported runner'
require_fixed "OS: [ 'windows', 'osx' ]" "$release_workflow" 'release workflow is not statically limited to Windows and macOS'
require_fixed 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' "$release_workflow" 'release workflow does not bind source to the reported SHA'
require_fixed 'test -z "$(git status --porcelain)"' "$release_workflow" 'release workflow does not require a pristine checkout'
require_min_count 'bash -Eeuo pipefail' "$release_workflow" 4 'release helper scripts are not invoked fail closed'
require_fixed 'if-no-files-found: error' "$release_workflow" 'release artifact upload permits missing output'
require_fixed '436df6dfc7073365d12f8ef6c1fdb060777c720602cc67c2dcf9a59d94290e38' .github/scripts/02-copy-build-dependencies.sh 'macOS SDK checksum pin changed'
require_fixed 'sha256sum --check' .github/scripts/02-copy-build-dependencies.sh 'macOS SDK is not verified before extraction'
reject_fixed 'pip3 install ds-store' .github/scripts/00-install-deps.sh 'release workflow uses an unpinned PyPI ds-store package'

temporary_paths=(
  .glm-remediation-trigger
  contrib/devtools/one-shot-glm-remediation.sh
  contrib/devtools/remediate-glm-rip25-v48.py
  .github/workflows/rip25-glm-remediation.yml
  .github/workflows/rip25-glm-remediate-once.yml
  .github/workflows/rip25-glm-remediate-pr.yml
)
for path in "${temporary_paths[@]}"; do
  [[ ! -e "$path" ]] || fail "temporary remediation infrastructure remains: $path"
done

if [[ "$mode" == '--structural-only' ]]; then
  echo 'RIP-25/v4.8 structural lint: OK (behavior not certified)'
  exit 0
fi

test_binary=src/test/test_raven
[[ -x "$test_binary" ]] || fail "behavioral test binary is missing or not executable: $test_binary"
newer_source="$(find src -type f \( -name '*.cpp' -o -name '*.h' \) -newer "$test_binary" -print -quit)"
[[ -z "$newer_source" ]] || fail "behavioral test binary is stale relative to: $newer_source"

behavioral_tests=(
  sigopcount_tests/rip25_v2_sigops_activation_gated
  rip25_versionbits_tests
  asset_tx_tests/transfer_overflow_checks_follow_explicit_context
  coins_tests/txundo_large_roundtrip_test
  coins_tests/txundo_deserialization_limit_test
  rip25_miner_tests
  net_tests/incomplete_message_buffer_concurrent_global_limit
  net_tests/incomplete_message_buffer_releases_reservations
  net_tests/maximum_message_completes_with_global_buffer_limit
  net_tests/header_only_messages_are_globally_accounted
  transaction_tests/compact_witness_empty_element_amplification
  transaction_tests/compact_witness_block_empty_element_amplification
  transaction_tests/compact_witness_truncated_element_is_atomic_and_chunked
  transaction_tests/compact_witness_move_leaves_valid_source
  transaction_tests/compact_witness_preserves_compactsize_boundaries
  blockencodings_tests/block_family_counts_reject_before_element_read
  blockencodings_tests/block_family_transaction_count_boundary_roundtrips
  blockencodings_tests/block_family_count_bounds_are_atomic_and_apply_on_write
  blockencodings_tests/consumed_partial_block_fails_closed_after_fallback
  DoS_tests/unexpected_blocktxn_is_rejected_before_body_parse
  DoS_tests/orphan_pq_shape_uses_raw_size_limit
  rpc_tests/rip25_gbt_reports_contextual_resource_limits
  mempool_tests/rip25_reorg_purges_preactivation_policy_transactions
  pqkey_hardening_tests
  kawpow_v48_hardening_tests
  bip39_tests
  wallet_crypto/lock_cleanses_and_releases_plaintext_secret_storage
  pq_wallet_tests
)

for test_filter in "${behavioral_tests[@]}"; do
  echo "RIP-25/v4.8 behavioral invariant: $test_filter"
  "$test_binary" --run_test="$test_filter" --log_level=test_suite
done

echo 'RIP-25/v4.8 structural + behavioral invariants: OK'
