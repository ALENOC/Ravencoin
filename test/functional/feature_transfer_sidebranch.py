#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A side branch must parse transfers using its own bit-8 parent state."""

import configparser
import os

from test_framework.blocktools import create_block, create_coinbase
from test_framework.mininode import CTransaction, from_hex, to_hex
from test_framework.test_framework import RavenTestFramework
from test_framework import util as test_util
from test_framework.util import assert_equal, disconnect_nodes


class TransferSidebranchTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-assetindex'], ['-assetindex']]

    def fixed_locktime_raw(self, node, txid):
        tx = from_hex(CTransaction(), node.gettransaction(txid)['hex'])
        tx.nLockTime = 0
        for txin in tx.vin:
            txin.scriptSig = b''
        signed = node.signrawtransaction(to_hex(tx))
        assert_equal(signed['complete'], True)
        return signed['hex']

    def run_test(self):
        producer, verifier = self.nodes
        producer.generate(860)
        asset_name = 'SIDEBRANCHASSET1234567890123'
        producer.issue(asset_name, 2)
        producer.generate(1)
        self.sync_all()
        assert_equal(verifier.getblockcount(), 861)
        assert_equal(verifier.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        parent_hash = verifier.getbestblockhash()

        disconnect_nodes(producer, 1)
        disconnect_nodes(verifier, 0)
        producer.generate(2)
        verifier.generate(3)
        assert_equal(producer.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        assert_equal(verifier.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        active_tip = verifier.getbestblockhash()
        assert_equal(verifier.getblockcount(), 864)

        txid = producer.transfer(asset_name, 1, producer.getnewaddress(), 'ab' * 32, 123456789)[0]
        transfer_raw = self.fixed_locktime_raw(producer, txid)
        decoded = verifier.decoderawtransaction(transfer_raw)
        assert_equal(decoded['locktime'], 0)
        assert any(out['scriptPubKey']['hex'][52:54] == '4c' for out in decoded['vout']
                   if out['scriptPubKey'].get('asset', {}).get('name') == asset_name)
        for txin in decoded['vin']:
            assert verifier.gettxout(txin['txid'], txin['vout']) is not None

        config = configparser.ConfigParser()
        config.read(self.options.configfile)
        test_util.x16r_hash_cmd = os.path.join(
            config['environment']['BUILDDIR'], 'src', 'test',
            'test_raven_hash' + config['environment']['EXEEXT'])

        block_time = verifier.getblockheader(parent_hash)['time'] + 1
        block = create_block(int(parent_hash, 16), create_coinbase(862), block_time)
        block.nVersion = verifier.getblockheader(verifier.getblockhash(862))['version']
        block.vtx.append(from_hex(CTransaction(), transfer_raw))
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        assert_equal(verifier.submitblock(block.serialize().hex()),
                     'bad-txns-transfer-asset-bad-deserialize')
        assert_equal(verifier.getbestblockhash(), active_tip)


if __name__ == '__main__':
    TransferSidebranchTest().main()
