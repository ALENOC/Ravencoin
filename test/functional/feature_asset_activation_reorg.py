#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Asset activation policy must not depend on whether the node saw ACTIVE."""

import configparser
import os

from test_framework.blocktools import create_block, create_coinbase
from test_framework.mininode import CTransaction, from_hex
from test_framework.test_framework import RavenTestFramework
from test_framework import util as test_util
from test_framework.util import Decimal, assert_equal


class AssetActivationReorgTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-assetindex', '-persistmempool=0']]

    def run_test(self):
        node = self.nodes[0]
        node.generate(287)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        active_block = None
        for _ in range(150):
            candidate = node.generate(1)[0]
            if node.getblockchaininfo()['bip9_softforks']['assets']['status'] == 'active':
                active_block = candidate
                break
        assert active_block is not None

        node.listmyassets()  # Exercise the cached deployment query at ACTIVE.
        native_coin = next(coin for coin in node.listunspent()
                           if coin['amount'] > 501 and coin['confirmations'] > 101)
        raw = node.createrawtransaction(
            [{'txid': native_coin['txid'], 'vout': native_coin['vout']}],
            {'n1issueAssetXXXXXXXXXXXXXXXXWdnemQ': 500,
             node.getnewaddress(): native_coin['amount'] - Decimal('500.1'),
             node.getnewaddress(): {'issue': {
                 'asset_name': 'LATCHASSET', 'asset_quantity': 1,
                 'units': 0, 'reissuable': 1, 'has_ipfs': 0}}})
        raw = node.signrawtransaction(raw)['hex']

        active_height = node.getblockcount()
        active_accept = node.testmempoolaccept([raw])[0]
        assert_equal(active_accept['allowed'], True)
        issue_txid = node.sendrawtransaction(raw)
        issue_block = node.generate(1)[0]
        assert_equal(node.getblockcount(), active_height + 1)
        assert issue_txid in node.getblock(issue_block)['tx']
        after_block = node.generate(1)[0]
        assert_equal(node.getblockcount(), active_height + 2)
        assert_equal(node.verifychain(4, 3), True)

        node.invalidateblock(active_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        live_result = node.testmempoolaccept([raw])[0]
        assert_equal(live_result['allowed'], False)

        # Check one more pre-activation tip with the same signed issue.
        locked_tip = node.getbestblockhash()
        config = configparser.ConfigParser()
        config.read(self.options.configfile)
        test_util.x16r_hash_cmd = os.path.join(
            config['environment']['BUILDDIR'], 'src', 'test',
            'test_raven_hash' + config['environment']['EXEEXT'])
        block_time = node.getblockheader(locked_tip)['time'] + 1
        invalid_issue = create_block(int(locked_tip, 16), create_coinbase(active_height), block_time)
        invalid_issue.nVersion = node.getblockheader(active_block)['version']
        invalid_issue.vtx.append(from_hex(CTransaction(), raw))
        invalid_issue.hashMerkleRoot = invalid_issue.calc_merkle_root()
        invalid_issue.solve()
        rejected = node.submitblock(invalid_issue.serialize().hex())
        self.log.info('Pre-activation issue block rejected: %s', rejected)
        assert_equal(rejected, 'bad-txns-assets-not-active')
        assert_equal(node.getbestblockhash(), locked_tip)

        node.invalidateblock(locked_tip)
        before_two = node.testmempoolaccept([raw])[0]
        assert_equal(before_two['allowed'], False)
        node.reconsiderblock(locked_tip)
        # Reconsidering an ancestor also revives its descendants. Keep the
        # ACTIVE branch invalid while comparing the LOCKED_IN tip to restart.
        node.invalidateblock(active_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        assert_equal(node.testmempoolaccept([raw])[0]['allowed'], False)

        self.stop_node(0)
        self.start_node(0, ['-assetindex', '-persistmempool=0'])
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        restarted_result = node.testmempoolaccept([raw])[0]
        assert_equal(live_result['allowed'], restarted_result['allowed'])

        node.reconsiderblock(active_block)
        assert_equal(node.getbestblockhash(), after_block)
        assert issue_txid in node.getblock(issue_block)['tx']
        assert_equal(node.verifychain(4, 3), True)


if __name__ == '__main__':
    AssetActivationReorgTest().main()
