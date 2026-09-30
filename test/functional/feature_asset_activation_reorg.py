#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Asset activation policy must not depend on whether the node saw ACTIVE."""

from test_framework.test_framework import RavenTestFramework
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

        node.invalidateblock(active_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        live_result = node.testmempoolaccept([raw])[0]

        self.stop_node(0)
        self.start_node(0, ['-assetindex', '-persistmempool=0'])
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        restarted_result = node.testmempoolaccept([raw])[0]
        assert_equal(live_result['allowed'], restarted_result['allowed'])


if __name__ == '__main__':
    AssetActivationReorgTest().main()
