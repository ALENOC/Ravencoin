#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restricted-asset activation must agree after reorg and restart."""

from test_framework.test_framework import RavenTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal


class Rip5ActivationReorgTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-assetindex', '-persistmempool=0']]

    def run_test(self):
        node = self.nodes[0]
        node.generate(287)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['messaging_restricted']['status'], 'locked_in')

        active_block = None
        for _ in range(150):
            candidate = node.generate(1)[0]
            if node.getblockchaininfo()['bip9_softforks']['messaging_restricted']['status'] == 'active':
                active_block = candidate
                break
        assert active_block is not None

        node.listglobalrestrictions()  # Exercise the cached RIP5 deployment query.

        node.invalidateblock(active_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['messaging_restricted']['status'], 'locked_in')
        try:
            node.listglobalrestrictions()
            live_available = True
        except JSONRPCException:
            live_available = False

        self.stop_node(0)
        self.start_node(0, ['-assetindex', '-persistmempool=0'])
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()['bip9_softforks']['messaging_restricted']['status'], 'locked_in')
        try:
            node.listglobalrestrictions()
            restarted_available = True
        except JSONRPCException:
            restarted_available = False
        assert_equal(live_available, restarted_available)


if __name__ == '__main__':
    Rip5ActivationReorgTest().main()
