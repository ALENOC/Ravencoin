#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test fail-closed wallet encryption rewrite recovery."""

import glob
import os

from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletEncryptionRewriteTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def induce_rewrite_failure(self, node_index):
        passphrase = "RewriteFailurePassphrase"
        node = self.nodes[node_index]
        address = node.getnewaddress()
        private_key = node.dumpprivkey(address)
        rewrite_path = os.path.join(
            node.datadir,
            node.getblockchaininfo()["chain"],
            "wallet.dat.rewrite",
        )

        os.mkdir(rewrite_path)
        assert_raises_rpc_error(
            -16,
            "Wallet encryption failed after the live key state changed",
            node.encryptwallet,
            passphrase,
        )
        node.wait_until_stopped()
        return address, private_key, passphrase, rewrite_path

    def assert_encrypted_key_survives(self, node_index, address, private_key, passphrase):
        node = self.nodes[node_index]
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            node.dumpprivkey,
            address,
        )
        node.walletpassphrase(passphrase, 60)
        assert_equal(node.dumpprivkey(address), private_key)

    def run_test(self):
        address, private_key, passphrase, rewrite_path = (
            self.induce_rewrite_failure(0)
        )

        self.assert_start_raises_init_error(
            0,
            expected_msg="Wallet encryption recovery could not complete",
        )

        os.rmdir(rewrite_path)
        self.start_node(0)
        self.assert_encrypted_key_survives(
            0, address, private_key, passphrase
        )

        address, private_key, passphrase, rewrite_path = (
            self.induce_rewrite_failure(1)
        )
        wallet_dir = os.path.dirname(rewrite_path)
        self.start_node(1, extra_args=["-salvagewallet=1"])

        retained_backups = glob.glob(
            os.path.join(wallet_dir, "wallet.dat.*.bak")
        )
        assert_equal(len(retained_backups), 1)
        retained_backup = retained_backups[0]
        debug_log = os.path.join(wallet_dir, "debug.log")
        with open(debug_log, encoding="utf-8") as log_file:
            log_text = log_file.read()
        salvage_warnings = [
            line for line in log_text.splitlines()
            if "Warning: Wallet salvage retained the original wallet.dat as" in line
        ]
        assert_equal(len(salvage_warnings), 1)
        salvage_warning = salvage_warnings[0]
        assert retained_backup in salvage_warning
        assert_equal(
            salvage_warning.count("Wallet salvage retained the original wallet.dat as"),
            1,
        )
        assert "may contain recoverable unencrypted private-key material" in salvage_warning

        os.rmdir(rewrite_path)
        self.assert_encrypted_key_survives(
            1, address, private_key, passphrase
        )


if __name__ == "__main__":
    WalletEncryptionRewriteTest().main()
