#!/usr/bin/env python3
"""Check that inert workflow bait cannot satisfy the invariant gate."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "contrib/devtools/check-rip25-v48-invariants.sh"
WORKFLOWS = ("build-raven.yml", "rip25-v48-final-gate.yml")


class InvariantGateNegativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix="rip25-gate-")
        cls.fixture = Path(cls.tempdir.name)
        for entry in ROOT.iterdir():
            if entry.name in (".git", ".github"):
                continue
            (cls.fixture / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
        github = cls.fixture / ".github"
        github.mkdir()
        for entry in (ROOT / ".github").iterdir():
            if entry.name == "workflows":
                shutil.copytree(entry, github / entry.name)
            else:
                (github / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def run_gate(self):
        return subprocess.run(
            ["bash", str(GATE), "--structural-only"], cwd=self.fixture,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def check_mutation(self, workflow, old, new, occurrence=1):
        path = self.fixture / ".github/workflows" / workflow
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, "The workflow fixture no longer matches the test")
        self.assertGreaterEqual(original.count(old), occurrence)
        at = -1
        for _ in range(occurrence):
            at = original.index(old, at + 1)
        mutated = original[:at] + new + original[at + len(old):]
        path.write_text(mutated, encoding="utf-8")
        try:
            result = self.run_gate()
            self.assertNotEqual(
                result.returncode, 0,
                workflow + " accepted inert bait: " + old + "\n" + result.stdout,
            )
        finally:
            path.write_text(original, encoding="utf-8")

    def test_unmodified_workflows_pass(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_build_raven_dependency_is_executable_yaml(self):
        self.check_mutation(
            WORKFLOWS[0], "    needs: security-tests",
            "    #    needs: security-tests",
        )

    def test_build_raven_make_check_is_executed(self):
        self.check_mutation(
            WORKFLOWS[0], "          if ! make check; then",
            "          if ! echo 'make check'; then",
        )

    def test_build_raven_sha_check_is_executed_before_and_after(self):
        old = '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'
        self.check_mutation(WORKFLOWS[0], old, "          # " + old.strip())
        self.check_mutation(WORKFLOWS[0], old, "          # " + old.strip(), occurrence=2)

    def test_final_gate_make_check_is_executed(self):
        self.check_mutation(
            WORKFLOWS[1], "        run: make check",
            "        run: echo 'make check'",
        )

    def test_final_gate_sha_check_is_executed_before_and_after(self):
        old = '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'
        self.check_mutation(WORKFLOWS[1], old, "          # " + old.strip())
        self.check_mutation(WORKFLOWS[1], old, "          # " + old.strip(), occurrence=2)

    def test_wallet_modal_prompt_removal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rip25-wallet-gate-") as directory:
            fixture = Path(directory)
            for entry in ROOT.iterdir():
                if entry.name == ".git":
                    continue
                if entry.name != "src":
                    (fixture / entry.name).symlink_to(
                        entry, target_is_directory=entry.is_dir())
                    continue
                source_dir = fixture / "src"
                source_dir.mkdir()
                for source_entry in entry.iterdir():
                    if source_entry.name != "wallet":
                        (source_dir / source_entry.name).symlink_to(
                            source_entry, target_is_directory=source_entry.is_dir())
                        continue
                    wallet_dir = source_dir / "wallet"
                    wallet_dir.mkdir()
                    for wallet_entry in source_entry.iterdir():
                        if wallet_entry.name != "wallet.cpp":
                            (wallet_dir / wallet_entry.name).symlink_to(
                                wallet_entry, target_is_directory=wallet_entry.is_dir())
                            continue
                        original = wallet_entry.read_text(encoding="utf-8")
                        modal_call = "uiInterface.ShowMnemonic(CClientUIInterface::MODAL);"
                        self.assertEqual(original.count(modal_call), 1)
                        (wallet_dir / "wallet.cpp").write_text(
                            original.replace(modal_call, "/* prompt omitted */", 1),
                            encoding="utf-8",
                        )
            result = subprocess.run(
                ["bash", str(GATE), "--structural-only"], cwd=fixture,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("cannot locate the BIP44 atomic-creation boundaries",
                          result.stderr)


if __name__ == "__main__":
    unittest.main()
