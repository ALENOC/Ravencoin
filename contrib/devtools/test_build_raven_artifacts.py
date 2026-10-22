#!/usr/bin/env python3
"""Negative controls for the downloaded Build Raven release bundles."""

import gzip
import hashlib
import io
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

import verify_build_raven_artifacts as verifier


SHA = "a" * 40
DIST = "raven-4.8.1-aaaaaaaaa"
STATUS = "unsigned CI build; Windows and macOS outputs are not signed final releases"


def elf(machine, elf_class):
    header = bytearray(64)
    header[:6] = b"\x7fELF" + bytes((elf_class, 1))
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def macho():
    return struct.pack("<II", 0xFEEDFACF, 0x01000007) + bytes(56)


def pe(machine):
    header = bytearray(256)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 128)
    header[128:132] = b"PE\0\0"
    struct.pack_into("<H", header, 132, machine)
    return bytes(header)


def archive(members, commit=None):
    buffer = io.BytesIO()
    pax = {"comment": commit} if commit is not None else {}
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT,
                      pax_headers=pax) as tar:
        for name, content in members:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
    return gzip.compress(buffer.getvalue(), mtime=0)


def payloads(source):
    output = {}
    for target, (_, suffixes, machine, kind) in verifier.TARGETS.items():
        files = {DIST + ".tar.gz": source}
        primary = DIST + suffixes[0]
        if kind == "pe":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as z:
                for binary in ("ravend.exe", "raven-cli.exe", "raven-qt.exe"):
                    z.writestr(f"{DIST}/bin/{binary}", pe(machine))
            files[primary] = buffer.getvalue()
            files[DIST + suffixes[1]] = pe(0x14C)
            files[DIST + suffixes[2]] = archive([("./detached-sig-create.sh", b"test")])
        else:
            binary = macho() if kind == "macho" else elf(
                machine, 1 if target == "arm32v7" else 2
            )
            files[primary] = archive(
                [(f"{DIST}/bin/{name}", binary) for name in
                 ("ravend", "raven-cli", "raven-qt")]
            )
            if target == "osx":
                files[DIST + suffixes[1]] = bytes(512) + b"koly" + bytes(508)
                files[DIST + suffixes[2]] = archive([("./dist/Raven-Qt.app/Contents/Info.plist", b"test")])
        output[target] = files
    return output


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="rip25-artifact-test-")
        self.root = Path(self.tempdir.name)
        source = archive([(f"{DIST}/README", b"source")], commit=SHA)
        self.files = payloads(source)
        self.write_bundles()

    def tearDown(self):
        self.tempdir.cleanup()

    def bundle(self, target):
        return self.root / f"raven-unsigned-{target}-{SHA}"

    def write_bundles(self):
        for target, (host, _, _, _) in verifier.TARGETS.items():
            path = self.bundle(target)
            path.mkdir(exist_ok=True)
            provenance = (
                f"commit={SHA}\ntarget={target}\nhost={host}\n"
                f"source_archive={DIST}.tar.gz\nstatus={STATUS}\n"
            )
            (path / "PROVENANCE.txt").write_text(provenance)
            files = dict(self.files[target])
            files["PROVENANCE.txt"] = provenance.encode()
            for name, content in files.items():
                (path / name).write_bytes(content)
            self.rehash(target)

    def rehash(self, target):
        path = self.bundle(target)
        manifest = "".join(
            hashlib.sha256((path / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in sorted((*self.files[target], "PROVENANCE.txt"))
        )
        (path / "SHA256SUMS").write_text(manifest)

    def verify(self):
        return verifier.verify(self.root, SHA, DIST)

    def test_five_valid_bundles(self):
        result = self.verify()
        self.assertEqual({item["target"] for item in result["targets"]},
                         set(verifier.TARGETS))
        self.assertEqual(result["source_sha"], SHA)

    def test_missing_target_fails(self):
        self.bundle("osx").rename(self.root / "missing")
        with self.assertRaisesRegex(ValueError, "bundle directories"):
            self.verify()

    def test_wrong_sha_fails_even_with_updated_manifest(self):
        path = self.bundle("linux") / "PROVENANCE.txt"
        path.write_text(path.read_text().replace(SHA, "b" * 40))
        self.rehash("linux")
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.verify()

    def test_modified_payload_fails_without_manifest_update(self):
        binary = self.bundle("linux") / (DIST + verifier.TARGETS["linux"][1][0])
        binary.write_bytes(binary.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_wrong_target_binary_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["aarch64"][1][0]
        self.files["aarch64"][name] = archive(
            [(f"{DIST}/bin/{binary}", elf(0x3E, 2)) for binary in
             ("ravend", "raven-cli", "raven-qt")]
        )
        (self.bundle("aarch64") / name).write_bytes(self.files["aarch64"][name])
        self.rehash("aarch64")
        with self.assertRaisesRegex(ValueError, "machine"):
            self.verify()

    def test_missing_binary_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["linux"][1][0]
        contents = archive([(f"{DIST}/bin/ravend", elf(0x3E, 2)),
                            (f"{DIST}/bin/raven-cli", elf(0x3E, 2))])
        self.files["linux"][name] = contents
        (self.bundle("linux") / name).write_bytes(contents)
        self.rehash("linux")
        with self.assertRaisesRegex(ValueError, "missing binary"):
            self.verify()

    def test_wrong_embedded_source_commit_fails_with_updated_manifest(self):
        source = archive([(f"{DIST}/README", b"source")], commit="b" * 40)
        for target in verifier.TARGETS:
            name = DIST + ".tar.gz"
            self.files[target][name] = source
            (self.bundle(target) / name).write_bytes(source)
            self.rehash(target)
        with self.assertRaisesRegex(ValueError, "source archive commit"):
            self.verify()

    def test_nonidentical_source_archives_fail(self):
        name = DIST + ".tar.gz"
        altered = archive([(f"{DIST}/README", b"different")], commit=SHA)
        self.files["osx"][name] = altered
        (self.bundle("osx") / name).write_bytes(altered)
        self.rehash("osx")
        with self.assertRaisesRegex(ValueError, "source archives differ"):
            self.verify()

    def test_forged_source_commit_header_fails_checkout_comparison(self):
        repo = self.root / "checkout"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        (repo / "README").write_text("correct source\n")
        subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
        env = os.environ.copy()
        env.update({
            "GIT_AUTHOR_NAME": "ALENOC",
            "GIT_AUTHOR_EMAIL": "185200505+ALENOC@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "ALENOC",
            "GIT_COMMITTER_EMAIL": "185200505+ALENOC@users.noreply.github.com",
        })
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "[FINDING-020] Fixture source tree"],
                       check=True, env=env)
        sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                      text=True).strip()
        source = self.root / "source.tar.gz"
        genuine = subprocess.check_output(
            ["git", "-C", str(repo), "archive", "--format=tar",
             f"--prefix={DIST}/", sha]
        )
        source.write_bytes(gzip.compress(genuine, mtime=0))
        verifier.check_source_matches_checkout(source, repo, sha, DIST)
        source.write_bytes(archive([(f"{DIST}/README", b"forged source")], commit=sha))
        self.assertEqual(verifier.source_commit(source), sha)
        with self.assertRaisesRegex(ValueError, "source archive content differs"):
            verifier.check_source_matches_checkout(source, repo, sha, DIST)

    def test_unsafe_tar_member_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["linux"][1][0]
        members = [(f"{DIST}/bin/{binary}", elf(0x3E, 2)) for binary in
                   ("ravend", "raven-cli", "raven-qt")]
        members.append(("../outside", b"escape"))
        self.files["linux"][name] = archive(members)
        (self.bundle("linux") / name).write_bytes(self.files["linux"][name])
        self.rehash("linux")
        with self.assertRaisesRegex(ValueError, "unsafe archive path"):
            self.verify()

    def test_unsafe_zip_member_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["windows"][1][0]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            for binary in ("ravend.exe", "raven-cli.exe", "raven-qt.exe"):
                z.writestr(f"{DIST}/bin/{binary}", pe(0x8664))
            z.writestr("../outside", b"escape")
        self.files["windows"][name] = buffer.getvalue()
        (self.bundle("windows") / name).write_bytes(buffer.getvalue())
        self.rehash("windows")
        with self.assertRaisesRegex(ValueError, "unsafe archive path"):
            self.verify()

    def test_unsafe_tar_symlink_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["linux"][1][0]
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for binary in ("ravend", "raven-cli", "raven-qt"):
                entry = tarfile.TarInfo(f"{DIST}/bin/{binary}")
                data = elf(0x3E, 2)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
            link = tarfile.TarInfo(f"{DIST}/bin/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../outside"
            tar.addfile(link)
        contents = gzip.compress(buffer.getvalue(), mtime=0)
        self.files["linux"][name] = contents
        (self.bundle("linux") / name).write_bytes(contents)
        self.rehash("linux")
        with self.assertRaisesRegex(ValueError, "unsafe archive path"):
            self.verify()

    def test_bad_sidecar_fails(self):
        name = DIST + verifier.TARGETS["linux"][1][0]
        (self.bundle("linux") / (name + ".sha256sum")).write_text("0" * 64 + "  " + name + "\n")
        with self.assertRaisesRegex(ValueError, "sidecar"):
            self.verify()

    def test_bad_dmg_fails_with_updated_manifest(self):
        name = DIST + verifier.TARGETS["osx"][1][1]
        self.files["osx"][name] = b"not a disk image"
        (self.bundle("osx") / name).write_bytes(self.files["osx"][name])
        self.rehash("osx")
        with self.assertRaisesRegex(ValueError, "DMG"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
