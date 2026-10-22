#!/usr/bin/env python3
"""Verify all unsigned Build Raven bundles from one workflow run and commit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile
import gzip
import shutil


# Target, GNU host, package suffixes, machine identifier, primary binary format.
TARGETS = {
    "windows": ("x86_64-w64-mingw32", ("-win64.zip", "-win64-setup-unsigned.exe", "-win64-unsigned.tar.gz"), 0x8664, "pe"),
    "osx": ("x86_64-apple-darwin14", ("-osx64.tar.gz", "-osx-unsigned.dmg", "-osx-unsigned.tar.gz"), 0x01000007, "macho"),
    "linux": ("x86_64-linux-gnu", ("-x86_64-linux-gnu.tar.gz",), 0x3E, "elf"),
    "arm32v7": ("arm-linux-gnueabihf", ("-arm-linux-gnueabihf.tar.gz",), 0x28, "elf"),
    "aarch64": ("aarch64-linux-gnu", ("-aarch64-linux-gnu.tar.gz",), 0xB7, "elf"),
}
STATUS = "unsigned CI build; Windows and macOS outputs are not signed final releases"


def digest(path, algorithm="sha256"):
    hasher = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def archive_name(name, label):
    if (not name or name.startswith("/") or "\\" in name or "\0" in name
            or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/")):
        raise ValueError(f"{label}: unsafe archive path {name!r}")
    normalized = posixpath.normpath(name)
    if normalized.startswith("../") or normalized == "..":
        raise ValueError(f"{label}: unsafe archive path {name!r}")
    return normalized


def inspect_tar(path, prefix=None, mac_signing_bundle=False):
    members = {}
    links = set()
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                name = archive_name(member.name, path.name)
                if prefix is not None and name != prefix and not name.startswith(prefix + "/"):
                    raise ValueError(f"{path.name}: unsafe archive path {member.name!r}")
                if name in members:
                    raise ValueError(f"{path.name}: duplicate archive path {name!r}")
                members[name] = member
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError(f"{path.name}: unsupported archive entry {name!r}")
                if member.issym():
                    special = mac_signing_bundle and name == "dist/Applications" and member.linkname == "/Applications"
                    if not special:
                        target = archive_name(member.linkname, path.name)
                        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                        if resolved.startswith("../") or resolved == "..":
                            raise ValueError(f"{path.name}: unsafe symlink {name!r}")
                        if prefix is not None and resolved != prefix and not resolved.startswith(prefix + "/"):
                            raise ValueError(f"{path.name}: unsafe symlink {name!r}")
                    links.add(name)
                elif member.islnk():
                    target = archive_name(member.linkname, path.name)
                    if prefix is not None and target != prefix and not target.startswith(prefix + "/"):
                        raise ValueError(f"{path.name}: unsafe hardlink {name!r}")
                    links.add(name)
            for name in members:
                if any(name.startswith(link + "/") for link in links):
                    raise ValueError(f"{path.name}: archive path below link {name!r}")
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"{path.name}: invalid tar archive: {exc}") from exc
    return members


def inspect_zip(path, prefix):
    members = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = archive_name(member.filename, path.name)
                if name != prefix and not name.startswith(prefix + "/"):
                    raise ValueError(f"{path.name}: unsafe archive path {member.filename!r}")
                if name in members:
                    raise ValueError(f"{path.name}: duplicate archive path {name!r}")
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"{path.name}: symlink in ZIP {name!r}")
                members[name] = member
            bad = archive.testzip()
            if bad is not None:
                raise ValueError(f"{path.name}: failed ZIP CRC for {bad}")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"{path.name}: invalid ZIP archive: {exc}") from exc
    return members


def check_binary(header, kind, machine, target, name):
    if kind == "elf":
        expected_class = 1 if target == "arm32v7" else 2
        if len(header) < 20 or header[:4] != b"\x7fELF" or header[4:6] != bytes((expected_class, 1)):
            raise ValueError(f"{target}: invalid ELF header for {name}")
        actual = struct.unpack_from("<H", header, 18)[0]
    elif kind == "macho":
        if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError(f"{target}: invalid Mach-O header for {name}")
        actual = struct.unpack_from("<I", header, 4)[0]
    else:
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError(f"{target}: invalid PE header for {name}")
        offset = struct.unpack_from("<I", header, 0x3C)[0]
        if offset + 6 > len(header) or header[offset:offset + 4] != b"PE\0\0":
            raise ValueError(f"{target}: invalid PE signature for {name}")
        actual = struct.unpack_from("<H", header, offset + 4)[0]
    if actual != machine:
        raise ValueError(f"{target}: wrong binary machine for {name}: {actual:#x}, expected {machine:#x}")


def check_primary(path, target, dist):
    _, _, machine, kind = TARGETS[target]
    binary_names = ("ravend", "raven-cli", "raven-qt")
    if kind == "pe":
        members = inspect_zip(path, dist)
        with zipfile.ZipFile(path) as archive:
            for binary in binary_names:
                name = f"{dist}/bin/{binary}.exe"
                if name not in members:
                    raise ValueError(f"{target}: missing binary {name}")
                with archive.open(members[name]) as stream:
                    check_binary(stream.read(4096), kind, machine, target, name)
    else:
        members = inspect_tar(path, dist)
        with tarfile.open(path, "r:gz") as archive:
            for binary in binary_names:
                name = f"{dist}/bin/{binary}"
                if name not in members or not members[name].isfile():
                    raise ValueError(f"{target}: missing binary {name}")
                with archive.extractfile(members[name]) as stream:
                    check_binary(stream.read(4096), kind, machine, target, name)
    return {"format": kind, "machine": f"{machine:#x}", "archive_paths_safe": True}


def source_commit(path):
    with tempfile.TemporaryFile() as tar:
        with gzip.open(path, "rb") as source:
            shutil.copyfileobj(source, tar)
        tar.seek(0)
        result = subprocess.run(["git", "get-tar-commit-id"], stdin=tar,
                                capture_output=True, text=True)
        if result.returncode:
            raise ValueError(f"{path.name}: cannot read embedded source commit: {result.stderr.strip()}")
    return result.stdout.strip()


def check_source_matches_checkout(path, repository, sha, dist):
    head = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != sha:
        raise ValueError(f"checked-out commit {head} differs from {sha}")
    with gzip.open(path, "rb") as stream:
        source_hash = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            source_hash.update(chunk)
    command = ["git", "-C", str(repository), "archive", "--format=tar",
               f"--prefix={dist}/", sha]
    archive_hash = hashlib.sha256()
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
            archive_hash.update(chunk)
        error = process.stderr.read()
        if process.wait():
            raise ValueError(f"cannot archive checked-out commit: {error.decode(errors='replace').strip()}")
    if source_hash.digest() != archive_hash.digest():
        raise ValueError(f"{path.name}: source archive content differs from checked-out commit {sha}")


def parse_provenance(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 5 or any("=" not in line for line in lines):
        raise ValueError(f"{path}: invalid provenance")
    fields = dict(line.split("=", 1) for line in lines)
    if len(fields) != 5:
        raise ValueError(f"{path}: duplicate provenance field")
    return fields


def parse_manifest(path):
    records = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None or match[2] in records:
            raise ValueError(f"{path}: invalid manifest entry {line!r}")
        records[match[2]] = match[1]
    return records


def check_sidecars(bundle, artifact):
    for algorithm in ("sha256", "md5"):
        name = f"{artifact}.{algorithm}sum"
        path = bundle / name
        if path.exists():
            length = 64 if algorithm == "sha256" else 32
            expected = f"{digest(bundle / artifact, algorithm)}  {artifact}\n"
            if path.read_text(encoding="ascii") != expected or len(expected.split("  ")[0]) != length:
                raise ValueError(f"{bundle.name}: incorrect {algorithm} sidecar for {artifact}")


def distribution_from_checkout(repository, sha, packaging_ref):
    head = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != sha:
        raise ValueError(f"checked-out commit {head} differs from {sha}")
    source = (repository / "configure.ac").read_text(encoding="utf-8")
    version = []
    for field in ("MAJOR", "MINOR", "REVISION", "BUILD", "RC"):
        match = re.search(r"(?m)^define\(_CLIENT_VERSION_" + field + r", ([0-9]+)\)$", source)
        if match is None:
            raise ValueError(f"cannot read CLIENT_VERSION_{field} from configure.ac")
        version.append(int(match[1]))
    major, minor, revision, build, rc = version
    package_version = f"{major}.{minor}.{revision}"
    if build:
        package_version += f".{build}"
    if rc:
        package_version += f"test{rc}"
    dist = "raven-" + package_version
    if "release" not in packaging_ref:
        short = subprocess.run(["git", "-C", str(repository), "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, check=True).stdout.strip()
        dist += "-" + short
    return dist


def verify(root, sha, dist, repository=None):
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise ValueError("source SHA must be a full lowercase commit ID")
    if re.fullmatch(r"raven-[0-9A-Za-z.-]+", dist) is None or ".." in dist:
        raise ValueError("invalid distribution name")
    expected_dirs = {f"raven-unsigned-{target}-{sha}" for target in TARGETS}
    found_dirs = {entry.name for entry in root.iterdir()}
    if found_dirs != expected_dirs:
        raise ValueError(f"bundle directories differ: missing={expected_dirs - found_dirs}, extra={found_dirs - expected_dirs}")

    source_name = dist + ".tar.gz"
    source_hashes = set()
    records = []
    for target, (host, suffixes, _, _) in TARGETS.items():
        bundle = root / f"raven-unsigned-{target}-{sha}"
        if not bundle.is_dir() or bundle.is_symlink():
            raise ValueError(f"{target}: bundle is not a regular directory")
        expected_provenance = {
            "commit": sha, "target": target, "host": host,
            "source_archive": source_name, "status": STATUS,
        }
        provenance = parse_provenance(bundle / "PROVENANCE.txt")
        if provenance != expected_provenance:
            raise ValueError(f"{target}: unexpected provenance {provenance}")
        artifact_names = {dist + suffix for suffix in suffixes}
        expected_names = artifact_names | {source_name, "PROVENANCE.txt"}
        hashes = parse_manifest(bundle / "SHA256SUMS")
        if set(hashes) != expected_names:
            raise ValueError(f"{target}: manifest files differ: {set(hashes) ^ expected_names}")
        sidecars = {f"{name}.{algorithm}sum" for name in artifact_names
                    for algorithm in ("sha256", "md5")}
        allowed_names = expected_names | sidecars | {"SHA256SUMS"}
        if target == "windows":
            allowed_names.add("windeploy")
        found_names = {entry.name for entry in bundle.iterdir()}
        if found_names - allowed_names:
            raise ValueError(f"{target}: unexpected bundle files {found_names - allowed_names}")
        for entry in bundle.iterdir():
            if target == "windows" and entry.name == "windeploy":
                continue
            if not entry.is_file() or entry.is_symlink() or entry.stat().st_size == 0:
                raise ValueError(f"{target}: invalid bundle file {entry.name}")
        for name, reported in hashes.items():
            if digest(bundle / name) != reported:
                raise ValueError(f"{target}: checksum mismatch for {name}")
        for name in artifact_names:
            check_sidecars(bundle, name)

        primary = bundle / (dist + suffixes[0])
        binary = check_primary(primary, target, dist)
        if target == "windows":
            # The unsigned NSIS installer uses a 32-bit PE launcher around 64-bit payloads.
            installer = bundle / (dist + suffixes[1])
            with installer.open("rb") as stream:
                check_binary(stream.read(4096), "pe", 0x14C, target, installer.name)
            signing = bundle / (dist + suffixes[2])
            signing_members = inspect_tar(signing)
            deploy = bundle / "windeploy"
            if deploy.exists():
                if not deploy.is_dir() or deploy.is_symlink():
                    raise ValueError("windows: invalid windeploy directory")
                expected_deploy = {"win-codesign.cert", "detached-sig-create.sh"}
                if {entry.name for entry in deploy.iterdir()} != expected_deploy:
                    raise ValueError("windows: unexpected windeploy contents")
                with tarfile.open(signing, "r:gz") as archive:
                    for name in expected_deploy:
                        file = deploy / name
                        member = signing_members.get(name)
                        if (not file.is_file() or file.is_symlink() or member is None
                                or not member.isfile() or archive.extractfile(member).read() != file.read_bytes()):
                            raise ValueError(f"windows: windeploy differs from signing bundle: {name}")
        elif target == "osx":
            dmg = bundle / (dist + suffixes[1])
            if dmg.stat().st_size < 512:
                raise ValueError(f"{target}: invalid DMG trailer")
            with dmg.open("rb") as stream:
                stream.seek(-512, os.SEEK_END)
                if stream.read(4) != b"koly":
                    raise ValueError(f"{target}: invalid DMG trailer")
            inspect_tar(bundle / (dist + suffixes[2]), mac_signing_bundle=True)

        source_hashes.add(hashes[source_name])
        records.append({
            "target": target, "host": host, "bundle": bundle.name,
            "manifest_verified": True, "provenance_verified": True,
            "source_sha256": hashes[source_name], "binary": binary,
            "artifact_sha256": {name: hashes[name] for name in sorted(artifact_names)},
        })
    if len(source_hashes) != 1:
        raise ValueError(f"source archives differ: {sorted(source_hashes)}")
    source = root / f"raven-unsigned-linux-{sha}" / source_name
    inspect_tar(source, dist)
    commit = source_commit(source)
    if commit != sha:
        raise ValueError(f"source archive commit {commit} differs from {sha}")
    if repository is not None:
        check_source_matches_checkout(source, repository, sha, dist)
    return {"source_sha": sha, "distribution": dist,
            "source_sha256": next(iter(source_hashes)),
            "checkout_source_verified": repository is not None, "targets": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("source_sha")
    parser.add_argument("distribution", nargs="?")
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--package-ref")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.distribution is None:
        if args.repository is None or args.package_ref is None:
            parser.error("provide a distribution name or both --repository and --package-ref")
        dist = distribution_from_checkout(args.repository, args.source_sha, args.package_ref)
    else:
        dist = args.distribution
    result = verify(args.directory, args.source_sha, dist, args.repository)
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
