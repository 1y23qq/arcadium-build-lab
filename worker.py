import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import traceback
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SOURCE_AAD = b"Arcadium private build input v1"
RESULT_AAD = b"Arcadium private build result v1"


def unpack(repository, destination, key):
    manifest = json.loads((repository / "payload/manifest.json").read_text(encoding="utf-8"))
    parts = manifest.get("parts", [])
    if manifest.get("format") != 1 or not parts or len(parts) > 100 or len(set(parts)) != len(parts):
        raise ValueError("Invalid encrypted input manifest")
    encrypted = bytearray()
    for index, name in enumerate(parts):
        if name != f"part-{index:03}.enc":
            raise ValueError("Invalid encrypted input part")
        encrypted.extend((repository / "payload" / name).read_bytes())
    if len(encrypted) < 28 or hashlib.sha256(encrypted).hexdigest() != manifest["sha256"]:
        raise ValueError("Encrypted input checksum mismatch")
    archive = AESGCM(key).decrypt(bytes(encrypted[:12]), bytes(encrypted[12:]), SOURCE_AAD)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        names = set()
        size = 0
        for entry in source:
            name = PurePosixPath(entry.name)
            if (not name.parts or name.is_absolute() or "\\" in entry.name
                    or any(part in {".", ".."} for part in name.parts)
                    or name.as_posix() != entry.name or entry.name in names
                    or not (entry.isfile() or entry.isdir())):
                raise ValueError("Invalid private source entry")
            names.add(entry.name)
            size += entry.size
            if len(names) > 100_000 or size > 2 * 1024 * 1024 * 1024:
                raise ValueError("Private source exceeds build limits")
            source.extract(entry, destination, filter="data")


def verify_components(source):
    catalog = json.loads((source / "distribution/oneclient-1.8.9.lock.json").read_text(encoding="utf-8"))
    for entry in catalog["arcadiumComponents"]:
        name = entry["file"]
        if Path(name).name != name:
            raise ValueError("Invalid client component name")
        path = source / "packages/arcadium_common/assets/distribution" / name
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry["sha256"] or path.stat().st_size != entry["bytes"]:
            raise ValueError("Bundled client component checksum mismatch")


def execute(source, platform, log, environment):
    target = "aarch64-apple-darwin" if platform == "macos-arm64" else "x86_64-apple-darwin"
    environment.update(SQLX_OFFLINE="true", MACOSX_DEPLOYMENT_TARGET="13.0", CARGO_BUILD_JOBS="2",
                       RUSTUP_TOOLCHAIN="stable")
    verify_components(source)
    commands = [
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_auth", "-p", "arcadium_update", "-p", "arcadium_common", "-p", "arcadium_java",
         "-p", "arcadium_core", "-p", "arcadium_discord", "--lib", "--", "--test-threads=1"],
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_auth", "--test", "concurrent_store", "--", "--test-threads=1"],
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_auth", "--test", "offline", "--", "--test-threads=1"],
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_app", "--lib", "account_service", "--", "--test-threads=1"],
        [sys.executable, "scripts/test_macos_updater.py"],
        [sys.executable, "scripts/build_macos.py", "--target", target],
        [sys.executable, "scripts/smoke_native_helpers.py", "--executable",
         f"target/{target}/macos-testing/Arcadium", "--output", "build/macos-native-helper-tests.json"],
    ]
    for index, command in enumerate(commands):
        log.write(f"Private build step {index + 1}/{len(commands)}\n".encode())
        log.flush()
        result = subprocess.run(command, cwd=source, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=7200)
        if result.returncode:
            return result.returncode
    verify_components(source)
    return 0


def seal(source, private_log, destination, platform, key, exit_code):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        archive.write(private_log, "worker.log")
        archive.writestr("status.json", json.dumps({"platform": platform, "exitCode": exit_code}))
        directory = source / "build/installers" / platform
        if directory.is_dir():
            for file in sorted(directory.iterdir()):
                if file.is_file() and (file.suffix in {".dmg", ".json", ".txt", ".md"}
                                      or file.name.endswith(".app.tar.gz")):
                    archive.write(file, file.relative_to(source).as_posix())
        test_result = source / "build/macos-native-helper-tests.json"
        if test_result.is_file():
            archive.write(test_result, test_result.relative_to(source).as_posix())
    nonce = os.urandom(12)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(nonce + AESGCM(key).encrypt(nonce, output.getvalue(), RESULT_AAD))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=["macos-arm64", "macos-x64"])
    parser.add_argument("--mode", choices=["package"], default="package")
    args = parser.parse_args()
    try:
        key = bytes.fromhex(os.environ.pop("ARCADIUM_BUILD_KEY", ""))
        if len(key) != 32:
            raise ValueError("Invalid key")
    except ValueError:
        print("Private build key is unavailable or invalid.", file=sys.stderr)
        return 1
    repository = Path(__file__).resolve().parent
    temporary = Path(os.environ["RUNNER_TEMP"]) / f"arcadium-private-{args.platform}"
    source = temporary / "source"
    source.mkdir(parents=True, exist_ok=False)
    private_log = temporary / "worker.log"
    exit_code = 1
    with private_log.open("wb") as log:
        try:
            unpack(repository, source, key)
            exit_code = execute(source, args.platform, log, dict(os.environ))
        except Exception:
            log.write(traceback.format_exc().encode())
    seal(source, private_log, repository / "encrypted-output" / f"{args.platform}.enc",
         args.platform, key, exit_code)
    print(f"Encrypted build diagnostics are ready. Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Private build infrastructure failed before encrypted results were ready.", file=sys.stderr)
        raise SystemExit(1) from None
