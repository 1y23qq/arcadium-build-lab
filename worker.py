import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import traceback
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SOURCE_AAD = b"Arcadium private build input v1"
RESULT_AAD = b"Arcadium private build result v1"


def unpack(repository, destination, key):
    manifest = json.loads((repository / "payload/manifest.json").read_text())
    pieces = []
    for name in manifest["parts"]:
        if Path(name).name != name:
            raise ValueError("Invalid payload path")
        pieces.append((repository / "payload" / name).read_bytes())
    encrypted = b"".join(pieces)
    if hashlib.sha256(encrypted).hexdigest() != manifest["sha256"]:
        raise ValueError("Payload checksum mismatch")
    archive = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], SOURCE_AAD)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        source.extractall(destination, filter="data")


def execute(source, platform, mode, log, environment):
    target = "aarch64-apple-darwin" if platform == "macos-arm64" else "x86_64-apple-darwin"
    environment.update(SQLX_OFFLINE="true", MACOSX_DEPLOYMENT_TARGET="13.0", CARGO_BUILD_JOBS="2")
    if mode == "package":
        environment["MVK_CONFIG_USE_METAL_ARGUMENT_BUFFERS"] = "0" if platform == "macos-x64" else "1"
        commands = [
            [sys.executable, "scripts/build_macos.py", "--target", target],
            ["bash", "game-branding/gradlew", "-p", "game-renderer", "test", ":agent:test",
             "probeDevice", "probeSdkCalls", "probeSdkShaders", "probeSdkVertexArrays", "probeSdkTerrain", "probeSdkIndexCache",
             "probeSkiaSnapshots", "probeSdkLogicOps", "probeSdkLogicOpsEmulated", "probeSdkFrames"],
            [sys.executable, "scripts/run_macos_vulkan_scene.py", "--target", target]
        ]
    else:
        environment["MVK_CONFIG_USE_METAL_ARGUMENT_BUFFERS"] = "1" if mode=="benchmark" and platform=="macos-arm64" else "0"
        commands = [
            ["bash", "game-branding/gradlew", "-p", "game-renderer", "test", ":agent:test",
             "probeDevice", "probeSdkCalls", "probeSdkShaders", "probeSdkVertexArrays", "probeSdkTerrain", "probeSdkIndexCache", "probeSkiaSnapshots",
             "probeSdkLogicOps", "probeSdkLogicOpsEmulated"],
            [sys.executable, "scripts/run_macos_vulkan_scene.py", "--target", target]
        ]
        if mode == "benchmark":
            commands[0].append("probeSdkFrames")
            commands[1].append("--benchmark")
            if (source / "build/ci-benchmark-baseline").is_dir(): commands[1].extend(["--baseline-components","build/ci-benchmark-baseline"])
        if mode == "probes":
            commands = commands[:1]
    if mode == "probes" and platform == "macos-arm64":
        results = []
        for metal_arguments in ["0", "1"]:
            environment["MVK_CONFIG_USE_METAL_ARGUMENT_BUFFERS"] = metal_arguments
            log.write(("Metal argument buffers: " + metal_arguments + "\n").encode())
            log.flush()
            command = commands[0] if metal_arguments == "0" else ["bash", "game-branding/gradlew", "-p", "game-renderer", "probeSdkTerrain"]
            results.append(subprocess.run(command, cwd=source, env=environment, stdout=log,
                                          stderr=subprocess.STDOUT, timeout=4800).returncode)
        return next((result for result in results if result), 0)
    for command in commands:
        completed = subprocess.run(command, cwd=source, env=environment, stdout=log,
                                   stderr=subprocess.STDOUT, timeout=4800)
        if completed.returncode:
            return completed.returncode
    return 0


def seal(source, private_log, destination, platform, key, exit_code):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as packed:
        packed.write(private_log, "worker.log")
        packed.writestr("status.json", json.dumps({"platform": platform, "exitCode": exit_code}))
        for relative in ["build/macos-game-test", "build/installers",
                         "game-renderer/build/test-results", "game-renderer/agent/build/test-results"]:
            directory = source / relative
            if directory.is_dir():
                for file in directory.rglob("*"):
                    if file.is_file():
                        packed.write(file, file.relative_to(source).as_posix())
    nonce = os.urandom(12)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(nonce + AESGCM(key).encrypt(nonce, archive.getvalue(), RESULT_AAD))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=["macos-arm64", "macos-x64"])
    parser.add_argument("--mode", required=True, choices=["scene", "package", "probes", "benchmark"])
    args = parser.parse_args()
    key = bytes.fromhex(os.environ.pop("ARCADIUM_BUILD_KEY"))
    if len(key) != 32:
        raise ValueError("Invalid build key")
    repository = Path(__file__).resolve().parent
    temporary = Path(os.environ["RUNNER_TEMP"]) / "arcadium-private-work"
    source = temporary / "source"
    source.mkdir(parents=True, exist_ok=False)
    private_log = temporary / "worker.log"
    exit_code = 1
    with private_log.open("wb") as log:
        try:
            unpack(repository, source, key)
            exit_code = execute(source, args.platform, args.mode, log, dict(os.environ))
        except Exception:
            log.write(traceback.format_exc().encode())
    seal(source, private_log, repository / "encrypted-output" / (args.platform + ".enc"),
         args.platform, key, exit_code)
    print("Encrypted build diagnostics are ready. Exit code: " + str(exit_code))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
