import argparse
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import traceback
import tomllib
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SOURCE_AAD = b"Arcadium private build input v1"
RESULT_AAD = b"Arcadium private build result v1"
PACKAGE_MODES = {"package", "hotfix"}
HYINFO_TEST_MODULE = "game::launch::retired_mod_tests"


def hotfix_steps(target, target_dir, minimum):
    return [
        ("pythonCompatibility", [sys.executable, "-m", "unittest", "discover", "-s", "scripts",
                                  "-p", "test_macos_compatibility.py"], 120),
        ("rustHyInfoRetirement", ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
                                   "-p", "arcadium_core", "--lib", HYINFO_TEST_MODULE,
                                   "--", "--test-threads=1"], 7200),
        ("macosUpdater", [sys.executable, "scripts/test_macos_updater.py"], 120),
        ("package", [sys.executable, "scripts/build_macos.py", "--target", target], 7200),
        ("binaryCompatibility", [sys.executable, "scripts/check_macos_compatibility.py", "--binary",
                                   str(target_dir / target / "macos-testing/Arcadium"), "--target", target,
                                   "--minimum", minimum, "--static-root", str(target_dir / target / "macos-testing"),
                                   "--fetch-sdk", "--output", "build/macos-compatibility-tests.json"], 7200),
        ("nativeHelpers", [sys.executable, "scripts/smoke_native_helpers.py", "--executable",
                            str(target_dir / target / "macos-testing/Arcadium"),
                            "--output", "build/macos-native-helper-tests.json"], 600),
    ]


def hotfix_test_counts(name, output):
    text = output.decode("utf-8", errors="replace")
    if name == "pythonCompatibility":
        count = re.search(r"\bRan (\d+) tests? in ", text)
        if count is None or int(count[1]) < 15 or not re.search(r"(?m)^OK\s*$", text):
            raise ValueError("The Python compatibility suite did not pass at least 15 tests")
        return {"tests": int(count[1]), "passed": int(count[1]), "failed": 0}
    summary = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", text)
    names = re.findall(r"(?m)^test (game::launch::retired_mod_tests::\S+) \.\.\. ok\s*$", text)
    if summary is None or int(summary[1]) < 6 or int(summary[2]) != 0 or len(names) != int(summary[1]) or len(set(names)) != len(names):
        raise ValueError("The targeted HyInfo retirement suite did not pass at least six named tests")
    return {"tests": int(summary[1]) + int(summary[3]), "passed": int(summary[1]), "failed": int(summary[2]),
            "ignored": int(summary[3]), "filteredOut": int(summary[5]), "testNames": names}


def execute_hotfix(source, platform, target, target_dir, minimum, log, environment):
    path = source / "build/hotfix-checks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = {"schema": 1, "mode": "hotfix", "platform": platform, "passed": False,
              "componentHashesBefore": False, "componentHashesAfter": False, "steps": [],
              "skipped": {
                  "broadRustSuites": "Only the changed HyInfo retirement module is executed in hotfix mode.",
                  "jvmSuite": "Not executed in hotfix mode. Bundled Java component hashes are verified.",
                  "nativeCookieConsent": "Not executed in hotfix mode. Use package or consent mode when consent code changes.",
              }}

    def write_checks():
        path.write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")

    write_checks()
    verify_components(source)
    checks["componentHashesBefore"] = True
    write_checks()
    steps = hotfix_steps(target, target_dir, minimum)
    for index, (name, command, timeout) in enumerate(steps):
        step = {"name": name, "command": command, "status": "running"}
        checks["steps"].append(step)
        write_checks()
        print(f"Private hotfix step {index + 1}/{len(steps)} started", flush=True)
        log.write(f"Private hotfix step {index + 1}/{len(steps)}: {name}\n".encode())
        log.flush()
        capture = name in {"pythonCompatibility", "rustHyInfoRetirement"}
        try:
            result = subprocess.run(command, cwd=source, env=environment,
                                    stdout=subprocess.PIPE if capture else log,
                                    stderr=subprocess.STDOUT, timeout=timeout)
            if capture:
                log.write(result.stdout)
                log.flush()
            step["exitCode"] = result.returncode
            if result.returncode:
                step["status"] = "failed"
                write_checks()
                return result.returncode
            if capture:
                checks[name] = hotfix_test_counts(name, result.stdout)
            step["status"] = "passed"
        except Exception as error:
            step["status"] = "failed"
            step["error"] = str(error)
            write_checks()
            raise
        write_checks()
        print(f"Private hotfix step {index + 1}/{len(steps)} completed", flush=True)
    verify_components(source)
    checks["componentHashesAfter"] = True
    checks["passed"] = True
    write_checks()
    return 0


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


def native_baseline(source, platform):
    directory = source / "build/ci-native-baseline" / platform
    if not directory.is_dir():
        directory = directory.parent
    manifest = json.loads((directory / f"package-manifest-{platform}.json").read_text(encoding="utf-8"))
    if manifest.get("product") != "Arcadium Client" or manifest.get("platform") != platform:
        raise ValueError("Invalid native baseline manifest")
    name = manifest["archive"]
    if Path(name).name != name or name != f"ArcadiumClient-{manifest['launcherVersion']}-{platform}.app.tar.gz":
        raise ValueError("Invalid native baseline name")
    path = directory / name
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != manifest["installerSha256"]:
            raise ValueError("Native baseline archive checksum mismatch")
    destination = source / "build/mac-helpers-baseline" / platform
    destination.mkdir(parents=True, exist_ok=False)
    files = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    seen = set()
    seen_files = set()
    size = 0
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            relative = PurePosixPath(entry.name)
            if (not relative.parts or relative.parts[0] != "Arcadium Client.app"
                    or relative.is_absolute() or "\\" in entry.name
                    or any(part in {".", ".."} for part in relative.parts)
                    or str(relative) != entry.name or entry.name in seen
                    or not (entry.isdir() or entry.isfile())):
                raise ValueError("Invalid native baseline archive entry")
            seen.add(entry.name)
            size += entry.size
            if len(seen) > 10_000 or size > 1024 * 1024 * 1024:
                raise ValueError("Native baseline exceeds update archive limits")
            if entry.isfile():
                name = relative.relative_to("Arcadium Client.app").as_posix()
                if name not in files:
                    raise ValueError("Unlisted native baseline file")
                with archive.extractfile(entry) as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != files[name]:
                        raise ValueError("Native baseline payload checksum mismatch")
                seen_files.add(name)
            archive.extract(entry, destination, filter="data")
    if seen_files != set(files):
        raise ValueError("Native baseline payload list mismatch")
    executable = destination / "Arcadium Client.app/Contents/MacOS/Arcadium"
    arch = "arm64" if platform == "macos-arm64" else "x86_64"
    subprocess.run(["/usr/bin/lipo", str(executable), "-verify_arch", arch], check=True, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(executable.parents[2])],
                   check=True, capture_output=True)
    return executable


def java_fixture_environment(source, fixtures, environment):
    with zipfile.ZipFile(fixtures) as archive:
        relative = json.loads(archive.read("manifest.json")).get("testGameDirectory")
    if relative is None:
        return environment
    if not isinstance(relative, str):
        raise ValueError("Invalid JVM fixture selection")
    path = PurePosixPath(relative)
    if (not relative.startswith("build/forge-compat/runtime-qa/") or path.as_posix() != relative
            or any(part in {".", ".."} for part in path.parts) or any(c in relative for c in '\\:\"\r\n')):
        raise ValueError("Invalid JVM fixture selection")
    game = source.joinpath(*path.parts).resolve()
    if not game.is_relative_to(source.resolve()) or not game.is_dir():
        raise ValueError("The selected JVM fixture directory is unavailable")
    configured = dict(environment)
    for name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
        configured.pop(name, None)
    configured["JAVA_TOOL_OPTIONS"] = f'-Darcadium.forgeTest.gameDir="{game}"'
    return configured


def execute(source, platform, mode, log, environment):
    if mode not in PACKAGE_MODES | {"helpers", "consent"}:
        raise ValueError("Invalid private build mode")
    target = "aarch64-apple-darwin" if platform == "macos-arm64" else "x86_64-apple-darwin"
    minimum = "13.0" if platform == "macos-arm64" else "12.0"
    if environment.get("MACOSX_DEPLOYMENT_TARGET", minimum) != minimum:
        raise ValueError("Workflow and platform deployment targets disagree")
    target_dir = source / "target" / f"macos-{minimum}"
    jobs = min(os.cpu_count() or 2, 4 if platform == "macos-x64" else 2)
    environment.update(SQLX_OFFLINE="true", MACOSX_DEPLOYMENT_TARGET=minimum, CARGO_BUILD_JOBS=str(jobs),
                       RUSTUP_TOOLCHAIN="stable", CARGO_TARGET_DIR=str(target_dir))
    if mode == "consent":
        print("Private native cookie consent probe started", flush=True)
        result = subprocess.run([sys.executable, "scripts/test_native_cookie_consent.py", "--target", target,
                                 "--profile", "macos-testing", "--fetch-dependencies",
                                 "--output", "build/native-cookie-consent-tests.json"],
                                cwd=source, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        print("Private native cookie consent probe finished", flush=True)
        return result.returncode
    if mode == "helpers":
        prototype = source / "build/ci-native-baseline/keychain-prototype.json"
        if prototype.is_file():
            config = json.loads(prototype.read_text(encoding="utf-8"))
            if config != {"type": "keychain-prototype", "iterations": 32}:
                raise ValueError("Invalid Keychain prototype fixture")
            return subprocess.run([sys.executable, "scripts/run_macos_keychain_prototype.py", "--iterations", "32",
                                   "--output", "build/macos-native-helper-tests.json"], cwd=source,
                                  env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=600).returncode
        executable = native_baseline(source, platform)
        return subprocess.run([sys.executable, "scripts/diagnose_native_helpers.py", "--executable", str(executable),
                               "--output", "build/macos-native-helper-tests.json"], cwd=source,
                              env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=600).returncode
    if mode == "hotfix":
        return execute_hotfix(source, platform, target, target_dir, minimum, log, environment)
    verify_components(source)
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "scripts",
                             "-p", "test_macos_compatibility.py"], cwd=source, env=environment,
                            stdout=log, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        return result.returncode
    fixtures = source / "build/forge-compat-ci-fixtures.zip"
    if fixtures.is_file():
        java_commands = [
            [sys.executable, "scripts/forge_compat_ci.py", "restore", "--bundle", str(fixtures),
             "--source-root", str(source), "--home", str(Path.home())],
            ["sh", "game-branding/gradlew", "-p", "forge-compat", "test", "--no-daemon"],
            [sys.executable, "scripts/forge_compat_ci.py", "junit", "--bundle", str(fixtures),
             "--results", "forge-compat/build/test-results/test", "--output", "build/forge-compat-ci-tests.json"],
        ]
        for index, command in enumerate(java_commands):
            print(f"Private JVM verification step {index + 1}/{len(java_commands)} started", flush=True)
            command_environment = java_fixture_environment(source, fixtures, environment) if index == 1 else environment
            result = subprocess.run(command, cwd=source, env=command_environment, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=1200)
            if result.returncode:
                return result.returncode
    commands = [
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_auth", "--lib", "--tests", "--", "--test-threads=1"],
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_update", "-p", "arcadium_common", "-p", "arcadium_java",
         "-p", "arcadium_core", "-p", "arcadium_content", "-p", "arcadium_discord", "--lib", "--", "--test-threads=1"],
        ["cargo", "test", "--locked", "--profile", "macos-testing", "--target", target,
         "-p", "arcadium_app", "--lib", "account_service", "--", "--test-threads=1"],
        [sys.executable, "scripts/test_macos_updater.py"],
        [sys.executable, "scripts/test_native_cookie_consent.py", "--target", target,
         "--profile", "macos-testing", "--output", "build/native-cookie-consent-tests.json"],
        [sys.executable, "scripts/build_macos.py", "--target", target],
        [sys.executable, "scripts/check_macos_compatibility.py", "--binary",
         str(target_dir / target / "macos-testing/Arcadium"), "--target", target, "--minimum", minimum,
         "--static-root", str(target_dir / target / "macos-testing"), "--fetch-sdk",
         "--output", "build/macos-compatibility-tests.json"],
        [sys.executable, "scripts/smoke_native_helpers.py", "--executable",
         str(target_dir / target / "macos-testing/Arcadium"), "--output", "build/macos-native-helper-tests.json"],
    ]
    for index, command in enumerate(commands):
        print(f"Private build step {index + 1}/{len(commands)} started", flush=True)
        log.write(f"Private build step {index + 1}/{len(commands)}\n".encode())
        log.flush()
        result = subprocess.run(command, cwd=source, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=7200)
        if result.returncode:
            return result.returncode
        print(f"Private build step {index + 1}/{len(commands)} completed", flush=True)
    verify_components(source)
    return 0


def compiler_cache(source, repository, platform, key, log):
    helper = source / "scripts/private_build_cache.py"
    if not helper.is_file():
        return None
    spec = importlib.util.spec_from_file_location("private_build_cache", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    minimum = "13.0" if platform == "macos-arm64" else "12.0"
    config = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    identity = {"platform": platform, "minimum": minimum,
                "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
                "profiles": config["profile"]}
    target = (source / "target" / f"macos-{minimum}").resolve()
    if not target.is_relative_to(source.resolve()) or target.exists():
        raise ValueError("Compiler cache requires a new owned target directory")
    cache = repository / "encrypted-cache/native.enc"
    before = None
    if cache.is_symlink() or cache.parent.is_symlink():
        raise ValueError("Compiler cache must not contain links")
    if cache.is_file():
        try:
            result = module.restore_cache(cache, target, key, identity)
            if hasattr(module, "inventory"):
                before = module.inventory(target)
            log.write((json.dumps({"compilerCache": "restored", **result}) + "\n").encode())
            print("Encrypted compiler cache restored", flush=True)
        except Exception:
            log.write(traceback.format_exc().encode())
            if target.exists():
                if not target.is_relative_to(source.resolve()) or target.is_symlink():
                    raise ValueError("Invalid owned cache destination")
                shutil.rmtree(target)
            print("Compiler cache unavailable; using a clean build", flush=True)
    else:
        print("No compiler cache is available for this architecture", flush=True)
    return module, target, cache, identity, before


def seal(source, private_log, destination, platform, key, exit_code, mode="package"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=1, strict_timestamps=False) as archive:
        archive.write(private_log, "worker.log")
        archive.writestr("status.json", json.dumps({"platform": platform, "exitCode": exit_code, "mode": mode}))
        directory = source / "build/installers" / platform
        if directory.is_dir():
            for file in sorted(directory.iterdir()):
                if file.is_file() and (file.suffix in {".dmg", ".json", ".txt", ".md"}
                                      or file.name.endswith(".app.tar.gz")):
                    archive.write(file, file.relative_to(source).as_posix())
        for name in ["macos-native-helper-tests.json", "native-cookie-consent-tests.json", "macos-compatibility-tests.json"]:
            if mode == "hotfix" and name == "native-cookie-consent-tests.json":
                continue
            test_result = source / "build" / name
            if test_result.is_file():
                archive.write(test_result, test_result.relative_to(source).as_posix())
        if mode == "hotfix":
            checks = source / "build/hotfix-checks.json"
            if checks.is_file():
                archive.write(checks, checks.relative_to(source).as_posix())
        else:
            java_result = source / "build/forge-compat-ci-tests.json"
            if java_result.is_file():
                archive.write(java_result, java_result.relative_to(source).as_posix())
            for test_result in sorted((source / "forge-compat/build/test-results/test").glob("TEST-*.xml")):
                if test_result.is_file() and test_result.stat().st_size <= 16 * 1024 * 1024:
                    archive.write(test_result, test_result.relative_to(source).as_posix())
    nonce = os.urandom(12)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(nonce + AESGCM(key).encrypt(nonce, output.getvalue(), RESULT_AAD))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True, choices=["macos-arm64", "macos-x64"])
    parser.add_argument("--mode", choices=["package", "hotfix", "helpers", "consent"], default="package")
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
            cache = compiler_cache(source, repository, args.platform, key, log) if args.mode in PACKAGE_MODES else None
            exit_code = execute(source, args.platform, args.mode, log, dict(os.environ))
            if exit_code == 0 and cache is not None:
                module, target, destination, identity, before = cache
                try:
                    if before is not None and module.inventory(target) == before:
                        log.write((json.dumps({"compilerCache": "unchanged", "files": len(before)}) + "\n").encode())
                        print("Reusing the unchanged encrypted compiler cache", flush=True)
                    else:
                        result = module.save_cache(target, destination, key, identity)
                        log.write((json.dumps({"compilerCache": "saved", **result}) + "\n").encode())
                        print("Encrypted compiler cache is ready for reuse", flush=True)
                except Exception:
                    log.write(traceback.format_exc().encode())
                    destination.unlink(missing_ok=True)
                    print("Compiler cache could not be saved", flush=True)
        except Exception:
            log.write(traceback.format_exc().encode())
    seal(source, private_log, repository / "encrypted-output" / f"{args.platform}.enc",
         args.platform, key, exit_code, args.mode)
    print(f"Encrypted build diagnostics are ready. Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Private build infrastructure failed before encrypted results were ready.", file=sys.stderr)
        raise SystemExit(1) from None
