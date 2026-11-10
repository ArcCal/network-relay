"""Check the real native-test wrapper with stub compiler products, not macOS."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TARGET = "arm64-apple-macosx27.0"
TOOL = r'''import json, os, pathlib, sys
args = sys.argv[1:]
if pathlib.Path(sys.argv[0]).name == "xcrun":
    if args == ["--find", "swiftc"]:
        print(os.environ["TLS_TEST_COMPILER"])
    elif args == ["--sdk", "macosx", "--show-sdk-path"]:
        if os.environ.get("TLS_TEST_SDK_FAIL"):
            print("fixture SDK selection failed", file=sys.stderr)
            raise SystemExit(19)
        print(os.environ["TLS_TEST_SDK"])
    elif args[:1] == ["swiftc"]:
        compiler = os.environ["TLS_TEST_COMPILER"]
        os.execv(compiler, [compiler, *args[1:]])
    else:
        raise SystemExit("unexpected xcrun invocation: " + repr(args))
else:
    with open(os.environ["TLS_TEST_COMMANDS"], "a") as log:
        log.write(json.dumps(args) + "\n")
    if os.environ.get("TLS_TEST_COMPILER_FAIL"):
        print("fixture compiler failure", file=sys.stderr)
        raise SystemExit(23)
    if os.environ.get("TLS_TEST_DARWIN_FLAGS") == "1":
        for flag, expected in (("-sdk", os.environ["TLS_TEST_SDK"]),
                               ("-target", "arm64-apple-macosx27.0")):
            if flag not in args or args[args.index(flag) + 1] != expected:
                print("fixture cannot load Darwin standard library without explicit SDK/target", file=sys.stderr)
                raise SystemExit(86)
    elif "-sdk" in args or "-target" in args:
        raise SystemExit("portable invocation unexpectedly received Darwin flags")
    output = pathlib.Path(args[args.index("-o") + 1])
    if "-emit-object" in args:
        output.write_text("fixture object\n")
        pathlib.Path(args[args.index("-emit-module-path") + 1]).write_text("fixture module\n")
    else:
        output.write_text("#!" + sys.executable + "\nimport os\n"
                          "with open(os.environ['TLS_TEST_EXECUTED'], 'a') as log: "
                          "log.write(" + repr(output.name + "\n") + ")\n")
        output.chmod(0o755)
'''


class NativeTlsBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-tls-build-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.native = self.base / "network-relay-nf"
        for relative in (
            "scripts/test-native.sh", "scripts/test-tls-errors.py",
            "App/Sources/NetworkRelayNF/NativeClient.swift",
            "App/Sources/NetworkRelayNFBridge/include/NetworkRelayNFBridge.h",
        ):
            destination = self.native / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "network-relay-nf" / relative, destination)
        model = self.native / "App/Sources/NetworkRelayNFModel/Fixture.swift"
        model.parent.mkdir(parents=True)
        model.write_text("// Compiler fixture; no native framework code is executed.\n")
        tools = self.base / "tools"
        tools.mkdir()
        for name in ("xcrun", "swiftc"):
            path = tools / name
            path.write_text(f"#!{sys.executable}\n" + TOOL)
            path.chmod(0o755)
        self.sdk = self.base / "Xcode 27.app/SDKs/MacOSX27.sdk"
        self.sdk.mkdir(parents=True)
        self.commands = self.base / "commands.jsonl"
        self.executed = self.base / "executed.txt"
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                        TLS_TEST_COMPILER=str(tools / "swiftc"), TLS_TEST_SDK=str(self.sdk),
                        TLS_TEST_COMMANDS=str(self.commands), TLS_TEST_EXECUTED=str(self.executed),
                        TLS_TEST_DARWIN_FLAGS="1", MACOSX_DEPLOYMENT_TARGET="27.0")
        self.env.pop("TLS_TEST_SDK_FAIL", None)
        self.env.pop("TLS_TEST_COMPILER_FAIL", None)

    def wrapper(self, **environment):
        return subprocess.run(["bash", str(self.native / "scripts/test-native.sh"), str(self.base / "lib")],
                              env=dict(self.env, **environment), capture_output=True, text=True, timeout=15)

    def compiled(self):
        return [json.loads(line) for line in self.commands.read_text().splitlines()] if self.commands.exists() else []

    def programs(self):
        return self.executed.read_text().splitlines() if self.executed.exists() else []

    def test_all_native_compiles_use_the_selected_sdk_and_deployment_target(self):
        result = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.compiled()
        self.assertEqual(len(commands), 3)
        for command in commands:
            self.assertEqual(command[command.index("-sdk") + 1], str(self.sdk))
            self.assertEqual(command[command.index("-target") + 1], TARGET)
        self.assertEqual(self.programs(), ["tls-check", "native-smoke"])

    def test_sdk_selection_failure_stops_before_compilation(self):
        result = self.wrapper(TLS_TEST_SDK_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture SDK selection failed", result.stderr)
        self.assertEqual(self.compiled(), [])
        self.assertEqual(self.programs(), [])

    def test_compiler_failure_is_not_skipped(self):
        result = self.wrapper(TLS_TEST_COMPILER_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture compiler failure", result.stderr)
        self.assertEqual(len(self.compiled()), 1)
        self.assertEqual(self.programs(), [])

    def test_portable_tls_cli_does_not_add_darwin_flags(self):
        result = subprocess.run(
            [sys.executable, str(self.native / "scripts/test-tls-errors.py"),
             "--swiftc", self.env["TLS_TEST_COMPILER"]],
            env=dict(self.env, TLS_TEST_DARWIN_FLAGS="0"), capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.compiled()
        self.assertEqual(len(commands), 1)
        self.assertNotIn("-sdk", commands[0])
        self.assertNotIn("-target", commands[0])
        self.assertEqual(self.programs(), ["tls-check"])


if __name__ == "__main__":
    unittest.main()
