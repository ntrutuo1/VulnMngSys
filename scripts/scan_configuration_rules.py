from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


DEFAULT_RULE_FILE = PROJECT_ROOT / "rules" / "Windows_Server_2022_rules.json"
RULE_COMMAND_FIELDS = ("powershell_check", "command", "shell_command")
RULE_REQUIRED_KEYS = ("code", "title")


@dataclass(frozen=True, slots=True)
class RuleSpec:
    code: str
    title: str
    command: str
    source_file: Path
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RuleScanResult:
    code: str
    title: str
    command: str
    source_file: Path
    returncode: int
    passed: bool
    stdout: str
    stderr: str


def _find_shell_executable() -> str:
    for candidate in ("pwsh", "powershell"):
        executable = shutil.which(candidate)
        if executable:
            return executable
    raise RuntimeError("No PowerShell executable found. Install pwsh or powershell.")


def _load_rule_file(rule_file: Path) -> list[RuleSpec]:
    raw_text = rule_file.read_text(encoding="utf-8")
    raw_rules = json.loads(raw_text)
    if not isinstance(raw_rules, list):
        raise ValueError(f"Rule file must contain a JSON list: {rule_file}")

    specs: list[RuleSpec] = []
    for index, item in enumerate(raw_rules, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule entry #{index} in {rule_file} must be a JSON object")

        missing = [key for key in RULE_REQUIRED_KEYS if key not in item]
        if missing:
            missing_list = ", ".join(missing)
            raise ValueError(f"Rule entry #{index} in {rule_file} is missing required keys: {missing_list}")

        command = ""
        for field_name in RULE_COMMAND_FIELDS:
            field_value = item.get(field_name)
            if field_value:
                command = str(field_value).strip()
                break

        if not command:
            raise ValueError(
                f"Rule entry #{index} in {rule_file} must define one of: {', '.join(RULE_COMMAND_FIELDS)}"
            )

        specs.append(
            RuleSpec(
                code=str(item["code"]),
                title=str(item["title"]),
                command=command,
                source_file=rule_file,
                metadata=dict(item),
            )
        )

    return specs


def _load_rules(rule_files: list[Path]) -> list[RuleSpec]:
    rules: list[RuleSpec] = []
    for rule_file in rule_files:
        if not rule_file.exists():
            raise FileNotFoundError(f"Rule file not found: {rule_file}")
        rules.extend(_load_rule_file(rule_file))
    return rules


def _run_rule_command(command: str) -> tuple[int, str, str]:
    shell = _find_shell_executable()
    completed = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _print_header(rule_files: list[Path]) -> None:
    print("VulnMngSys Configuration Rule Scan")
    print(f"Project root : {PROJECT_ROOT}")
    print("Rule files   :")
    for rule_file in rule_files:
        print(f"  - {rule_file}")
    print("")


def _print_result(result: RuleScanResult, show_command: bool) -> None:
    status = "PASS" if result.passed else "FAIL"
    print(f"[{status}] {result.code} - {result.title}")
    if show_command:
        print(f"  command: {result.command}")
    if result.stdout:
        print("  stdout :")
        for line in result.stdout.splitlines():
            print(f"    {line}")
    if result.stderr:
        print("  stderr :")
        for line in result.stderr.splitlines():
            print(f"    {line}")
    print("")


def _scan_rules(rules: list[RuleSpec]) -> list[RuleScanResult]:
    results: list[RuleScanResult] = []
    for rule in rules:
        returncode, stdout, stderr = _run_rule_command(rule.command)
        results.append(
            RuleScanResult(
                code=rule.code,
                title=rule.title,
                command=rule.command,
                source_file=rule.source_file,
                returncode=returncode,
                passed=returncode == 0,
                stdout=stdout,
                stderr=stderr,
            )
        )
    return results


def _export_json(results: list[RuleScanResult]) -> str:
    payload = [
        {
            "code": result.code,
            "title": result.title,
            "command": result.command,
            "source_file": str(result.source_file),
            "returncode": result.returncode,
            "passed": result.passed,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        for result in results
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan configuration rules using one command per rule entry"
    )
    parser.add_argument(
        "--rules-file",
        action="append",
        dest="rules_files",
        default=None,
        help="Path to a JSON rules file. Can be provided multiple times.",
    )
    parser.add_argument(
        "--show-command",
        action="store_true",
        help="Print the command used for each rule.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the final result as JSON instead of a text summary.",
    )
    args = parser.parse_args()

    rule_files = [Path(path).expanduser().resolve() for path in args.rules_files] if args.rules_files else [DEFAULT_RULE_FILE]
    rules = _load_rules(rule_files)

    if not args.json:
        _print_header(rule_files)

    results = _scan_rules(rules)

    if args.json:
        print(_export_json(results))
    else:
        for result in results:
            _print_result(result, args.show_command)

        total = len(results)
        passed = sum(1 for result in results if result.passed)
        failed = total - passed
        print(f"Summary: {passed}/{total} passed, {failed} failed")

    return 0 if all(result.passed for result in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())