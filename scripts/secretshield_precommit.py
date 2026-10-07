#!/usr/bin/env python3
"""Apply SecretShield policy to the safe, relevant staged files in a commit."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

# On non-Windows systems, prefer the Gitleaks executable found on PATH. The
# existing service's Windows default remains available as its fallback.
if not os.environ.get("GITLEAKS_PATH"):
    discovered_gitleaks = shutil.which("gitleaks")
    if discovered_gitleaks:
        os.environ["GITLEAKS_PATH"] = discovered_gitleaks

from app.services.gitleaks import GITLEAKS_PATH
from app.services.policy import evaluate_policy
from app.services.risk_engine import calculate_risk


FAIL_ACTIONS = {"BLOCK", "REVIEW"}
GENERATED_DIRECTORIES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    "out",
    "target",
    "coverage",
}
DATABASE_SUFFIXES = {
    ".db",
    ".db-shm",
    ".db-wal",
    ".sqlite",
    ".sqlite-shm",
    ".sqlite-wal",
    ".sqlite3",
}
REGULAR_BLOB_MODES = {b"100644", b"100755", b"120000"}


class ScannerError(Exception):
    """A safe-to-report pre-commit scanner/configuration error."""


def _git(repository: Path, *arguments: str, env=None, input_bytes=None):
    binary_mode = input_bytes is not None or "-z" in arguments
    try:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=not binary_mode,
            encoding=None if binary_mode else "utf-8",
            errors=None if binary_mode else "replace",
            input=input_bytes,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError("Git executable was not found.") from exc


def _git_root(repository: Path) -> Path:
    result = _git(repository, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        raise ScannerError("The target directory is not a Git repository.")
    return Path(result.stdout.strip()).resolve()


def _staged_paths(repository: Path) -> list[bytes]:
    result = _git(
        repository,
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
    )
    if result.returncode != 0:
        raise ScannerError("Could not read staged file names from Git.")
    return [path for path in result.stdout.split(b"\0") if path]


def _ignored_paths(repository: Path, paths: list[bytes]) -> set[bytes]:
    if not paths:
        return set()
    result = _git(
        repository,
        "check-ignore",
        "--no-index",
        "-z",
        "--stdin",
        input_bytes=b"\0".join(paths) + b"\0",
    )
    if result.returncode not in (0, 1):
        raise ScannerError("Could not check Git ignore rules for staged files.")
    return {path for path in result.stdout.split(b"\0") if path}


def _is_relevant(path_bytes: bytes) -> bool:
    path = os.fsdecode(path_bytes).replace("\\", "/")
    parts = [part.lower() for part in path.split("/")]
    if any(part in GENERATED_DIRECTORIES for part in parts):
        return False
    if Path(parts[-1]).suffix.lower() in DATABASE_SUFFIXES:
        return False
    return True


def _index_entries(repository: Path) -> dict[bytes, tuple[bytes, bytes, bytes]]:
    result = _git(repository, "ls-files", "--stage", "-z")
    if result.returncode != 0:
        raise ScannerError("Could not read staged Git index entries.")

    entries = {}
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, path = entry.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
        except ValueError as exc:
            raise ScannerError("Git returned an invalid staged index entry.") from exc
        if stage == b"0":
            entries[path] = (mode, object_id, stage)
    return entries


def _create_filtered_index(
    repository: Path,
    index_path: Path,
    staged_paths: list[bytes],
    ignored_paths: set[bytes],
) -> int:
    entries = _index_entries(repository)
    selected_records = []
    selected_count = 0

    for path in staged_paths:
        if path in ignored_paths or not _is_relevant(path):
            continue
        entry = entries.get(path)
        if entry is None:
            # Deleted files do not appear in staged_paths; a missing index
            # entry here means Git has no stage-0 blob to inspect.
            continue
        mode, object_id, _stage = entry
        if mode not in REGULAR_BLOB_MODES or set(object_id) == {ord("0")}:
            continue
        selected_records.append(mode + b" " + object_id + b"\t" + path + b"\0")
        selected_count += 1

    index_env = os.environ.copy()
    index_env["GIT_INDEX_FILE"] = str(index_path)

    head = _git(repository, "rev-parse", "--verify", "HEAD", env=index_env)
    read_tree_target = "HEAD" if head.returncode == 0 else "--empty"
    initialized = _git(repository, "read-tree", read_tree_target, env=index_env)
    if initialized.returncode != 0:
        raise ScannerError("Could not prepare a filtered Git index for scanning.")

    if selected_records:
        updated = _git(
            repository,
            "update-index",
            "-z",
            "--index-info",
            env=index_env,
            input_bytes=b"".join(selected_records),
        )
        if updated.returncode != 0:
            raise ScannerError("Could not prepare staged files for scanning.")

    return selected_count


def _run_gitleaks_staged(repository: Path, index_path: Path) -> list[dict]:
    index_env = os.environ.copy()
    index_env["GIT_INDEX_FILE"] = str(index_path)
    command = [
        GITLEAKS_PATH,
        "protect",
        "--source",
        str(repository),
        "--staged",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
        "--no-color",
        "--redact=100",
        "--log-level",
        "error",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            env=index_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError(
            "Gitleaks executable was not found. Install Gitleaks or set GITLEAKS_PATH."
        ) from exc
    except OSError as exc:
        raise ScannerError(f"Could not start Gitleaks ({exc.__class__.__name__}).") from exc

    if result.returncode not in (0, 1):
        raise ScannerError(
            f"Gitleaks staged scan failed with exit code {result.returncode}."
        )
    try:
        findings = json.loads(result.stdout or "[]")
    except ValueError as exc:
        raise ScannerError("Could not parse Gitleaks staged scan output.") from exc
    if not isinstance(findings, list):
        raise ScannerError("Gitleaks returned an unexpected report format.")
    return findings


def _safe_file(finding: dict, repository: Path) -> str:
    reported = str(finding.get("File") or "<unknown>").replace("\r", "").replace("\n", "")
    try:
        candidate = Path(reported)
        if candidate.is_absolute():
            reported = candidate.resolve().relative_to(repository).as_posix()
    except (OSError, ValueError):
        pass
    return reported[:200]


def _local_finding_id(finding: dict, repository: Path) -> str:
    """Build a stable display ID from metadata only, never the secret value."""
    fingerprint = finding.get("Fingerprint")
    identity = "\0".join(
        (
            str(repository.resolve()),
            _safe_file(finding, repository),
            str(finding.get("RuleID") or "secret"),
            str(fingerprint or finding.get("Commit") or ""),
            str(finding.get("StartLine") or ""),
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()
    return f"SS-LOCAL-{digest[:8].upper()}"


def _dashboard_border(char: str = "=") -> str:
    return char * 72


def _report(findings: list[dict], repository: Path) -> bool:
    print("+" + _dashboard_border("-") + "+")
    print("|" + " SECRET SHIELD  |  PRE-COMMIT SECURITY GATE ".center(72) + "|")
    print("+" + _dashboard_border("-") + "+")
    print(f"Repository : {repository.name}")
    print("Scan       : Staged changes")
    print("Scanner    : Gitleaks")
    print("\n[SCAN]")
    print("  Scanning staged changes..." if findings else "  No secrets detected in staged changes.")

    should_block = False
    for finding in findings:
        risk = calculate_risk(finding)
        policy = evaluate_policy(
            severity=risk["severity"],
            secret_type=finding.get("RuleID"),
            risk_score=risk["score"],
        )
        action = str(policy["action"]).upper()
        should_block = should_block or action in FAIL_ACTIONS
        print("\n[DETECTION]")
        print(f"  Finding ID : {_local_finding_id(finding, repository)} (local display ID)")
        print(f"  Secret Type: {finding.get('RuleID') or 'secret'}")
        print(f"  File       : {_safe_file(finding, repository)}")
        line = finding.get("StartLine")
        if line is not None:
            print(f"  Line       : {line}")
        print(f"  Severity   : {risk['severity']}")
        print(f"  Risk Score : {risk['score']}")
        print(f"  Policy     : {action}")
        print("\n[RISK ANALYSIS]")
        for reason in risk.get("reasons", []):
            print(f"  * {reason}")
        print(f"  Decision   : {action}")

    print("\n[SECURITY GATE]")
    if should_block:
        print("  COMMIT BLOCKED")
        print("  Reason: SecretShield policy requires review before commit.")
        print("\n" + _dashboard_border())
        print("  SecretShield prevented a potentially unsafe commit.")
        print(_dashboard_border())
    else:
        print("  COMMIT ALLOWED")
        print("\n" + _dashboard_border())
        print("  SecretShield found no staged secrets requiring action.")
        print(_dashboard_border())
    return should_block


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan only relevant staged changes with SecretShield policy."
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git repository to scan (defaults to the current directory).",
    )
    args = parser.parse_args()

    try:
        repository = _git_root(args.repository.resolve())
        staged_paths = _staged_paths(repository)
        if not staged_paths:
            _report([], repository)
            return 0

        ignored_paths = _ignored_paths(repository, staged_paths)
        with tempfile.TemporaryDirectory(prefix="secretshield-index-") as temp_dir:
            filtered_index = Path(temp_dir) / "index"
            selected_count = _create_filtered_index(
                repository,
                filtered_index,
                staged_paths,
                ignored_paths,
            )
            if selected_count == 0:
                _report([], repository)
                return 0
            findings = _run_gitleaks_staged(repository, filtered_index)
        return 1 if _report(findings, repository) else 0
    except ScannerError as exc:
        print(f"SecretShield pre-commit scan error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"SecretShield pre-commit scan failed unexpectedly ({exc.__class__.__name__}).",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
