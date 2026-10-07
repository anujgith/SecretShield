"""SecretShield command line interface."""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

HOOK_MARKER = "# SecretShield managed pre-commit hook"


def _database_path() -> Path:
    configured = os.environ.get("SECRET_SHIELD_DATABASE_PATH")
    if configured:
        path = Path(configured).expanduser().resolve()
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
        path = base / "SecretShield" / "secretshield.db"
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "secretshield/secretshield.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args], capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Git executable was not found.") from exc
    if result.returncode:
        raise RuntimeError("The current directory is not a Git repository.")
    return result.stdout.strip()


def _hook_path(repository: Path) -> tuple[Path, Path]:
    root = Path(_git(repository.resolve(), "rev-parse", "--show-toplevel")).resolve()
    hook_dir = Path(_git(root, "rev-parse", "--git-path", "hooks"))
    if not hook_dir.is_absolute():
        hook_dir = (root / hook_dir).resolve()
    return root, hook_dir / "pre-commit"


def _protect(repository: Path) -> int:
    try:
        root, hook = _hook_path(repository)
        hook.parent.mkdir(parents=True, exist_ok=True)
        if hook.exists() and HOOK_MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
            print(f"An unrecognized pre-commit hook exists at {hook}; it was left untouched.", file=sys.stderr)
            return 1
        contents = "\n".join((
            "#!/bin/sh", HOOK_MARKER, "set -eu",
            'repository_root=$(git rev-parse --show-toplevel) || exit 2',
            'cd "$repository_root"',
            "exec secretshield scan --staged", "",
        ))
        temporary = hook.with_name(hook.name + ".secretshield-tmp")
        temporary.write_text(contents, encoding="utf-8", newline="\n")
        if os.name != "nt":
            temporary.chmod(temporary.stat().st_mode | 0o111)
        os.replace(temporary, hook)
        print(f"SecretShield protection installed for {root}.")
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"Could not install SecretShield protection: {exc}", file=sys.stderr)
        return 1


def _status(repository: Path) -> int:
    try:
        _root, hook = _hook_path(repository)
        if hook.is_file() and HOOK_MARKER in hook.read_text(encoding="utf-8", errors="replace"):
            print("SecretShield protection is installed.")
            return 0
        print("SecretShield protection is not installed.")
        return 1
    except (RuntimeError, OSError) as exc:
        print(f"Could not check SecretShield protection: {exc}", file=sys.stderr)
        return 2


def _unprotect(repository: Path) -> int:
    try:
        _root, hook = _hook_path(repository)
        if not hook.exists():
            print("SecretShield protection is not installed.")
        elif HOOK_MARKER in hook.read_text(encoding="utf-8", errors="replace"):
            hook.unlink()
            print("SecretShield managed hook removed.")
        else:
            print(f"Unrecognized pre-commit hook at {hook}; it was left untouched.")
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"Could not remove SecretShield protection: {exc}", file=sys.stderr)
        return 1


def _scan_current(repository: Path) -> int:
    repository = repository.expanduser().resolve()
    if not repository.exists():
        print(f"Repository path does not exist: {repository}", file=sys.stderr)
        return 2
    if not repository.is_dir():
        print("Repository path is not a directory.", file=sys.stderr)
        return 2
    os.environ["SECRET_SHIELD_DATABASE_PATH"] = str(_database_path())
    from app.core.database import Base, SessionLocal, engine
    from app.services.scan import scan_repository

    try:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            result = scan_repository(str(repository), db)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 2

    print("+--------------------------------------------------+")
    print("|              SECRET SHIELD                      |")
    print("|                 Security Scan                   |")
    print("+--------------------------------------------------+")
    print(f"\nRepository: {repository.name}\n\nScanning...\n")
    from app.services.policy import evaluate_policy
    decisions = []
    for finding in result.findings:
        policy = evaluate_policy(finding.severity, finding.secret_type, finding.risk_score)
        decisions.append(policy["action"])
        print("[DETECTION]")
        print(f"  Secret Type : {finding.secret_type or 'secret'}")
        print(f"  File        : {finding.file or '<unknown>'}")
        print(f"  Line        : {finding.line if finding.line is not None else '—'}")
        print(f"  Risk Score  : {finding.risk_score}")
        print(f"  Severity    : {finding.severity}")
        print(f"  Policy      : {policy['action']}")
        print(f"  Incident ID : {finding.incident_id}\n")
    if not decisions:
        print("No secrets detected.\n")
    if "BLOCK" in decisions:
        print("[SECURITY]\n  BLOCKED")
    elif "REVIEW" in decisions:
        print("[SECURITY]\n  REVIEW REQUIRED")
    elif "WARN" in decisions:
        print("[SECURITY]\n  WARNING")
    else:
        print("[SECURITY]\n  ALLOWED")
    return 1 if any(action in {"BLOCK", "REVIEW"} for action in decisions) else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="secretshield", description="SecretShield secret scanning and repository protection.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Scan current files or staged changes.")
    scan_parser.add_argument("path", nargs="?", default=".", help="Repository path (default: current directory).")
    scan_parser.add_argument("--staged", action="store_true", help="Scan only staged Git changes.")
    commands.add_parser("protect", help="Install the managed pre-commit hook.")
    commands.add_parser("status", help="Show whether repository protection is installed.")
    commands.add_parser("unprotect", help="Remove the SecretShield managed hook.")
    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.staged:
            if args.path != ".":
                parser.error("--staged does not accept a repository path; run it inside the target repository.")
            from app.services.staged_scan import scan_staged
            return scan_staged(Path.cwd())
        return _scan_current(Path(args.path))
    repository = Path.cwd()
    if args.command == "protect":
        return _protect(repository)
    if args.command == "status":
        return _status(repository)
    return _unprotect(repository)


if __name__ == "__main__":
    raise SystemExit(main())
