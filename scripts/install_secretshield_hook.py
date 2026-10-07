#!/usr/bin/env python3
"""Install SecretShield's local pre-commit hook into a Git repository."""

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


HOOK_MARKER = "# SecretShield managed pre-commit hook"


def _git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Git executable was not found.") from exc
    if result.returncode != 0:
        raise RuntimeError("The target directory is not a Git repository.")
    return result.stdout.strip()


def _shell_path(path: Path) -> str:
    value = str(path.resolve())
    if os.name == "nt":
        value = value.replace("\\", "/")
    return shlex.quote(value)


def _hook_contents(scanner: Path, python: Path) -> str:
    return "\n".join(
        [
            "#!/bin/sh",
            HOOK_MARKER,
            "set -eu",
            'repository_root=$(git rev-parse --show-toplevel) || {',
            '  echo "SecretShield could not locate the Git repository root." >&2',
            "  exit 2",
            "}",
            f"exec {_shell_path(python)} {_shell_path(scanner)} --repository \"$repository_root\"",
            "",
        ]
    )


def install(repository: Path) -> Path:
    try:
        root = Path(_git(repository.resolve(), "rev-parse", "--show-toplevel")).resolve()
        hooks_dir_value = _git(root, "rev-parse", "--git-path", "hooks")
    except RuntimeError:
        raise

    hooks_dir = Path(hooks_dir_value)
    if not hooks_dir.is_absolute():
        hooks_dir = (root / hooks_dir).resolve()
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        current = hook_path.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in current:
            raise RuntimeError(
                f"An existing pre-commit hook is present at {hook_path}; it was left unchanged."
            )

    scanner = Path(__file__).resolve().with_name("secretshield_precommit.py")
    if not scanner.is_file():
        raise RuntimeError("SecretShield pre-commit scanner is missing from this checkout.")

    contents = _hook_contents(scanner, Path(sys.executable))
    descriptor, temporary_name = tempfile.mkstemp(prefix="pre-commit-", dir=hooks_dir)
    os.close(descriptor)
    temporary_hook = Path(temporary_name)
    try:
        temporary_hook.write_text(contents, encoding="utf-8", newline="\n")
        if os.name != "nt":
            temporary_hook.chmod(temporary_hook.stat().st_mode | 0o111)
        os.replace(temporary_hook, hook_path)
    finally:
        if temporary_hook.exists():
            temporary_hook.unlink()
    return hook_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install SecretShield's local pre-commit hook into a Git repository."
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git repository to install into (defaults to the current directory).",
    )
    args = parser.parse_args()
    try:
        hook_path = install(args.repository)
    except RuntimeError as exc:
        print(f"SecretShield hook installation failed: {exc}", file=sys.stderr)
        return 1
    print(f"SecretShield pre-commit hook installed at: {hook_path}")
    print("Make sure Gitleaks is installed and available to the hook.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
