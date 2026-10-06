import json
import subprocess
from pathlib import Path

from app.services.gitleaks import GITLEAKS_PATH


def scan_git_history(repository_path: str) -> list[dict]:
    """Scan every Git revision in a repository with Gitleaks."""
    repository = Path(repository_path).resolve()

    if not repository.exists():
        raise FileNotFoundError(
            f"Repository path does not exist: {repository}"
        )
    if not repository.is_dir():
        raise ValueError("Repository path is not a directory.")

    try:
        git_check = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Git executable was not found.") from exc

    if git_check.returncode != 0 or git_check.stdout.strip() != "true":
        raise ValueError("Repository path is not a Git repository.")

    command = [
        GITLEAKS_PATH,
        "detect",
        "--source",
        str(repository),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Gitleaks executable was not found.") from exc

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Gitleaks history scan failed with exit code {result.returncode}."
        )

    output = result.stdout.strip()
    if not output:
        return []

    try:
        findings = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Could not parse Gitleaks history scan output.") from exc

    if not isinstance(findings, list):
        raise RuntimeError("Unexpected Gitleaks history scan output format.")

    return findings
