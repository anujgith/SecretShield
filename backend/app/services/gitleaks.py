import json
import os
import subprocess
from pathlib import Path


GITLEAKS_PATH = os.environ.get(
    "GITLEAKS_PATH",
    r"C:\gitleaks\gitleaks.exe",
)


def run_gitleaks(repository_path: str) -> list[dict]:
    repo = Path(repository_path).resolve()

    if not repo.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo}")

    if not repo.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo}")

    command = [
    GITLEAKS_PATH,
    "detect",
    "--source",
    str(repo),
    "--no-git",
    "--report-format",
    "json",
    "--report-path",
    "-",
    "--no-banner",
    "--redact=100",
]
    

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    # Gitleaks normally returns:
    # 0 = no leaks found
    # 1 = leaks found
    # other = execution/configuration error
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Gitleaks failed with exit code {result.returncode}."
        )

    output = result.stdout.strip()

    if not output:
        return []
    try:
        findings = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Could not parse Gitleaks JSON output.") from exc

    if not isinstance(findings, list):
        raise RuntimeError("Unexpected Gitleaks output format.")

    # Keep only metadata needed downstream. Gitleaks reports may contain raw
    # values in fields such as Match, Secret, or Raw; they must not escape.
    safe_fields = {
        "RuleID", "Description", "File", "StartLine", "StartColumn",
        "Commit", "Fingerprint",
    }
    return [
        {key: value for key, value in finding.items() if key in safe_fields}
        for finding in findings
        if isinstance(finding, dict)
    ]
