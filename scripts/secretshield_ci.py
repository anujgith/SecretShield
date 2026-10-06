#!/usr/bin/env python3
"""Run SecretShield's current-file and Git-history policy checks in CI."""

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.git_history import scan_git_history
from app.services.gitleaks import run_gitleaks
from app.services.policy import evaluate_policy
from app.services.risk_engine import calculate_risk


FAIL_ACTIONS = {"BLOCK", "REVIEW"}


def _safe_location(finding: dict) -> str:
    file_path = str(finding.get("File") or "<unknown>")
    file_path = file_path.replace("\r", "").replace("\n", "")[:200]
    line = finding.get("StartLine")
    return f"{file_path}:{line}" if line is not None else file_path


def _evaluate_findings(source: str, findings: list[dict]) -> tuple[int, bool]:
    failures = 0
    print(f"\n{source}: {len(findings)} finding(s)")

    for finding in findings:
        risk = calculate_risk(finding)
        policy = evaluate_policy(
            severity=risk["severity"],
            secret_type=finding.get("RuleID"),
            risk_score=risk["score"],
        )
        action = policy["action"].upper()
        if action in FAIL_ACTIONS:
            failures += 1

        commit = finding.get("Commit")
        commit_summary = f" commit={str(commit)[:12]}" if commit else ""
        print(
            f"[{action}] {finding.get('RuleID') or 'secret'} "
            f"severity={risk['severity']} risk={risk['score']} "
            f"location={_safe_location(finding)}{commit_summary}"
        )

    return len(findings), failures > 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SecretShield's policy gate on a local Git repository."
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository directory to scan (defaults to this project root).",
    )
    args = parser.parse_args()
    repository = args.repository.resolve()

    try:
        current_findings = run_gitleaks(str(repository))
        history_findings = scan_git_history(str(repository))
    except FileNotFoundError:
        print(
            "SecretShield CI scan failed: repository or Gitleaks executable not found.",
            file=sys.stderr,
        )
        return 2
    except ValueError as exc:
        print(f"SecretShield CI scan failed: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"SecretShield CI scan failed: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("SecretShield CI scan failed unexpectedly.", file=sys.stderr)
        return 2

    _, current_failed = _evaluate_findings("CURRENT FILES", current_findings)
    _, history_failed = _evaluate_findings("GIT HISTORY", history_findings)
    if current_failed or history_failed:
        print("\nSecretShield policy decision: FAIL (BLOCK or REVIEW requires action).")
        return 1

    print("\nSecretShield policy decision: PASS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
