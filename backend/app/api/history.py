from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.scan import ScanRequest
from app.services.audit import record_audit_event
from app.services.git_history import scan_git_history
from app.services.policy import evaluate_policy
from app.services.risk_engine import calculate_risk


router = APIRouter(tags=["Git History"])


@router.post(
    "/history-scan",
    summary="Scan Git history for historical secrets",
    description=(
        "Scans all Git revisions in the supplied local repository path. "
        "Returns finding metadata and policy decisions without storing "
        "historical findings as incidents or exposing secret values."
    ),
)
def history_scan(request: ScanRequest, db: Session = Depends(get_db)):
    record_audit_event(
        db,
        "HISTORY",
        "Git history scan started.",
        repository=request.repository_path,
    )
    try:
        raw_findings = scan_git_history(request.repository_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Git history scan failed.",
        ) from exc

    findings = []
    for finding in raw_findings:
        risk = calculate_risk(finding)
        policy = evaluate_policy(
            severity=risk["severity"],
            secret_type=finding.get("RuleID"),
            risk_score=risk["score"],
        )
        findings.append(
            {
                "source": "git-history",
                "rule_id": finding.get("RuleID"),
                "description": finding.get("Description"),
                "file": finding.get("File"),
                "line": finding.get("StartLine"),
                "column": finding.get("StartColumn"),
                "commit_hash": finding.get("Commit"),
                "fingerprint": finding.get("Fingerprint"),
                "secret_type": finding.get("RuleID"),
                "risk_score": risk["score"],
                "severity": risk["severity"],
                "risk_reasons": risk["reasons"],
                "policy": policy,
            }
        )

    record_audit_event(
        db,
        "HISTORY",
        f"Git history scan completed with {len(findings)} finding(s).",
        repository=request.repository_path,
    )
    for finding in findings:
        record_audit_event(
            db,
            "RISK",
            f"Historical risk score {finding['risk_score']} / {finding['severity']}.",
            repository=request.repository_path,
        )
        record_audit_event(
            db,
            "POLICY",
            f"Historical policy decision {finding['policy']['action']}.",
            repository=request.repository_path,
        )
        record_audit_event(
            db,
            "HISTORY",
            f"Historical {finding['secret_type'] or 'secret'} detected in commit {finding['commit_hash'] or 'unknown'}.",
            repository=request.repository_path,
        )

    return {
        "status": "completed",
        "source": "git-history",
        "repository_path": request.repository_path,
        "findings_count": len(findings),
        "findings": findings,
    }
