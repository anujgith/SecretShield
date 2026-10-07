from uuid import uuid4

from app.models.incident import Incident
from app.schemas.scan import ScanFinding, ScanResponse
from app.services.audit import record_audit_event
from app.services.gitleaks import run_gitleaks
from app.services.policy import evaluate_policy
from app.services.risk_engine import calculate_risk


def scan_repository(repository_path: str, db) -> ScanResponse:
    """Scan current files and persist metadata-only incidents."""
    record_audit_event(
        db, "SCAN", "Current-file repository scan started.",
        repository=repository_path,
    )
    raw_findings = run_gitleaks(repository_path)
    findings = []
    audit_findings = []

    for finding in raw_findings:
        risk = calculate_risk(finding)
        policy = evaluate_policy(
            severity=risk["severity"],
            secret_type=finding.get("RuleID"),
            risk_score=risk["score"],
        )
        incident_id = f"INC-{uuid4().hex[:8].upper()}"
        incident = Incident(
            incident_id=incident_id,
            repository=repository_path,
            file_path=finding.get("File") or "<unknown>",
            secret_type=finding.get("RuleID") or "secret",
            severity=risk["severity"],
            risk_score=risk["score"],
            commit_hash=finding.get("Commit"),
            fingerprint=finding.get("Fingerprint"),
            status="DETECTED",
            description=finding.get("Description"),
        )
        db.add(incident)
        findings.append(ScanFinding(
            rule_id=finding.get("RuleID"),
            description=finding.get("Description"),
            file=finding.get("File"),
            line=finding.get("StartLine"),
            column=finding.get("StartColumn"),
            secret_type=finding.get("RuleID"),
            fingerprint=finding.get("Fingerprint"),
            risk_score=risk["score"],
            severity=risk["severity"],
            risk_reasons=risk["reasons"],
            incident_id=incident_id,
        ))
        audit_findings.append((finding, risk, policy, incident_id))

    db.commit()
    record_audit_event(
        db, "SCAN",
        f"Current-file repository scan completed with {len(findings)} finding(s).",
        repository=repository_path,
    )
    for finding, risk, policy, incident_id in audit_findings:
        record_audit_event(
            db, "DETECTION",
            f"{finding.get('RuleID') or 'Secret'} detected in {finding.get('File') or 'a repository file'}.",
            repository=repository_path,
        )
        record_audit_event(
            db, "INCIDENT", f"Incident {incident_id} created.",
            incident_id=incident_id, repository=repository_path,
        )
        record_audit_event(
            db, "RISK", f"Risk score {risk['score']} / {risk['severity']}.",
            incident_id=incident_id, repository=repository_path,
        )
        record_audit_event(
            db, "POLICY",
            f"Policy decision {policy['action']} for {finding.get('RuleID') or 'secret'} (risk {risk['score']}, {risk['severity']}).",
            repository=repository_path,
        )
    return ScanResponse(
        status="completed", repository_path=repository_path,
        findings_count=len(findings), findings=findings,
    )
