from app.services.audit import record_audit_event
from app.services.gitleaks import run_gitleaks


def rescan_incident(db, incident) -> dict:
    """Rescan an incident repository and update status by fingerprint match."""
    if not incident.fingerprint:
        raise ValueError(
            "This incident cannot be safely rescanned because its fingerprint is missing."
        )

    findings = run_gitleaks(incident.repository)
    matching_finding = next(
        (finding for finding in findings
         if finding.get("Fingerprint") == incident.fingerprint),
        None,
    )

    if matching_finding:
        incident.status = "INVESTIGATING"
        db.commit()
        record_audit_event(
            db, "RESCAN", "Rescan completed; the secret remains detected.",
            incident_id=incident.incident_id, repository=incident.repository,
        )
        return {
            "incident_id": incident.incident_id,
            "status": "INVESTIGATING",
            "resolved": False,
            "message": "Secret is still exposed.",
            "finding": {
                "file": matching_finding.get("File"),
                "secret_type": matching_finding.get("RuleID"),
                "fingerprint": matching_finding.get("Fingerprint"),
            },
        }

    incident.status = "RESOLVED"
    db.commit()
    record_audit_event(
        db, "RESOLVE",
        "Rescan confirmed the secret is no longer detected; incident resolved.",
        incident_id=incident.incident_id, repository=incident.repository,
    )
    return {
        "incident_id": incident.incident_id,
        "status": "RESOLVED",
        "resolved": True,
        "message": "Secret is no longer detected. Incident resolved.",
    }
