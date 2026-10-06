def evaluate_policy(
    severity: str,
    secret_type: str,
    risk_score: int
) -> dict:

    severity = (severity or "").upper()
    secret_type = (secret_type or "").lower()

    if severity == "CRITICAL":
        action = "BLOCK"
        reason = "Critical secret exposure detected. Immediate remediation required."

    elif severity == "HIGH":
        action = "REVIEW"
        reason = "High-risk secret detected. Security review and remediation required."

    elif severity == "MEDIUM":
        action = "WARN"
        reason = "Potential secret exposure detected. Review and remediate if confirmed."

    else:
        action = "ALLOW"
        reason = "Low-risk finding. No immediate blocking action required."

    return {
        "action": action,
        "severity": severity,
        "risk_score": risk_score,
        "secret_type": secret_type,
        "reason": reason
    }