from pathlib import Path


def calculate_risk(finding: dict) -> dict:
    score = 0
    reasons = []

    rule_id = (finding.get("RuleID") or "").lower()
    file_path = (finding.get("File") or "").lower()

    # Secret type
    if any(x in rule_id for x in ["github", "gitlab", "bitbucket"]):
        score += 40
        reasons.append("Source-control credential detected")

    elif any(x in rule_id for x in ["aws", "amazon"]):
        score += 40
        reasons.append("AWS credential detected")

    elif any(x in rule_id for x in ["azure", "microsoft"]):
        score += 40
        reasons.append("Azure credential detected")

    elif any(x in rule_id for x in ["private-key", "private_key", "ssh"]):
        score += 45
        reasons.append("Private or SSH key detected")

    elif any(x in rule_id for x in ["password", "database", "db"]):
        score += 35
        reasons.append("Database/password credential detected")

    elif any(x in rule_id for x in ["token", "api-key", "api_key"]):
        score += 25
        reasons.append("API token detected")

    else:
        score += 20
        reasons.append("Potential secret detected")

    # File location
    extension = Path(file_path).suffix

    if extension in [".env", ".ini", ".cfg", ".conf"]:
        score += 20
        reasons.append("Secret found in configuration/environment file")

    elif extension in [".py", ".js", ".ts", ".java", ".go", ".cpp", ".c"]:
        score += 10
        reasons.append("Secret found in source code")

    elif extension in [".md", ".txt"]:
        score += 5
        reasons.append("Secret found in documentation/text file")

    score = min(score, 100)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }