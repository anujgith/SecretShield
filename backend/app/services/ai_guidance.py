def get_ai_guidance(
    secret_type: str | None = None,
    severity: str | None = None,
    description: str | None = None,
) -> dict:
    """Return a safe unavailable state until an AI provider is configured."""
    return {
        "available": False,
        "message": (
            "AI guidance is not configured. Use the deterministic risk, "
            "policy, and remediation guidance for this incident."
        ),
    }
