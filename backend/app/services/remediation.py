def get_remediation_guidance(secret_type: str):
    guidance = {
        "github-pat": {
            "action": "Rotate the GitHub Personal Access Token immediately.",
            "steps": [
                "Revoke the exposed GitHub Personal Access Token.",
                "Generate a new token with minimum required permissions.",
                "Remove the exposed token from the repository.",
                "Add the secret to environment variables or a secret manager.",
                "Rescan the repository to verify that the secret is no longer exposed."
            ]
        },
        "aws-access-key": {
            "action": "Rotate the exposed AWS access key immediately.",
            "steps": [
                "Deactivate the exposed AWS access key.",
                "Create a new access key if required.",
                "Remove the exposed key from the repository.",
                "Use IAM roles or environment variables instead of hardcoded credentials.",
                "Rescan the repository."
            ]
        },
        "generic-secret": {
            "action": "Remove and rotate the exposed secret.",
            "steps": [
                "Revoke or rotate the exposed credential.",
                "Remove it from the source code.",
                "Store the credential securely.",
                "Rescan the repository."
            ]
        }
    }

    return guidance.get(
        secret_type,
        guidance["generic-secret"]
    )