"""Explicitly simulated, local-only secret rotation metadata service."""

from datetime import datetime
from uuid import uuid4


class MockRotationProvider:
    """Simulate an operation; this provider performs no API or network calls."""

    provider = "mock"

    def simulate(self) -> dict:
        now = datetime.utcnow()
        return {
            "provider": self.provider,
            "status": "SIMULATED",
            "operation_id": f"MOCK-{uuid4().hex[:12].upper()}",
            "created_at": now,
            "completed_at": now,
        }


class RotationManager:
    """MVP coordinator for the mock-only rotation provider."""

    def __init__(self, provider: MockRotationProvider | None = None):
        self.provider = provider or MockRotationProvider()

    def simulate_rotation(self) -> dict:
        return self.provider.simulate()
