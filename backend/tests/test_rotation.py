import unittest
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.incidents import rescan_incident, rotate_incident_secret
from app.core.database import Base
from app.models.audit import AuditEvent
from app.models.incident import Incident
from app.models.rotation import RotationOperation
from app.schemas.rotation import RotationResponse
from app.services.scan import scan_repository


SYNTHETIC_VALUE_SENTINEL = "synthetic-only-value-must-not-escape"


class RotationBackendTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def add_incident(self, *, status="DETECTED", fingerprint="safe-fingerprint"):
        incident = Incident(
            incident_id="INC-1234ABCD",
            repository="/tmp/synthetic-repository",
            file_path="config.env",
            secret_type="github-pat",
            severity="HIGH",
            risk_score=60,
            fingerprint=fingerprint,
            status=status,
        )
        self.db.add(incident)
        self.db.commit()
        return incident

    @staticmethod
    def matching_finding():
        # The extra field represents the kind of raw scanner value that must
        # never be selected into response, persistence, or audit metadata.
        return {
            "RuleID": "github-pat",
            "File": "config.env",
            "Fingerprint": "safe-fingerprint",
            "Match": SYNTHETIC_VALUE_SENTINEL,
        }

    def test_rotation_is_mock_persisted_and_keeps_fingerprint_match_open(self):
        incident = self.add_incident()
        with patch("app.services.rescan.run_gitleaks", return_value=[self.matching_finding()]):
            result = rotate_incident_secret(incident.incident_id, self.db)
            response = RotationResponse.model_validate(result)

        self.assertEqual(response.provider, "mock")
        self.assertEqual(response.status, "SIMULATED")
        self.assertEqual(response.rescan.status, "INVESTIGATING")
        self.assertFalse(response.rescan.resolved)
        self.assertEqual(response.incident_status, "INVESTIGATING")
        self.assertRegex(response.operation_id, r"^MOCK-[A-F0-9]{12}$")
        self.assertRegex(response.incident_id, r"^INC-[A-F0-9]{8}$")

        operation = self.db.query(RotationOperation).one()
        columns = set(RotationOperation.__table__.columns.keys())
        self.assertEqual(
            columns,
            {"id", "incident_id", "provider", "status", "operation_id", "created_at", "completed_at"},
        )
        self.assertEqual(operation.provider, "mock")
        self.assertEqual(operation.status, "SIMULATED")
        self.assertNotIn(SYNTHETIC_VALUE_SENTINEL, repr(operation))
        self.assertNotIn(SYNTHETIC_VALUE_SENTINEL, response.model_dump_json())
        self.assertNotIn(
            SYNTHETIC_VALUE_SENTINEL,
            " ".join(event.message for event in self.db.query(AuditEvent).all()),
        )
        event_types = {event.event_type for event in self.db.query(AuditEvent).all()}
        self.assertTrue({"ROTATION_REQUESTED", "ROTATION_SIMULATED", "RESCAN_AFTER_ROTATION"}.issubset(event_types))

        with patch("app.services.rescan.run_gitleaks", return_value=[self.matching_finding()]):
            repeated = rotate_incident_secret(incident.incident_id, self.db)
        self.assertEqual(repeated["operation_id"], result["operation_id"])
        self.assertEqual(self.db.query(RotationOperation).count(), 1)

    def test_rotation_returns_404_for_unknown_incident(self):
        with self.assertRaises(HTTPException) as caught:
            rotate_incident_secret("INC-NOTFOUND", self.db)
        self.assertEqual(caught.exception.status_code, 404)

    def test_rotation_resolves_only_when_rescan_does_not_find_fingerprint(self):
        incident = self.add_incident()
        with patch("app.services.rescan.run_gitleaks", return_value=[]):
            result = rotate_incident_secret(incident.incident_id, self.db)
        self.assertEqual(result["provider"], "mock")
        self.assertTrue(result["rescan"]["resolved"])
        self.assertEqual(result["incident_status"], "RESOLVED")

    def test_resolved_incident_cannot_be_rotated_again(self):
        incident = self.add_incident(status="RESOLVED")
        with self.assertRaises(HTTPException) as caught:
            rotate_incident_secret(incident.incident_id, self.db)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.db.query(RotationOperation).count(), 0)

    def test_existing_rescan_resolves_only_when_fingerprint_is_absent(self):
        incident = self.add_incident(status="DETECTED")
        with patch("app.services.rescan.run_gitleaks", return_value=[self.matching_finding()]):
            remains = rescan_incident(incident.incident_id, self.db)
        self.assertEqual(remains["status"], "INVESTIGATING")
        self.assertFalse(remains["resolved"])

        with patch("app.services.rescan.run_gitleaks", return_value=[]):
            resolved = rescan_incident(incident.incident_id, self.db)
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertTrue(resolved["resolved"])

    def test_shared_scan_persists_real_incident_id_without_raw_value(self):
        finding = {
            "RuleID": "github-pat",
            "Description": "Synthetic detector result",
            "File": "config.env",
            "StartLine": 1,
            "StartColumn": 1,
            "Fingerprint": "scan-fingerprint",
            "Match": SYNTHETIC_VALUE_SENTINEL,
        }
        with patch("app.services.scan.run_gitleaks", return_value=[finding]):
            result = scan_repository("/tmp/synthetic-repository", self.db)
        item = result.findings[0]
        self.assertRegex(item.incident_id, r"^INC-[A-F0-9]{8}$")
        self.assertEqual(self.db.query(Incident).one().incident_id, item.incident_id)
        self.assertNotIn(SYNTHETIC_VALUE_SENTINEL, result.model_dump_json())
        self.assertNotIn(
            SYNTHETIC_VALUE_SENTINEL,
            " ".join(event.message for event in self.db.query(AuditEvent).all()),
        )


if __name__ == "__main__":
    unittest.main()
