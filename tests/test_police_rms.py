import unittest

from police_rms import AccessDenied, PoliceRMS, UserContext


class TestPoliceRMS(unittest.TestCase):
    def setUp(self) -> None:
        self.rms = PoliceRMS()
        self.records_officer = UserContext("u1", "records_officer", "agency-a", True)
        self.detective = UserContext("u2", "detective", "agency-a", True)
        self.patrol = UserContext("u3", "patrol", "agency-a", True)
        self.auditor = UserContext("u4", "auditor", "agency-a", True)

    def test_create_and_view_record(self) -> None:
        record_id = self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-001",
            subject_name="Jane Doe",
            offense_code="13-101",
            narrative="Initial report",
            classification="criminal_incident",
        )

        record = self.rms.view_record(self.detective, record_id)
        self.assertEqual(record["incident_number"], "A-2026-001")
        self.assertEqual(record["version"], 1)

    def test_mfa_required_for_read(self) -> None:
        record_id = self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-002",
            subject_name="John Doe",
            offense_code="13-102",
            narrative="Initial report",
            classification="criminal_incident",
        )
        no_mfa_user = UserContext("u5", "detective", "agency-a", False)
        with self.assertRaises(AccessDenied):
            self.rms.view_record(no_mfa_user, record_id)

    def test_sealed_record_visibility_is_restricted(self) -> None:
        record_id = self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-003",
            subject_name="Protected Witness",
            offense_code="13-103",
            narrative="Sensitive details",
            classification="criminal_incident",
        )
        self.rms.seal_record(self.records_officer, record_id)

        with self.assertRaises(AccessDenied):
            self.rms.view_record(self.patrol, record_id)

    def test_cross_agency_access_denied(self) -> None:
        record_id = self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-004",
            subject_name="Cross Agency",
            offense_code="13-104",
            narrative="Details",
            classification="criminal_incident",
        )
        other_agency = UserContext("u6", "detective", "agency-b", True)

        with self.assertRaises(AccessDenied):
            self.rms.view_record(other_agency, record_id)

    def test_audit_requires_auditor_or_admin(self) -> None:
        record_id = self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-005",
            subject_name="Audit Subject",
            offense_code="13-105",
            narrative="Details",
            classification="criminal_incident",
        )
        self.rms.view_record(self.detective, record_id)
        events = self.rms.audit_trail(self.auditor, record_id=record_id)

        self.assertGreaterEqual(len(events), 2)
        with self.assertRaises(AccessDenied):
            self.rms.audit_trail(self.detective, record_id=record_id)

    def test_auditor_is_agency_scoped(self) -> None:
        other_officer = UserContext("u7", "records_officer", "agency-b", True)
        other_auditor = UserContext("u8", "auditor", "agency-b", True)

        self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-006",
            subject_name="Agency A Subject",
            offense_code="13-106",
            narrative="A details",
            classification="criminal_incident",
        )
        self.rms.create_record(
            other_officer,
            incident_number="B-2026-001",
            subject_name="Agency B Subject",
            offense_code="13-201",
            narrative="B details",
            classification="criminal_incident",
        )

        agency_a_events = self.rms.audit_trail(self.auditor)
        agency_b_events = self.rms.audit_trail(other_auditor)

        self.assertTrue(all(event["agency_id"] == "agency-a" for event in agency_a_events))
        self.assertTrue(all(event["agency_id"] == "agency-b" for event in agency_b_events))

    def test_admin_can_view_cross_agency_audit_events(self) -> None:
        other_officer = UserContext("u9", "records_officer", "agency-b", True)
        admin = UserContext("admin", "admin", "hq", True)

        self.rms.create_record(
            self.records_officer,
            incident_number="A-2026-007",
            subject_name="Agency A Subject",
            offense_code="13-107",
            narrative="A details",
            classification="criminal_incident",
        )
        self.rms.create_record(
            other_officer,
            incident_number="B-2026-002",
            subject_name="Agency B Subject",
            offense_code="13-202",
            narrative="B details",
            classification="criminal_incident",
        )

        events = self.rms.audit_trail(admin)
        agencies = {event["agency_id"] for event in events}
        self.assertIn("agency-a", agencies)
        self.assertIn("agency-b", agencies)


if __name__ == "__main__":
    unittest.main()
