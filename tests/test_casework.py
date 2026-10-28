import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cyberai.casework import (CaseStore, extract_indicators, extract_timestamps, normalize_phone_number, openstreetmap_url, sha256_file)


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = CaseStore(self.root / "casework")

    def tearDown(self):
        self.temp.cleanup()

    def _case(self):
        return self.store.create_case("Unauthorized account access", "Victim-provided sample records")

    def _write(self, name, data):
        path = self.root / name
        path.write_text(data, encoding="utf-8")
        return path

    def test_create_case_and_status_event(self):
        case = self._case()
        self.assertTrue(case["case_id"].startswith("CASE-"))
        self.assertEqual(case["status"], "OPEN")
        changed = self.store.set_case_status(case["case_id"], "investigating")
        self.assertEqual(changed["status"], "INVESTIGATING")
        self.assertTrue(self.store.audit_integrity()["ok"])

    def test_invalid_case_title_and_status_rejected(self):
        with self.assertRaises(ValueError):
            self.store.create_case(" ")
        case = self._case()
        with self.assertRaises(ValueError):
            self.store.set_case_status(case["case_id"], "TRACKING_SUSPECT")

    def test_evidence_copy_hash_provenance_and_source_unchanged(self):
        case = self._case()
        source = self._write("victim.log", "login from 198.51.100.8 at 2026-10-28T10:30:00Z")
        original = source.read_bytes()
        item = self.store.add_evidence(case["case_id"], source, "Victim-provided log export", "Example log")
        self.assertEqual(item["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(Path(item["absolute_path"]).read_bytes(), original)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.store.verify_evidence(item["evidence_id"])["status"], "MATCH")
        self.assertTrue(self.store.audit_integrity()["ok"])

    def test_changed_stored_evidence_is_flagged(self):
        case = self._case()
        source = self._write("snapshot.txt", "First line")
        item = self.store.add_evidence(case["case_id"], source, "Authorized lab export")
        Path(item["absolute_path"]).write_text("tampered", encoding="utf-8")
        result = self.store.verify_evidence(item["evidence_id"])
        self.assertEqual(result["status"], "HASH_MISMATCH")

    def test_shared_indicators_across_two_files_are_correlated(self):
        case = self._case()
        first = self._write("first.log", "Request to https://example.invalid/login from 198.51.100.7")
        second = self._write("second.eml", "Received from 198.51.100.7; link https://example.invalid/reset")
        self.store.add_evidence(case["case_id"], first, "Victim-provided browser log")
        self.store.add_evidence(case["case_id"], second, "Victim-provided email export")
        leads = self.store.correlations(case["case_id"])
        shared = {(lead["indicator_type"], lead["value"]) for lead in leads}
        self.assertIn(("ipv4", "198.51.100.7"), shared)
        self.assertIn(("domain", "example.invalid"), shared)
        self.assertTrue(all(lead["evidence_count"] >= 2 for lead in leads))

    def test_extract_timestamps_normalizes_offsets_and_preserves_unknown_timezone(self):
        events = extract_timestamps(
            "2026-10-28T10:30:00+05:30 login from 198.51.100.7\n"
            "2026-10-28 09:45:00 local time with no offset\n"
            "[28/Oct/2026:11:15:00 +0000] Apache request\n"
            "Oct 28 11:15:00 legacy syslog without year"
        )
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["timestamp_utc"], "2026-10-28T05:00:00+00:00")
        self.assertEqual(events[0]["timezone_status"], "EXPLICIT_OFFSET")
        self.assertIsNone(events[1]["timestamp_utc"])
        self.assertEqual(events[1]["timezone_status"], "UNSPECIFIED")
        self.assertEqual(events[2]["parser"], "APACHE")
        self.assertEqual(events[2]["timestamp_utc"], "2026-10-28T11:15:00+00:00")

    def test_evidence_timeline_correlates_indicators_with_source_lines(self):
        case = self._case()
        first = self._write(
            "first.log",
            "2026-10-28T10:30:00Z connection from 198.51.100.22\n"
            "2026-10-28T10:31:00Z another entry"
        )
        second = self._write(
            "second.log",
            "2026-10-28T10:35:00+00:00 repeated address 198.51.100.22"
        )
        self.store.add_evidence(case["case_id"], first, "Operator-authorized sample log")
        self.store.add_evidence(case["case_id"], second, "Operator-authorized second log")
        timeline = self.store.evidence_timeline(case["case_id"])
        self.assertEqual(timeline["event_count"], 3)
        self.assertEqual(timeline["evidence_files_scanned"], 2)
        self.assertEqual(timeline["events"][0]["timestamp_utc"], "2026-10-28T10:30:00+00:00")
        self.assertEqual(timeline["events"][0]["line_number"], 1)
        address_lead = next(
            item for item in timeline["timeline_correlation_leads"]
            if item["indicator_type"] == "ipv4" and item["value"] == "198.51.100.22"
        )
        self.assertEqual(address_lead["evidence_count"], 2)
        self.assertIn("does not identify a person", address_lead["interpretation"])

    def test_evidence_timeline_skips_hash_mismatched_content(self):
        case = self._case()
        source = self._write("changed.log", "2026-10-28T10:30:00Z login")
        item = self.store.add_evidence(case["case_id"], source, "Authorized sample log")
        Path(item["absolute_path"]).write_text("2026-10-28T10:31:00Z modified content", encoding="utf-8")
        timeline = self.store.evidence_timeline(case["case_id"])
        self.assertEqual(timeline["event_count"], 0)
        self.assertTrue(any("SHA-256 mismatch" in warning["reason"] for warning in timeline["warnings"]))

    def test_phone_lead_normalization_and_duplicate_protection(self):
        case = self._case()
        lead = self.store.add_phone_lead(
            case["case_id"], "+94 71-234-5678", "Complaint record",
            legal_basis="LEAD_ONLY_NOT_LOCATION_AUTHORITY",
        )
        self.assertEqual(lead["phone_number"], "+94712345678")
        self.assertEqual(lead["lead_status"], "UNVERIFIED")
        self.assertEqual(normalize_phone_number("0094712345678"), "+94712345678")
        with self.assertRaises(ValueError):
            normalize_phone_number("0712345678")
        with self.assertRaises(ValueError):
            self.store.add_phone_lead(case["case_id"], "+94712345678", "Duplicate complaint")
        self.assertTrue(self.store.audit_integrity()["ok"])

    def test_phone_indicator_extraction_only_accepts_explicit_international_numbers(self):
        values = set(extract_indicators("Call +94 71 234 5678 or +1 (202) 555-0147"))
        self.assertIn(("phone", "+94712345678"), values)
        self.assertIn(("phone", "+12025550147"), values)

    def test_authorized_location_record_is_evidence_linked_and_normalized_to_utc(self):
        case = self._case()
        source = self._write("provider-response.json", '{"location":{"lat":6.9271,"lon":79.8612}}')
        evidence = self.store.add_evidence(case["case_id"], source, "Authorized provider response, reference REQ-2026-123")
        lead = self.store.add_phone_lead(
            case["case_id"], "+94712345678", "Officer-entered case lead",
            legal_basis="AUTHORIZED_PROVIDER_RESPONSE", authority_reference="REQ-2026-123",
        )
        location = self.store.add_location_record(
            case["case_id"], lead["phone_id"], "2026-10-28T15:30:00+05:30",
            "6.9271", "79.8612", "PROVIDER_RESPONSE",
            "AUTHORIZED_PROVIDER_RESPONSE", "REQ-2026-123",
            evidence["evidence_id"], "120", "Coordinate read from the imported response",
        )
        self.assertEqual(location["observed_at_utc"], "2026-10-28T10:00:00+00:00")
        self.assertEqual(location["evidence_sha256"], evidence["sha256"])
        self.assertEqual(location["phone_number"], "+94712345678")
        self.assertIn("openstreetmap.org", openstreetmap_url(location["latitude"], location["longitude"]))
        listed = self.store.list_location_records(case["case_id"])
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["evidence_filename"], "provider-response.json")
        events = [item["event"] for item in self.store.timeline(case["case_id"])]
        self.assertIn("AUTHORIZED_LOCATION_RECORD_ADDED", events)
        self.assertTrue(self.store.audit_integrity()["ok"])

    def test_location_record_requires_authority_reference_and_verified_evidence(self):
        case = self._case()
        source = self._write("provider-response.json", "authorized test record")
        evidence = self.store.add_evidence(case["case_id"], source, "Authorized provider response")
        lead = self.store.add_phone_lead(case["case_id"], "+94712345678", "Case intake")
        with self.assertRaises(ValueError):
            self.store.add_location_record(
                case["case_id"], lead["phone_id"], "2026-10-28T15:30:00+05:30",
                6.9, 79.8, "PROVIDER_RESPONSE", "AUTHORIZED_PROVIDER_RESPONSE", "",
                evidence["evidence_id"],
            )
        Path(evidence["absolute_path"]).write_text("modified response", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.add_location_record(
                case["case_id"], lead["phone_id"], "2026-10-28T15:30:00+05:30",
                6.9, 79.8, "PROVIDER_RESPONSE", "AUTHORIZED_PROVIDER_RESPONSE", "REQ-2026-123",
                evidence["evidence_id"],
            )

    def test_location_time_requires_explicit_timezone_and_coordinates_are_validated(self):
        case = self._case()
        source = self._write("provider-response.json", "authorized test record")
        evidence = self.store.add_evidence(case["case_id"], source, "Authorized provider response")
        lead = self.store.add_phone_lead(case["case_id"], "+94712345678", "Case intake")
        with self.assertRaises(ValueError):
            self.store.add_location_record(
                case["case_id"], lead["phone_id"], "2026-10-28 15:30:00",
                6.9, 79.8, "PROVIDER_RESPONSE", "AUTHORIZED_PROVIDER_RESPONSE", "REQ-2026-123",
                evidence["evidence_id"],
            )
        with self.assertRaises(ValueError):
            openstreetmap_url(190, 79.8)

    def test_indicator_extraction_validates_ipv4(self):
        values = set(extract_indicators("bad IP 999.999.999.999 and valid 192.0.2.7, user@example.invalid"))
        self.assertIn(("ipv4", "192.0.2.7"), values)
        self.assertNotIn(("ipv4", "999.999.999.999"), values)
        self.assertIn(("email", "user@example.invalid"), values)

    def test_note_timeline_and_exported_audit(self):
        case = self._case()
        self.store.add_note(case["case_id"], "Compare the timestamp with the provider response.")
        timeline = self.store.timeline(case["case_id"])
        self.assertEqual(timeline[-1]["event"], "NOTE_ADDED")
        output = self.root / "export" / "audit.jsonl"
        count = self.store.export_audit(output)
        lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(count, len(lines))
        self.assertTrue(all(isinstance(json.loads(line), dict) for line in lines))
        self.assertTrue(self.store.audit_integrity()["ok"])

    def test_note_content_hash_is_verified(self):
        case = self._case()
        note = self.store.add_note(case["case_id"], "Original analyst note.")
        self.assertEqual(self.store.list_notes(case["case_id"])[0]["note"], "Original analyst note.")
        con = self.store._connect()
        try:
            con.execute("UPDATE notes SET note=? WHERE note_id=?", ("Edited note", note["note_id"]))
            con.commit()
        finally:
            con.close()
        result = self.store.audit_integrity()
        self.assertFalse(result["ok"])
        self.assertIn("note content mismatch", result["reason"].lower())

    def test_audit_chain_detects_modified_event(self):
        case = self._case()
        con = self.store._connect()
        try:
            con.execute("UPDATE audit_events SET event='EDITED' WHERE seq=1")
            con.commit()
        finally:
            con.close()
        result = self.store.audit_integrity()
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed_seq"], 1)

    def test_summary_counts_items(self):
        case = self._case()
        self.store.add_note(case["case_id"], "Analyst note.")
        summary = self.store.case_summary(case["case_id"])
        self.assertEqual(summary["evidence_count"], 0)
        self.assertEqual(summary["note_count"], 1)

    def test_case_report_export_contains_metadata_and_records_export(self):
        case = self._case()
        source = self._write("login.log", "2026-10-28T10:30:00Z Connection from 198.51.100.22 to https://example.invalid/login")
        evidence = self.store.add_evidence(case["case_id"], source, "Victim-provided log")
        self.store.add_note(case["case_id"], "Compare the login time with the transaction record.")
        destination = self.root / "exports" / "case-report.json"
        result = self.store.export_case_report(case["case_id"], destination)
        payload = destination.read_bytes()
        report = json.loads(payload.decode("utf-8"))
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report["case"]["case_id"], case["case_id"])
        self.assertEqual(report["evidence"][0]["sha256"], evidence["sha256"])
        self.assertTrue(any(item["indicator_type"] == "ipv4" for item in report["indicators"]))
        self.assertTrue(any(item["event"] == "NOTE_ADDED" for item in report["case_audit_timeline"]))
        self.assertEqual(report["report_schema"], "cyberai.case-report.v3")
        self.assertEqual(report["evidence_timeline"]["event_count"], 1)
        self.assertTrue(self.store.audit_integrity()["ok"])
        events = [item["event"] for item in self.store.timeline(case["case_id"])]
        self.assertEqual(events[-1], "CASE_REPORT_EXPORTED")

    def test_case_report_includes_phone_and_location_evidence(self):
        case = self._case()
        source = self._write(
            "authorized-location.json",
            '{"recorded_at":"2026-10-28T10:00:00Z","latitude":6.9271,"longitude":79.8612}'
        )
        evidence = self.store.add_evidence(case["case_id"], source, "Authorized provider response REQ-2026-991")
        lead = self.store.add_phone_lead(
            case["case_id"], "+94712345678", "Provider response for this case",
            legal_basis="AUTHORIZED_PROVIDER_RESPONSE", authority_reference="REQ-2026-991",
        )
        self.store.add_location_record(
            case["case_id"], lead["phone_id"], "2026-10-28T10:00:00Z",
            6.9271, 79.8612, "PROVIDER_RESPONSE", "AUTHORIZED_PROVIDER_RESPONSE",
            "REQ-2026-991", evidence["evidence_id"], 95,
        )
        report_path = self.root / "exports" / "phone-location-report.json"
        self.store.export_case_report(case["case_id"], report_path)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["report_schema"], "cyberai.case-report.v3")
        self.assertEqual(report["phone_leads"][0]["phone_number"], "+94712345678")
        self.assertEqual(len(report["authorized_location_records"]), 1)
        self.assertEqual(report["authorized_location_records"][0]["evidence_sha256"], evidence["sha256"])
        self.assertTrue(any("sensitive personal" in item.lower() for item in report["interpretation_guardrails"]))

    def test_case_report_export_refuses_vault_and_overwrite(self):
        case = self._case()
        with self.assertRaises(ValueError):
            self.store.export_case_report(case["case_id"], self.store.db_path)
        dest = self.root / "report.json"
        dest.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.store.export_case_report(case["case_id"], dest)
        self.assertEqual(dest.read_text(encoding="utf-8"), "keep")

    def test_sha256_file_helper(self):
        file_path = self._write("hash.txt", "abc")
        self.assertEqual(sha256_file(file_path), hashlib.sha256(b"abc").hexdigest())


if __name__ == "__main__":
    unittest.main()
