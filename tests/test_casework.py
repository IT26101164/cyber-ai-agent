import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cyberai.casework import CaseStore, extract_indicators, sha256_file


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

    def test_sha256_file_helper(self):
        file_path = self._write("hash.txt", "abc")
        self.assertEqual(sha256_file(file_path), hashlib.sha256(b"abc").hexdigest())


if __name__ == "__main__":
    unittest.main()
