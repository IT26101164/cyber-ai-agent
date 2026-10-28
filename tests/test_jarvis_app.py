import json
import unittest
from unittest.mock import patch

from cyberai.jarvis_app import format_bytes, make_simulated_events, parse_connections_json


class JarvisDashboardHelpersTests(unittest.TestCase):
    def test_parse_empty_json(self):
        self.assertEqual(parse_connections_json(""), [])

    def test_parse_single_connection_object(self):
        rows = parse_connections_json(json.dumps({
            "LocalAddress": "127.0.0.1", "LocalPort": 5000,
            "RemoteAddress": "127.0.0.1", "RemotePort": 443,
            "State": "Established", "OwningProcess": 123,
        }))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["RemotePort"], 443)

    def test_parse_connection_array(self):
        rows = parse_connections_json('[{"State":"Listen"},{"State":"Established"}]')
        self.assertEqual(len(rows), 2)

    def test_reject_unexpected_json_shape(self):
        with self.assertRaises(ValueError):
            parse_connections_json('"not a connection list"')

    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")

    def test_simulation_has_three_fictional_hops(self):
        events = make_simulated_events()
        self.assertEqual(len(events), 3)
        self.assertTrue(all(event["packet"].startswith("SIM-") for event in events))
        self.assertTrue(all("SIMULATED" in event["detail"] for event in events))


if __name__ == "__main__":
    unittest.main()
