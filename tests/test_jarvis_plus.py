import unittest

from cyberai.jarvis_plus import (
    _state_name,
    assess_connections,
    parse_json_rows,
    protocol_summary,
    simulated_hops,
)


class JarvisPlusHelperTests(unittest.TestCase):
    def test_parse_empty_and_object(self):
        self.assertEqual(parse_json_rows(""), [])
        self.assertEqual(parse_json_rows('{"Id":1}'), [{"Id": 1}])

    def test_parse_array(self):
        self.assertEqual(parse_json_rows('[{"Id":1},{"Id":2}]'), [{"Id": 1}, {"Id": 2}])

    def test_parse_rejects_wrong_shape(self):
        with self.assertRaises(ValueError):
            parse_json_rows('"text"')

    def test_state_normalization(self):
        self.assertEqual(_state_name("Listen"), "LISTEN")
        self.assertEqual(_state_name("Established"), "ESTABLISHED")
        self.assertEqual(_state_name("5"), "ESTABLISHED")

    def test_assess_returns_explained_hint_not_malware_claim(self):
        rows = [{"LocalAddress":"0.0.0.0","LocalPort":8080,"RemoteAddress":"0.0.0.0",
                 "RemotePort":0,"State":"Listen","OwningProcess":44}]
        findings = assess_connections(rows, {"44":"demo"})
        self.assertEqual(findings[0]["level"], "INFO")
        self.assertIn("verify", findings[0]["reason"])
        self.assertEqual(findings[0]["process"], "demo")

    def test_combined_review_signals_can_reach_high_review(self):
        rows = [
            {"LocalAddress":"0.0.0.0","LocalPort":4444,"RemoteAddress":"0.0.0.0",
             "RemotePort":4444,"State":"Listen","OwningProcess":44}
            for _ in range(80)
        ]
        findings = assess_connections(rows, {"44":"demo"})
        self.assertTrue(findings)
        self.assertEqual(findings[0]["level"], "HIGH REVIEW")
        self.assertIn("verify", findings[0]["reason"])

    def test_established_external_connection_alone_is_not_an_alert(self):
        rows = [{"LocalAddress":"192.168.1.10","LocalPort":50000,"RemoteAddress":"203.0.113.8",
                 "RemotePort":443,"State":"Established","OwningProcess":44}]
        self.assertEqual(assess_connections(rows, {"44":"browser"}), [])

    def test_assess_empty_is_empty(self):
        self.assertEqual(assess_connections([]), [])

    def test_protocol_summary_uses_destination_port_metadata(self):
        rows = [{"RemotePort":443},{"RemotePort":443},{"RemotePort":53},{"RemotePort":12345}]
        self.assertEqual(protocol_summary(rows), [("HTTPS/TLS", 2), ("DNS/TCP", 1), ("Other TCP", 1)])

    def test_simulation_is_synthetic(self):
        hops = simulated_hops()
        self.assertEqual(len(hops), 3)
        self.assertTrue(all(h["packet"].startswith("SIM-") for h in hops))


if __name__ == "__main__":
    unittest.main()
