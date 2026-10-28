import unittest

from cyberai.jarvis_plus import assess_connections, parse_json_rows, simulated_hops


class JarvisPlusHelperTests(unittest.TestCase):
    def test_parse_empty_and_object(self):
        self.assertEqual(parse_json_rows(""), [])
        self.assertEqual(parse_json_rows('{"Id":1}'), [{"Id": 1}])

    def test_parse_rejects_wrong_shape(self):
        with self.assertRaises(ValueError):
            parse_json_rows('"text"')

    def test_assess_returns_explained_hint_not_malware_claim(self):
        rows = [{"LocalAddress":"0.0.0.0","LocalPort":8080,"RemoteAddress":"0.0.0.0",
                 "RemotePort":0,"State":"Listen","OwningProcess":44}]
        findings = assess_connections(rows, {"44":"demo"})
        self.assertEqual(findings[0]["level"], "INFO")
        self.assertIn("verify", findings[0]["reason"])
        self.assertEqual(findings[0]["process"], "demo")

    def test_assess_empty_is_empty(self):
        self.assertEqual(assess_connections([]), [])

    def test_simulation_is_synthetic(self):
        hops = simulated_hops()
        self.assertEqual(len(hops), 3)
        self.assertTrue(all(h["packet"].startswith("SIM-") for h in hops))


if __name__ == "__main__":
    unittest.main()
