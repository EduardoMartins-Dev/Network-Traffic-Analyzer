#!/usr/bin/env python3
# test_mitre_layer.py — impede divergência entre mitre_layer.py e attack_to_mitre().
# Execução: python3 scripts/test_mitre_layer.py   (stdlib apenas)
import json
import re
import unittest
from pathlib import Path

import mitre_layer as ml

REQUIRED = ["T1046", "T1557", "T1498", "T1110", "T1071.004", "T1048"]
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class RealSourceTest(unittest.TestCase):
    """Lê o analyzer.c real: a camada precisa refletir o código atual."""

    @classmethod
    def setUpClass(cls):
        src = ml.DEFAULT_SOURCE.read_text(encoding="utf-8", errors="replace")
        cls.mapping = ml.parse_attack_to_mitre(src)
        cls.layer = ml.build_layer(cls.mapping)

    def test_every_mapped_attack_is_exported(self):
        exported = {t["techniqueID"] for t in self.layer["techniques"]}
        expected = {t for techs in self.mapping.values() for t in techs}
        self.assertEqual(exported, expected)

    def test_required_techniques_present(self):
        ids = {t["techniqueID"] for t in self.layer["techniques"]}
        for tid in REQUIRED:
            self.assertIn(tid, ids)

    def test_technique_ids_well_formed(self):
        for t in self.layer["techniques"]:
            self.assertRegex(t["techniqueID"], TECH_RE)

    def test_layer_json_round_trip(self):
        data = json.loads(json.dumps(self.layer))
        self.assertEqual(data["domain"], "enterprise-attack")
        self.assertEqual(data["versions"]["layer"], "4.5")
        self.assertTrue(data["techniques"])


class ParserGuardTest(unittest.TestCase):
    """Formas que o parser não entende precisam falhar, não sumir em silêncio."""

    GOOD = (
        "static const char *attack_to_mitre(const char *attack) {\n"
        '    if (!attack) return "";\n'
        '    if (strcmp(attack, "PORT_SCAN")    == 0) return "T1046";\n'
        '    if (strcmp(attack, "DNS_TUNNEL")   == 0) return "T1071.004,T1048";\n'
        '    return "";\n'
        "}\n"
    )

    def test_parses_synthetic_snippet(self):
        m = ml.parse_attack_to_mitre(self.GOOD)
        self.assertEqual(m, {"PORT_SCAN": ["T1046"],
                             "DNS_TUNNEL": ["T1071.004", "T1048"]})

    def test_unknown_entry_form_is_rejected(self):
        bad = self.GOOD.replace(
            '    return "";\n}',
            '    if (attack[0] == \'X\' && strcmp(attack, "XX") == 0) return "T1499";\n    return "";\n}',
        )
        with self.assertRaises(ValueError):
            ml.parse_attack_to_mitre(bad)

    def test_missing_function_is_rejected(self):
        with self.assertRaises(ValueError):
            ml.parse_attack_to_mitre("int main(void) { return 0; }\n")


if __name__ == "__main__":
    unittest.main()
