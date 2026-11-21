#!/usr/bin/env python3
# test_dash_schema.py — impede divergência entre o SCHEMA de dash_gen.py e o que o agente
# e o servidor gravam no InfluxDB. Execução: python3 scripts/test_dash_schema.py
# (stdlib apenas; fora do ctest e do CI, como test_mitre_layer.py). Lê o SCHEMA com ast,
# sem importar dash_gen.py, para não exigir o pacote requests.
import ast
import re
import unittest
from pathlib import Path

import mitre_layer as ml

ROOT = Path(__file__).resolve().parent.parent
DASH_GEN = ROOT / "scripts" / "dash_gen.py"
SERVER_SOURCES = [
    ROOT / "src" / "server" / "nta_influx.c",
    ROOT / "src" / "agent" / "core" / "pipeline.c",
]

# O agente grava "NONE" em todo pacote benigno (publisher.c).
BENIGN = "NONE"

# Tags e fields do measurement "traffic" e "pipeline_metrics" e "nta_pool" que o
# servidor grava e o schema precisa citar (ver nta_influx.c e pipeline.c).
TRAFFIC_NAMES = ["mitre", "asn", "asn_org", "ioc_hit", "ioc_source",
                 "kc_score", "abuse_score", "lat", "lon"]
PIPELINE_FIELDS = ["rb_pkt_depth", "rb_evt_depth", "rb_pkt_overflow", "rb_evt_overflow",
                   "batches_sent", "events_sent", "events_per_sec",
                   "vlan_frames", "frag_seen", "frag_discarded"]
POOL_FIELDS = ["pool_size", "backlog", "unacked", "consumers"]


def load_schema():
    tree = ast.parse(DASH_GEN.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "SCHEMA" for t in node.targets):
            return node.value.value
    raise ValueError("SCHEMA não encontrado em dash_gen.py")


def emitted_attack_types():
    """Tipos de ataque que o analyzer.c pode gravar: a tabela de MITRE e os retornos dos detectores."""
    src = ml.DEFAULT_SOURCE.read_text(encoding="utf-8", errors="replace")
    names = set(ml.parse_attack_to_mitre(src))
    names.update(re.findall(r'return\s+"([A-Z][A-Z_]*)"\s*;', src))
    return names | {BENIGN}


def schema_attack_types(schema):
    m = re.search(r"attack_type\s*\(([^)]*)\)", schema)
    if not m:
        raise ValueError("lista de attack_type não encontrada no SCHEMA")
    return set(re.split(r"[|\s]+", m.group(1).strip()))


class SchemaAttackTypesTest(unittest.TestCase):
    """A lista de attack_type do SCHEMA é exatamente a que o analyzer emite."""

    def test_schema_lists_exactly_the_emitted_attack_types(self):
        self.assertEqual(schema_attack_types(load_schema()), emitted_attack_types())


class SchemaFieldsTest(unittest.TestCase):
    """Os tags/fields gravados pelo servidor aparecem no schema."""

    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema()

    def assertInSchema(self, name):
        self.assertRegex(self.schema, r"\b%s\b" % re.escape(name))

    def test_traffic_tags_and_fields(self):
        for name in TRAFFIC_NAMES:
            self.assertInSchema(name)

    def test_pipeline_metrics_fields(self):
        for name in PIPELINE_FIELDS:
            self.assertInSchema(name)

    def test_nta_pool_fields(self):
        for name in POOL_FIELDS:
            self.assertInSchema(name)


class SchemaNamesWrittenTest(unittest.TestCase):
    """Guarda contra nomes inventados: cada tag/field citado aparece no código que o grava."""

    @classmethod
    def setUpClass(cls):
        cls.src = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in SERVER_SOURCES)

    def test_every_listed_name_is_written_by_code(self):
        for name in TRAFFIC_NAMES + PIPELINE_FIELDS + POOL_FIELDS:
            with self.subTest(name=name):
                self.assertRegex(self.src, r"\b%s\b" % re.escape(name))


if __name__ == "__main__":
    unittest.main()
