#!/usr/bin/env python3
# mitre_layer.py — exporta a cobertura MITRE real do NTA como camada do ATT&CK Navigator.
#
# A fonte é a função attack_to_mitre() em src/agent/analysis/analyzer.c: o script
# lê o código, não uma cópia. Se o código mudar de forma que o parser não entenda,
# o script falha em vez de gerar uma camada incompleta.
#
# Uso:
#   scripts/mitre_layer.py                          # imprime a camada no stdout
#   scripts/mitre_layer.py -o nta-mitre-layer.json  # grava em arquivo
#   scripts/mitre_layer.py --source outro/analyzer.c
#
# Abrir o JSON em https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload).
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT / "src" / "agent" / "analysis" / "analyzer.c"

ATTACK_VERSION = "16"        # versão do ATT&CK usada pelo Navigator na camada
NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"

FUNC_RE = re.compile(r"static\s+const\s+char\s*\*\s*attack_to_mitre\s*\([^)]*\)\s*\{")
ENTRY_RE = re.compile(
    r'if\s*\(\s*strcmp\(\s*attack\s*,\s*"([A-Z0-9_]+)"\s*\)\s*==\s*0\s*\)\s*'
    r'return\s*"([^"]*)"\s*;'
)


def parse_attack_to_mitre(source_text):
    """Devolve {ataque: [técnicas]} lido de attack_to_mitre().

    Levanta ValueError se a função não for encontrada ou se alguma comparação
    com strcmp(attack, ...) não casar com o padrão reconhecido.
    """
    m = FUNC_RE.search(source_text)
    if not m:
        raise ValueError("attack_to_mitre() não encontrada no código-fonte")
    end = source_text.find("\n}", m.end())
    if end < 0:
        raise ValueError("fim de attack_to_mitre() não encontrado")
    body = source_text[m.end():end]

    mapping = {}
    matched = 0
    for em in ENTRY_RE.finditer(body):
        matched += 1
        attack, mitre = em.group(1), em.group(2)
        techniques = [t.strip() for t in mitre.split(",") if t.strip()]
        mapping.setdefault(attack, [])
        for t in techniques:
            if t not in mapping[attack]:
                mapping[attack].append(t)

    total = body.count("strcmp(")
    if matched != total:
        raise ValueError(
            f"attack_to_mitre() tem {total} comparações com strcmp, mas só {matched} "
            "foram reconhecidas; ajuste o parser ou o código"
        )
    if not mapping:
        raise ValueError("nenhum mapeamento encontrado em attack_to_mitre()")
    return mapping


def build_layer(mapping):
    """Monta a camada ATT&CK Navigator (layer 4.5) a partir do mapeamento."""
    by_technique = {}
    for attack, techniques in mapping.items():
        for t in techniques:
            by_technique.setdefault(t, []).append(attack)

    techniques = []
    for tid in sorted(by_technique):
        techniques.append({
            "techniqueID": tid,
            "score": 1,
            "color": "",
            "comment": "Detectado pelo NTA: " + ", ".join(sorted(by_technique[tid])),
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        })

    return {
        "name": "NTA - cobertura MITRE ATT&CK",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "Técnicas que o NTA emite hoje, lidas de attack_to_mitre() em "
            "src/agent/analysis/analyzer.c por scripts/mitre_layer.py."
        ),
        "sorting": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1},
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Gera a camada do ATT&CK Navigator com as técnicas que o NTA emite "
                    "(lidas de attack_to_mitre() em analyzer.c)."
    )
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                    help="analyzer.c a ler (padrão: src/agent/analysis/analyzer.c)")
    ap.add_argument("-o", "--output", type=Path,
                    help="arquivo JSON de saída (padrão: stdout)")
    args = ap.parse_args(argv)

    try:
        text = args.source.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"erro: não foi possível ler {args.source}: {e}", file=sys.stderr)
        return 1

    try:
        mapping = parse_attack_to_mitre(text)
    except ValueError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 1

    out = json.dumps(build_layer(mapping), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"camada gravada em {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
