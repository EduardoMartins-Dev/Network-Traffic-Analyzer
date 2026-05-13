#!/usr/bin/env python3
"""dash_gen.py — gerador de dashboards Grafana via Groq Cloud.

Recebe descrição em linguagem natural, monta prompt com schema do InfluxDB,
chama a Groq API, e empurra o dashboard para o Grafana via API
(POST /api/dashboards/db). O dashboard aparece imediatamente no Grafana e é
editável via UI — sobrevive a restarts pois é persistido em grafana_data.

Uso:
  ./scripts/dash_gen.py --name top-threats --desc "top 10 IPs por kc_score nos últimos 30 min"
  ./scripts/dash_gen.py -n dns-tunnel -d "DNS tunneling: queries/min por src_ip" --model llama-3.1-8b-instant
  ./scripts/dash_gen.py -n foo -d "..." --print          # imprime e não envia
  ./scripts/dash_gen.py -n foo -d "..." --save-file      # também grava em grafana/dashboards/

Variáveis de ambiente:
  GROQ_API_KEY        (lido também de deploy/secrets/groq.env)
  DASH_GEN_MODEL      llama-3.3-70b-versatile
  DASH_GEN_TIMEOUT    120
  GRAFANA_URL         http://localhost:3000
  GRAFANA_USER        admin
  GRAFANA_PASS        admin
  GRAFANA_API_KEY     (alternativa ao USER/PASS — token de service account)
  GRAFANA_FOLDER_UID  ('' = General)
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
DASH_DIR = ROOT / "grafana" / "dashboards"

# Carrega GROQ_API_KEY de deploy/secrets/groq.env se ainda não estiver no env.
_GROQ_ENV = ROOT / "deploy" / "secrets" / "groq.env"
if not os.getenv("GROQ_API_KEY") and _GROQ_ENV.is_file():
    for _line in _GROQ_ENV.read_text().splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _v = _line.split("=", 1)
        os.environ.setdefault(_k, _v)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("DASH_GEN_MODEL", "llama-3.3-70b-versatile")
TIMEOUT = float(os.getenv("DASH_GEN_TIMEOUT", "120"))

GRAFANA_URL = os.getenv("GRAFANA_URL", "http://localhost:3000").rstrip("/")
GRAFANA_USER = os.getenv("GRAFANA_USER", "admin")
GRAFANA_PASS = os.getenv("GRAFANA_PASS", "admin")
GRAFANA_API_KEY = os.getenv("GRAFANA_API_KEY", "")
GRAFANA_FOLDER_UID = os.getenv("GRAFANA_FOLDER_UID", "")

# Schema do InfluxDB do projeto (bucket: network_traffic, org: cybersecurity).
# Mantido aqui sincronizado com src/server/nta_influx.c (v7.0+).
SCHEMA = """
Datasource Grafana: type=influxdb, uid=influxdb-nta, language=Flux, bucket=network_traffic.

Measurements:
  - traffic              tags: agent_id, src_ip, protocol (TCP|UDP|ICMP), attack_type
                               (NONE|PORT_SCAN|SYN_FLOOD|ICMP_FLOOD|NULL_SCAN|XMAS_SCAN|
                                SYN_FIN_SCAN|BRUTE_FORCE|DNS_TUNNEL|ARP_SPOOF|DDOS_AMP),
                               kill_chain_stage (IDLE|RECON|EXPLOIT|EXFIL|COMPLETE),
                               mitre (T1046, T1110, T1071.004, T1498, T1557, ...)
                          fields: port, bytes, is_scan (0|1), kc_score (0-100), lat, lon

  - pipeline_metrics     tags: agent_id
                          fields: rb_pkt_depth, rb_evt_depth, rb_pkt_overflow,
                                  rb_evt_overflow, batches_sent, events_sent,
                                  events_per_sec

  - incident_narrative   tags: agent_id, src_ip, attack_type, kill_chain_stage, backend
                          fields: narrative (string), kc_score
"""

SYSTEM_PROMPT = f"""\
Você é um especialista em Grafana e Flux que gera dashboards JSON para um
sistema de detecção de intrusão (IDS).

{SCHEMA}

REGRAS RÍGIDAS — siga exatamente:
1. Saída: APENAS o JSON do dashboard. Nada antes, nada depois. Sem markdown,
   sem ```json, sem comentários. A primeira char é '{{', a última é '}}'.
2. Estrutura mínima do dashboard: {{ "title": str, "schemaVersion": 39,
   "version": 1, "editable": true, "panels": [...], "time": {{"from":"now-1h","to":"now"}},
   "refresh": "30s", "tags": ["nta","ai-gen"] }}
3. Cada panel tem: id (int único), type (stat|timeseries|table|gauge|piechart|bargauge|geomap),
   title, gridPos {{h,w,x,y}} (12 colunas, h em unidades de 30px),
   datasource {{"type":"influxdb","uid":"influxdb-nta"}},
   targets: [{{"refId":"A","query":"<flux>","datasource":{{"type":"influxdb","uid":"influxdb-nta"}}}}].
4. Queries Flux SEMPRE começam com from(bucket: "network_traffic")
   e usam range(start: v.timeRangeStart, stop: v.timeRangeStop) salvo se
   o usuário pediu janela específica.
5. Use APENAS measurements/tags/fields listados acima. Não invente nomes.
6. Layout: distribua os panels em até 12 colunas. Cada linha tem y diferente.
7. Use tipos coerentes com os dados:
   - stat        → contagens, último valor (events_per_sec, kc_score atual)
   - timeseries  → taxas no tempo (pps, bytes/s, eventos/min)
   - table       → top-N (top IPs, top portas)
   - geomap      → coordenadas lat/lon de IPs externos
   - piechart    → distribuição de protocolo, attack_type
"""

FEW_SHOT = """\
Exemplo de painel timeseries válido (referência de estrutura, NÃO inclua no output):
{
  "id": 1,
  "type": "timeseries",
  "title": "Eventos por segundo",
  "datasource": {"type":"influxdb","uid":"influxdb-nta"},
  "gridPos": {"h":8,"w":12,"x":0,"y":0},
  "targets": [{
    "refId":"A",
    "datasource": {"type":"influxdb","uid":"influxdb-nta"},
    "query":"from(bucket: \\"network_traffic\\")\\n  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)\\n  |> filter(fn: (r) => r._measurement == \\"pipeline_metrics\\" and r._field == \\"events_per_sec\\")\\n  |> aggregateWindow(every: 30s, fn: mean)"
  }]
}
"""


def build_user_prompt(desc: str, name: str) -> str:
    return (
        f"Gere um dashboard Grafana com title \"{name}\" focado em: {desc}\n\n"
        "Use 3 a 6 painéis cobrindo o tema. Devolva apenas o JSON.\n\n"
        + FEW_SHOT
    )


def call_groq(system: str, user: str, model: str) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY ausente — popule deploy/secrets/groq.env")
    resp = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def extract_json(text: str) -> dict:
    """Tira fences, lixo antes/depois e parseia."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM não retornou objeto JSON.")
    return json.loads(text[start : end + 1])


def validate(dash: dict, name: str) -> dict:
    """Garante o mínimo. Falha se LLM cortou caminho. Normaliza alguns campos."""
    if not isinstance(dash, dict):
        raise ValueError("dashboard não é objeto.")
    panels = dash.get("panels")
    if not isinstance(panels, list) or not panels:
        raise ValueError("dashboard sem 'panels'.")

    dash.setdefault("title", name)
    dash.setdefault("schemaVersion", 39)
    dash.setdefault("editable", True)
    dash.setdefault("time", {"from": "now-1h", "to": "now"})
    dash.setdefault("refresh", "30s")
    tags = dash.setdefault("tags", [])
    for t in ("nta", "ai-gen"):
        if t not in tags:
            tags.append(t)
    dash["uid"] = re.sub(r"[^a-zA-Z0-9_-]", "-", f"nta-ai-{name}")[:40]
    # Importante: a API do Grafana espera version=null OU omitido para criação;
    # o overwrite=true cobre updates. Removemos qualquer version do LLM.
    dash.pop("version", None)
    dash.pop("id", None)

    seen_ids = set()
    for i, p in enumerate(panels, 1):
        if not isinstance(p, dict):
            raise ValueError(f"painel {i} não é objeto.")
        if "id" not in p or p["id"] in seen_ids:
            p["id"] = i
        seen_ids.add(p["id"])
        p.setdefault("type", "timeseries")
        p.setdefault("title", f"Panel {i}")
        p.setdefault("datasource", {"type": "influxdb", "uid": "influxdb-nta"})
        p.setdefault("gridPos", {"h": 8, "w": 12, "x": 0, "y": (i - 1) * 8})
        targets = p.get("targets") or []
        if not targets:
            raise ValueError(f"painel {i} sem 'targets'.")
        for t in targets:
            t.setdefault("refId", "A")
            t.setdefault("datasource", {"type": "influxdb", "uid": "influxdb-nta"})
            if "query" not in t or not t["query"]:
                raise ValueError(f"painel {i} target sem 'query'.")
            if 'from(bucket:' not in t["query"]:
                raise ValueError(f"painel {i} query não começa com from(bucket:).")
    return dash


def push_to_grafana(dash: dict, message: str = "Generated by dash_gen.py") -> dict:
    """POST /api/dashboards/db. Retorna dict da resposta (uid, url, version)."""
    body = {
        "dashboard": dash,
        "overwrite": True,
        "message": message,
    }
    if GRAFANA_FOLDER_UID:
        body["folderUid"] = GRAFANA_FOLDER_UID

    headers = {"Content-Type": "application/json"}
    auth = None
    if GRAFANA_API_KEY:
        headers["Authorization"] = f"Bearer {GRAFANA_API_KEY}"
    else:
        auth = (GRAFANA_USER, GRAFANA_PASS)

    resp = requests.post(
        f"{GRAFANA_URL}/api/dashboards/db",
        headers=headers,
        auth=auth,
        json=body,
        timeout=15,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Grafana API HTTP {resp.status_code}: {resp.text[:500]}")
    return resp.json()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--name", required=True, help="slug do dashboard (vira o título e UID)")
    ap.add_argument("-d", "--desc", required=True, help="descrição em linguagem natural")
    ap.add_argument("--model", default=GROQ_MODEL, help=f"modelo Groq (default: {GROQ_MODEL})")
    ap.add_argument("--print", action="store_true", help="imprime o JSON em stdout em vez de enviar")
    ap.add_argument("--save-file", action="store_true", help="também grava em grafana/dashboards/<slug>.json (versionável)")
    ap.add_argument("--no-push", action="store_true", help="não envia para o Grafana (combina com --save-file ou --print)")
    args = ap.parse_args()

    slug = re.sub(r"[^a-z0-9-]", "-", args.name.lower()).strip("-")
    if not slug:
        print("✗ --name inválido (precisa ter chars alfanuméricos).", file=sys.stderr)
        return 2

    print(f"▶ chamando Groq (model={args.model}, timeout={TIMEOUT}s)...", file=sys.stderr)
    try:
        raw = call_groq(SYSTEM_PROMPT, build_user_prompt(args.desc, slug), args.model)
    except (requests.exceptions.RequestException, RuntimeError) as e:
        print(f"✗ Groq falhou: {e}", file=sys.stderr)
        print(f"  Garanta que GROQ_API_KEY está em deploy/secrets/groq.env", file=sys.stderr)
        return 1

    try:
        dash = extract_json(raw)
        dash = validate(dash, slug)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"✗ JSON inválido do LLM: {e}", file=sys.stderr)
        print("--- raw output ---", file=sys.stderr)
        print(raw[:2000], file=sys.stderr)
        return 1

    pretty = json.dumps(dash, indent=2, ensure_ascii=False)

    if args.print:
        print(pretty)

    if args.save_file:
        DASH_DIR.mkdir(parents=True, exist_ok=True)
        out = DASH_DIR / f"{slug}.json"
        out.write_text(pretty + "\n", encoding="utf-8")
        print(f"✓ JSON gravado: {out}")

    if args.no_push:
        return 0

    print(f"▶ enviando para Grafana em {GRAFANA_URL}...", file=sys.stderr)
    try:
        result = push_to_grafana(dash, message=f"AI-generated: {args.desc[:80]}")
    except (requests.exceptions.RequestException, RuntimeError) as e:
        print(f"✗ Grafana API falhou: {e}", file=sys.stderr)
        print(f"  Verifique GRAFANA_URL/USER/PASS ou se o stack está de pé.", file=sys.stderr)
        return 1

    uid = result.get("uid", dash["uid"])
    url_path = result.get("url", f"/d/{uid}")
    print(f"✓ dashboard publicado no Grafana")
    print(f"  UID:    {uid}")
    print(f"  URL:    {GRAFANA_URL}{url_path}")
    print(f"  Versão: {result.get('version', '?')}")
    print(f"  Painéis: {len(dash['panels'])} · tags: {', '.join(dash['tags'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
