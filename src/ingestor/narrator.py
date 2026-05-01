"""
narrator.py — gera narrativa em linguagem natural pra incidentes de score alto.

Backends:
  - ollama (default): chama Ollama local em http://localhost:11434/api/chat
  - groq            : chama Groq Cloud API (OpenAI-compatible)

Configuração via env vars (todas opcionais):
  NARRATOR_ENABLED      "1"|"0"            (default "1")
  NARRATOR_BACKEND      "ollama"|"groq"    (default "ollama")
  NARRATOR_MIN_SCORE    int                (default 80)
  NARRATOR_TIMEOUT      seg                (default 20)

  OLLAMA_URL            http://localhost:11434
  OLLAMA_MODEL          llama3.2

  GROQ_API_KEY          (lido também de deploy/secrets/groq.env)
  GROQ_MODEL            llama-3.3-70b-versatile

Pré-requisito Ollama: `ollama pull llama3.2` (ou o modelo escolhido).
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("Narrator")

NARRATOR_ENABLED = os.getenv("NARRATOR_ENABLED", "1") == "1"
NARRATOR_BACKEND = os.getenv("NARRATOR_BACKEND", "ollama").lower()
NARRATOR_MIN_SCORE = int(os.getenv("NARRATOR_MIN_SCORE", "80"))
NARRATOR_TIMEOUT = float(os.getenv("NARRATOR_TIMEOUT", "20"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Carrega GROQ_API_KEY de deploy/secrets/groq.env se ainda não estiver no env
_GROQ_ENV = Path(__file__).resolve().parent.parent.parent / "deploy" / "secrets" / "groq.env"
if not os.getenv("GROQ_API_KEY") and _GROQ_ENV.is_file():
    for line in _GROQ_ENV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k, v)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

SYSTEM_PROMPT = (
    "Você é um analista de SOC sênior. Recebe um JSON de incidente do IDS "
    "e devolve uma narrativa concisa em PT-BR no formato EXATO abaixo "
    "(sem markdown, sem bullets):\n\n"
    "INCIDENT | Severidade: <Crítica|Alta|Média> (<score>/100)\n\n"
    "O QUE ACONTECEU:\n"
    "<máx 4 linhas técnicas>\n\n"
    "POR QUE É CRÍTICO:\n"
    "<máx 2 linhas, citando técnica MITRE>\n\n"
    "AÇÃO RECOMENDADA:\n"
    "<um comando concreto: iptables, nft, ip route ou similar>\n\n"
    "MITRE ATT&CK: <techniques separadas por vírgula>\n\n"
    "Não invente dados além do JSON. Seja direto."
)


def _user_prompt(event: dict, agent_id: str) -> str:
    payload = dict(event)
    payload.setdefault("agent_id", agent_id)
    return "Incidente:\n" + json.dumps(payload, ensure_ascii=False, indent=2)


def _call_ollama(prompt: str) -> Optional[str]:
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=NARRATOR_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()
    except requests.exceptions.RequestException as e:
        logger.warning("Ollama indisponível (%s): %s", type(e).__name__, e)
    except (KeyError, ValueError) as e:
        logger.warning("Resposta Ollama malformada: %s", e)
    return None


def _call_groq(prompt: str) -> Optional[str]:
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY ausente — narrativa pulada")
        return None
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=NARRATOR_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except requests.exceptions.RequestException as e:
        logger.warning("Groq indisponível (%s): %s", type(e).__name__, e)
    except (KeyError, ValueError, IndexError) as e:
        logger.warning("Resposta Groq malformada: %s", e)
    return None


def should_narrate(event: dict) -> bool:
    if not NARRATOR_ENABLED:
        return False
    score = event.get("kc_score")
    return isinstance(score, (int, float)) and score >= NARRATOR_MIN_SCORE


def narrate(event: dict, agent_id: str = "unknown") -> Optional[str]:
    """Retorna texto da narrativa, ou None se desativado/falhar."""
    if not should_narrate(event):
        return None
    prompt = _user_prompt(event, agent_id)
    if NARRATOR_BACKEND == "ollama":
        return _call_ollama(prompt)
    if NARRATOR_BACKEND == "groq":
        return _call_groq(prompt)
    logger.warning("NARRATOR_BACKEND desconhecido: %s", NARRATOR_BACKEND)
    return None


def backend_label() -> str:
    if NARRATOR_BACKEND == "ollama":
        return f"ollama:{OLLAMA_MODEL}"
    if NARRATOR_BACKEND == "groq":
        return f"groq:{GROQ_MODEL}"
    return NARRATOR_BACKEND
