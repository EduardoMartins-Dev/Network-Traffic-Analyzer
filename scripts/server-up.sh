#!/usr/bin/env bash
# server-up.sh — DEPRECATED. Wrapper de back-compat para up.sh.
#
# Antes: subia stack docker + ingestor em foreground.
# Agora: equivalente a `up.sh --foreground`.
# Use up.sh diretamente. Esta stub será removida em uma versão futura.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT_DIR/scripts/up.sh" --foreground "$@"
