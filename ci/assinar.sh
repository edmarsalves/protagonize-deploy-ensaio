#!/usr/bin/env bash
# Assina (keyless, OIDC do Actions) o atestado de proveniência de <imagem>@<digest> e a assinatura simples; com tentativas (o Sigstore público pode falhar de forma transitória).
set -euo pipefail
ref="$1"
python3 ci/gerar_predicado.py /tmp/predicado.json
for t in 1 2 3 4; do
  if /tmp/cosign attest --yes --predicate /tmp/predicado.json --type slsaprovenance1 "$ref"; then ok=1; break; fi
  echo "tentativa $t de atestar falhou; aguardando"; sleep $((t*20))
done
[ "${ok:-0}" = 1 ] || { echo "não foi possível atestar $ref"; exit 1; }
