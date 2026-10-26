#!/usr/bin/env bash
# R7 y R9 — Cuota de AbuseIPDB y puntaje como condicion de respuesta.
# Ya verificado con respuestas simuladas durante la campana: este script lo
# reproduce y guarda la salida. NO EJECUTADA en esta instancia.
set -uo pipefail

OUT=lab/results/tests
mkdir -p "$OUT"

{
  echo "== Verificacion de R7 y R9 con respuestas simuladas"
  docker cp lab/verify_r7_r9.js lab-n8n:/tmp/verify_r7_r9.js
  docker exec lab-n8n node /tmp/verify_r7_r9.js
} | tee "$OUT/r7_r9_verificacion.txt"

if grep -qi "fail\|error" "$OUT/r7_r9_verificacion.txt"; then
  echo "RESULTADO: FALLA (revisar la salida)"
else
  echo "RESULTADO: PASA (comprobaciones de cuota y de umbral de puntaje)"
fi

echo "Nota: la integracion contra la API real de AbuseIPDB no se probo por ausencia de clave."
