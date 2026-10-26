#!/usr/bin/env bash
# R3 — Lectura de logs con el nodo de archivos o con una ingesta por webhook, y
# declaracion de la configuracion de n8n que lo habilita. NO EJECUTADA.
#
# Esta prueba documenta el incumplimiento: el pipeline lee con fs dentro del nodo
# Code y depende de NODE_FUNCTION_ALLOW_BUILTIN, que tambien habilita child_process.
set -uo pipefail

OUT=lab/results/tests
mkdir -p "$OUT"
LOG="$OUT/r3_ingesta.txt"

{
  echo "== 1. Variables de entorno del contenedor n8n"
  docker exec lab-n8n sh -c 'env | grep -E "NODE_FUNCTION_ALLOW|N8N_RESTRICT_FILE_ACCESS_TO|N8N_RUNNERS"' || true
  echo
  echo "== 2. Uso de require() en el codigo medido"
  grep -n "require(" lab/pipeline.js || true
  echo
  echo "== 3. Nodos del flujo medido"
  grep -o '"type": *"[^"]*"' lab/pipeline-wf.json | sort -u || true
} | tee "$LOG"

if grep -q "require('fs')" lab/pipeline.js && grep -q "NODE_FUNCTION_ALLOW_BUILTIN" lab/docker-compose.yml; then
  echo "RESULTADO: FALLA (R3 no se cumple: lectura con fs dentro del nodo Code)"
  echo "  La instalacion limpia sin NODE_FUNCTION_ALLOW_BUILTIN falla en el primer ciclo;"
  echo "  para reproducirlo, retirar la variable del compose y reiniciar lab-n8n."
  echo "RESULTADO: FALLA" >> "$LOG"
else
  echo "RESULTADO: NO CONCLUYENTE (revisar el codigo y el compose: no se encontro el patron esperado)"
fi
