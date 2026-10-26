#!/usr/bin/env bash
# R2 — Offset de lectura por archivo e inodo: dos ciclos sin eventos nuevos no
# generan alertas nuevas. NO EJECUTADA.
set -uo pipefail

PG="docker exec lab-postgres psql -U admin -d security_monitoring -tAc"
OUT=lab/results/tests
mkdir -p "$OUT"

total() { $PG "SELECT count(*) FROM alerts;" | tr -d '[:space:]'; }
runs()  { $PG "SELECT count(*) FROM pipeline_runs;" | tr -d '[:space:]'; }
offsets(){ $PG "SELECT count(*) FROM file_offsets;" | tr -d '[:space:]'; }

echo "R2 | esperando que se estabilice un ciclo"
sleep 70

A0=$(total); R0=$(runs)
echo "  estado inicial: alerts=$A0 pipeline_runs=$R0 file_offsets=$(offsets)"

echo "R2 | dos ciclos sin trafico nuevo (130 s)"
sleep 130
A1=$(total); R1=$(runs)

echo "  estado final:   alerts=$A1 pipeline_runs=$R1"
printf 'alerts_antes=%s\nalerts_despues=%s\nruns_antes=%s\nruns_despues=%s\n' \
  "$A0" "$A1" "$R0" "$R1" | tee "$OUT/r2_offset.txt"

if [ "$A1" -eq "$A0" ] && [ "$R1" -gt "$R0" ]; then
  echo "RESULTADO: PASA (el flujo corrio y no reproceso eventos: offset efectivo)"
elif [ "$A1" -gt "$A0" ]; then
  echo "RESULTADO: FALLA (se generaron alertas sin eventos nuevos: posible reproceso)"
else
  echo "RESULTADO: NO CONCLUYENTE (el flujo no registro corridas nuevas)"
fi
