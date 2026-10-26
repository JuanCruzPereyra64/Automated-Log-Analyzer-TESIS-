#!/usr/bin/env bash
# R1 — Ventana deslizante con T menor que la ventana (regla 1: 5 eventos / 300 s).
# NO EJECUTADA: requiere el laboratorio levantado.
#
# Caso A (dentro de la ventana): 5 intentos SSH en ~20 s -> debe generar alerta.
# Caso B (defecto de la gracia): 5 intentos repartidos entre 0 y 400 s, con una
#   alerta previa del mismo origen, -> puede NO generar la segunda alerta.
set -uo pipefail

VICTIM=lab-victim
ATTACKER=lab-attacker
PG="docker exec lab-postgres psql -U admin -d security_monitoring -tAc"
IP_A=10.50.0.240
IP_B=10.50.0.241
OUT=lab/results/tests
mkdir -p "$OUT"

alerts_for() { $PG "SELECT count(*) FROM alerts WHERE source_ip='$1';" | tr -d '[:space:]'; }
wait_cycle()  { sleep 130; }   # un ciclo de sondeo (60 s) + margen de proceso

echo "R1 | caso A: 5 intentos en 20 s desde $IP_A"
docker exec "$ATTACKER" ip addr add "$IP_A/32" dev eth0 2>/dev/null || true
for i in 1 2 3 4 5; do
  docker exec "$ATTACKER" sshpass -p 'WrongPass_LAB!' ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
    -b "$IP_A" testuser@"$VICTIM" true 2>/dev/null
  sleep 4
done
wait_cycle
A=$(alerts_for "$IP_A")
echo "  alertas para $IP_A: $A (se espera >= 1)"

echo "R1 | caso B: 5 intentos repartidos en 400 s desde $IP_B"
docker exec "$ATTACKER" ip addr add "$IP_B/32" dev eth0 2>/dev/null || true
for i in 1 2 3 4 5; do
  docker exec "$ATTACKER" sshpass -p 'WrongPass_LAB!' ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
    -b "$IP_B" testuser@"$VICTIM" true 2>/dev/null
  sleep 90
done
wait_cycle
B=$(alerts_for "$IP_B")
echo "  alertas para $IP_B: $B"

{
  echo "casoA_ip=$IP_A alertas=$A"
  echo "casoB_ip=$IP_B alertas=$B"
} | tee "$OUT/r1_ventana.txt"

if [ "${A:-0}" -ge 1 ] && [ "${B:-0}" -eq 0 ]; then
  echo "RESULTADO: FALLA (el caso B evidencia el defecto de la ventana efectiva)"
elif [ "${A:-0}" -ge 1 ]; then
  echo "RESULTADO: PASA (el caso B también alertó; revisar la gracia antes de concluir)"
else
  echo "RESULTADO: NO CONCLUYENTE (el caso A no alertó: revisar el flujo y el sondeo)"
fi

$PG "DELETE FROM alerts WHERE source_ip IN ('$IP_A','$IP_B');" >/dev/null 2>&1 || true
