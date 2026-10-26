#!/usr/bin/env bash
# R8 — Flujo de error, reintentos y alerta de latido del propio pipeline.
# NO EJECUTADA. Resultado esperado segun el codigo medido: FALLA (no hay latido).
set -uo pipefail

PG="docker exec lab-postgres psql -U admin -d security_monitoring -tAc"
OUT=lab/results/tests
mkdir -p "$OUT"

runs_before() { $PG "SELECT count(*) FROM pipeline_runs;" | tr -d '[:space:]'; }
last_run()    { $PG "SELECT coalesce(max(run_ts)::text,'ninguna') FROM pipeline_runs;" | tr -d '[:space:]'; }
alerts()      { $PG "SELECT count(*) FROM alerts WHERE rule_name ILIKE '%heartbeat%' OR category ILIKE '%latido%';" | tr -d '[:space:]'; }

echo "R8 | desactivando el flujo"
# Con la CLI de n8n no se puede desactivar un flujo importado; se hace desde la UI
# o se detiene la instancia entera:
docker stop lab-n8n >/dev/null
sleep 10

R0=$(runs_before)
echo "  corridas registradas: $R0 | ultimo run_ts: $(last_run)"
echo "  esperando 180 s para verificar si aparece un latido o una alerta de fallo..."
sleep 180

HB=$(alerts)
echo "  alertas de latido: ${HB:-0}"
printf 'runs=%s\nultimo_run_ts=%s\nalertas_latido=%s\n' "$R0" "$(last_run)" "$HB" \
  | tee "$OUT/r8_latido.txt"

docker start lab-n8n >/dev/null

if [ "${HB:-0}" -eq 0 ]; then
  echo "RESULTADO: FALLA (no existe alerta de latido: un fallo silencioso sigue siendo indistinguible)"
  echo "  Coincide con lo declarado en la Tabla 11 (R8 parcial) y en la seccion 7.2."
else
  echo "RESULTADO: PASA (hay alerta de latido: actualizar la Tabla 11)"
fi
