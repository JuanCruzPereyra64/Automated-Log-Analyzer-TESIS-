#!/usr/bin/env bash
# R4 — Validacion de la direccion antes de cualquier comando. NO EJECUTADA.
#
# Caso A: el pipeline debe descartar una IP con metacaracteres.
# Caso B: el agente de bloqueo no debe ejecutar nada con una IP invalida.
set -uo pipefail

ATTACKER=lab-attacker
VICTIM=lab-victim
PG="docker exec lab-postgres psql -U admin -d security_monitoring -tAc"
OUT=lab/results/tests
mkdir -p "$OUT"
IP_INV='10.50.0.99;id'
LOG="$OUT/r4_inyeccion_ip.txt"

rules() { docker exec "$VICTIM" iptables -S | grep -c "10.50.0.99" || true; }

echo "R4 | reglas con 10.50.0.99 antes: $(rules)"
{
  echo "== A. Pedido directo al agente con IP invalida"
  docker exec "$ATTACKER" python3 - "$VICTIM" <<'PY'
import sys, urllib.request
host = sys.argv[1]
url = "http://%s:9000/block?ip=10.50.0.99;id&ttl=60" % host
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        print("status", r.status, r.read(200).decode("latin1", "replace"))
except Exception as exc:
    print("error", exc)
PY
  echo
  echo "== B. Insercion de una alerta con IP no canonica en parsed_events"
  $PG "INSERT INTO parsed_events (event_ts, rule_name, src_ip, raw_log, ingest_ts)
       VALUES (now(), 'SSH Brute Force', '10.50.0.99;id', 'test r4', now());" || true
  echo "  insertado; el proximo ciclo no debe disparar ningun comando"
  sleep 70
  echo "== C. Reglas con 10.50.0.99 despues"
  docker exec "$VICTIM" iptables -S | grep "10.50.0.99" || echo "  (ninguna)"
} | tee "$LOG"

AFTER=$(rules)
if [ "${AFTER:-0}" -eq 0 ]; then
  echo "RESULTADO: PASA (no se aplico ninguna regla con una IP no canonica)"
else
  echo "RESULTADO: FALLA (se aplico una regla a partir de una IP no canonica)"
fi

$PG "DELETE FROM parsed_events WHERE raw_log='test r4';" >/dev/null 2>&1 || true
