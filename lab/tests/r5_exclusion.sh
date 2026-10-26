#!/usr/bin/env bash
# R5 — Lista de exclusion y limite de bloqueos por tiempo. NO EJECUTADA.
#
# Caso A: una IP excluida (10.50.0.1, puerta de enlace) no debe bloquearse.
# Caso B: no existe tope de bloqueos por ventana: se documenta el defecto.
set -uo pipefail

ATTACKER=lab-attacker
VICTIM=lab-victim
OUT=lab/results/tests
mkdir -p "$OUT"
LOG="$OUT/r5_exclusion.txt"

post() {
  docker exec "$ATTACKER" python3 - "$VICTIM" "$1" <<'PY'
import sys, urllib.request
host, ip = sys.argv[1], sys.argv[2]
url = "http://%s:9000/block?ip=%s&ttl=120" % (host, ip)
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        print(ip, r.status, r.read(200).decode("latin1", "replace"))
except Exception as exc:
    print(ip, "error", exc)
PY
}

{
  echo "== A. Bloqueo de la IP excluida 10.50.0.1"
  post 10.50.0.1
  sleep 1
  docker exec "$VICTIM" iptables -S | grep "10.50.0.1" && echo "  REGLA PRESENTE" || echo "  sin regla (correcto)"
  echo
  echo "== B. Diez bloqueos seguidos: no hay tope por tiempo en el agente"
  for i in $(seq 1 10); do post "10.50.0.$((30+i))"; done
  sleep 1
  docker exec "$VICTIM" iptables -S | grep -c "LABBLOCK" || true
} | tee "$LOG"

if docker exec "$VICTIM" iptables -S | grep -q "10.50.0.1"; then
  echo "RESULTADO: FALLA (se bloqueo una IP excluida)"
else
  echo "RESULTADO: PASA en A (la IP excluida no se bloqueo); B evidencia la ausencia de tope"
fi

for i in $(seq 1 10); do
  docker exec "$ATTACKER" python3 - "$VICTIM" "10.50.0.$((30+i))" <<'PY' >/dev/null 2>&1 || true
import sys, urllib.request
host, ip = sys.argv[1], sys.argv[2]
try:
    urllib.request.urlopen("http://%s:9000/unblock?ip=%s" % (host, ip), timeout=5).read()
except Exception:
    pass
PY
done
