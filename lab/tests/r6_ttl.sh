#!/usr/bin/env bash
# R6 — TTL, tope de reglas y desbloqueo. NO EJECUTADA.
#
# A: una regla de bloqueo desaparece sola despues del TTL (600 s por defecto).
# B: /unblock retira la regla antes del TTL.
# C: reiniciar el agente borra el estado (las reglas quedan huerfanas en iptables).
set -uo pipefail

ATTACKER=lab-attacker
VICTIM=lab-victim
OUT=lab/results/tests
mkdir -p "$OUT"
IP_A=10.50.0.250
IP_B=10.50.0.251
IP_C=10.50.0.252
TTL=600

call() {
  docker exec "$ATTACKER" python3 - "$VICTIM" "$1" "$2" <<'PY' || true
import sys, urllib.request
host, endpoint, ip = sys.argv[1], sys.argv[2], sys.argv[3]
url = "http://%s:9000/%s?ip=%s&ttl=600" % (host, endpoint, ip)
if endpoint == "unblock":
    url = "http://%s:9000/unblock?ip=%s" % (host, ip)
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        print(endpoint, ip, r.status, r.read(200).decode("latin1", "replace"))
except Exception as exc:
    print(endpoint, ip, "error", exc)
PY
}

has_rule() { docker exec "$VICTIM" iptables -S | grep -c "$1" || true; }

{
  echo "== A. TTL"
  call block "$IP_A"
  echo "  regla inmediata: $(has_rule "$IP_A")"
  echo "  esperando $((TTL + 30)) s..."
  sleep $((TTL + 30))
  echo "  regla despues del TTL: $(has_rule "$IP_A")"
  echo
  echo "== B. Desbloqueo manual"
  call block "$IP_B"
  echo "  regla inmediata: $(has_rule "$IP_B")"
  call unblock "$IP_B"
  echo "  regla despues de /unblock: $(has_rule "$IP_B")"
  echo
  echo "== C. Reinicio del agente"
  call block "$IP_C"
  echo "  regla antes del reinicio: $(has_rule "$IP_C")"
  docker restart lab-victim >/dev/null
  sleep 20
  echo "  regla despues del reinicio (el estado en memoria se pierde): $(has_rule "$IP_C")"
} | tee "$OUT/r6_ttl.txt"

A=$(has_rule "$IP_A"); B=$(has_rule "$IP_B")
if [ "${A:-1}" -eq 0 ] && [ "${B:-1}" -eq 0 ]; then
  echo "RESULTADO: PASA en A y B (el TTL expira y /unblock funciona); C documenta el estado en memoria"
else
  echo "RESULTADO: FALLA (revisar TTL o /unblock)"
fi

docker exec "$VICTIM" iptables -S | grep -q "$IP_C" && \
  docker exec "$VICTIM" iptables -D INPUT -s "$IP_C" -j DROP 2>/dev/null || true
