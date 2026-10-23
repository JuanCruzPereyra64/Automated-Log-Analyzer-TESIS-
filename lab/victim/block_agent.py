#!/usr/bin/env python3
"""Agente de bloqueo (Active Response executor) del laboratorio SIEM-SOAR.

Expone endpoints HTTP para aplicar/retirar reglas iptables en el namespace de red
del contenedor 'victim'. El pipeline n8n (arm=n8n) lo invoca como su accion de
respuesta activa. Registra cada evento con timestamp ISO-8601 en /var/log/blocks.log.

Endpoints:
  GET /block?ip=<ip>[&ttl=<seg>]   -> iptables DROP para <ip>
  GET /unblock?ip=<ip>             -> retira la regla
  GET /reset                       -> limpia la cadena LABBLOCK
  GET /blocked                     -> lista IPs bloqueadas (JSON)
"""
import json
import os
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

CHAIN = "LABBLOCK"
LOG = "/var/log/blocks.log"

_lock = threading.Lock()
_blocked = {}  # ip -> expiry_epoch (0 = sin ttl)


def log_event(kind, ip, extra=""):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = f"{ts} {kind} {ip} {extra}".strip()
    with _lock:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_chain():
    run(["iptables", "-N", CHAIN])
    # Asegura jump en INPUT
    r = run(["iptables", "-C", "INPUT", "-j", CHAIN])
    if r.returncode != 0:
        run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])


def do_block(ip, ttl=0):
    ensure_chain()
    with _lock:
        # evita duplicados
        if ip in _blocked and _blocked[ip] != 0 and _blocked[ip] > time.time():
            return
        run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        run(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
        _blocked[ip] = (time.time() + ttl) if ttl else 0
    log_event("BLOCK", ip, f"ttl={ttl}")


def do_unblock(ip):
    ensure_chain()
    with _lock:
        run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        _blocked.pop(ip, None)
    log_event("UNBLOCK", ip)


def do_reset():
    ensure_chain()
    with _lock:
        run(["iptables", "-F", CHAIN])
        _blocked.clear()
    log_event("RESET", "-")


def reap_expired():
    while True:
        now = time.time()
        with _lock:
            exp = [ip for ip, t in _blocked.items() if t and t <= now]
        for ip in exp:
            do_unblock(ip)
        time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        ip = (q.get("ip", [""])[0] or "").strip()
        ttl = int(q.get("ttl", ["0"])[0] or 0)
        if u.path == "/block" and ip:
            do_block(ip, ttl)
            self._send({"ok": True, "action": "block", "ip": ip, "ttl": ttl})
        elif u.path == "/unblock" and ip:
            do_unblock(ip)
            self._send({"ok": True, "action": "unblock", "ip": ip})
        elif u.path == "/reset":
            do_reset()
            self._send({"ok": True, "action": "reset"})
        elif u.path == "/blocked":
            with _lock:
                self._send({"blocked": list(_blocked.keys())})
        elif u.path == "/health":
            self._send({"ok": True})
        else:
            self._send({"ok": False, "error": "bad request"}, 400)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ensure_chain()
    threading.Thread(target=reap_expired, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)
    print("block_agent listening on :9000", flush=True)
    srv.serve_forever()
