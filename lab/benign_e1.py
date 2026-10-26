#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""benign_e1.py — generador de trafico benigno etiquetado (POSTERIOR A LA CAMPANA).

No modifica el codigo medido: solo emite trafico y registra la evidencia.

Unidades que genera
-------------------
E1, tipo "subumbral"  : sesion SSH con 3 intentos fallidos (umbral de la regla 1 = 5
                        eventos / 300 s). No debe generar alerta en ninguno de los brazos.
E1, tipo "exitosa"    : inicio de sesion valido de testuser. No debe generar alerta.
E3, tipo "union_legit": GET con la cadena «union select» en un parametro de busqueda
                        legitimo. Sirve para medir falsos positivos de la regla
                        «(union.*select|drop.*table)» sobre uso normal.

Por cada unidad se registra: id, brazo, escenario, tipo, IP de origen, instante UTC,
si hubo respuesta HTTP y las lineas de log que el evento produjo (o «ninguna»).

Donde se ejecuta
----------------
Dentro del contenedor `lab-attacker`, que es el unico con `sshpass`, `ip` y el volumen
de logs de la victima montado en /logs. Desde el anfitrion:

    docker cp benign_e1.py lab-attacker:/opt/benign_e1.py
    docker exec lab-attacker python3 /opt/benign_e1.py --arm both --n 10 \
        --ip-base 10.50.0.230 --out /logs/benign_e1.jsonl
    docker cp lab-attacker:/logs/benign_e1.jsonl lab/results/benign_e1.jsonl

Las IP de origen deben quedar fuera del rango usado en la campana (10.50.0.200-.209)
y dentro de 10.50.0.0/24, para no reutilizar la misma IP que un episodio malicioso.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

WRONG_PASSWORD = "WrongPass_LAB!"
DEFAULT_PASSWORD = "CorrectHorseBattery"   # definida en lab/victim/Dockerfile
AUTH_LOG = "auth.log"
APACHE_LOG = os.path.join("apache_access", "all.log")


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ensure_src_ip(src):
    subprocess.run(["ip", "addr", "add", "%s/32" % src, "dev", "eth0"],
                   capture_output=True, text=True)


def ssh_attempt(src, target, user, password, timeout=4, command=None):
    cmd = [
        "sshpass", "-p", password, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "ConnectTimeout=%d" % timeout,
        "-b", src,
        "%s@%s" % (user, target),
    ]
    if command:
        cmd.append(command)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 8)
        out = (p.stderr or "") + (p.stdout or "")
        return p.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def http_get(src, target, port, path, timeout=4):
    """GET crudo con IP de origen fijada. Devuelve (status_line, bytes_leidos)."""
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
           "User-Agent: benign-e1/1.0\r\n\r\n" % (path, target))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.bind((src, 0))
    except OSError:
        pass
    try:
        s.connect((target, port))
        s.sendall(req.encode("latin1"))
        data = s.recv(512)
        first = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else ""
        return first, len(data)
    except OSError as exc:
        return "ERROR: %s" % exc, 0
    finally:
        try:
            s.close()
        except OSError:
            pass


def tail_lines(path, max_bytes=262144):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(-max_bytes, os.SEEK_END)
            blob = fh.read()
        return blob.decode("utf-8", "replace").splitlines()
    except OSError:
        return []


def capture(logs_dir, ip, since_dt, files, limit=6):
    """Lineas de log que mencionan la IP y son posteriores a `since_dt` (comparacion por marca)."""
    found = []
    stamp = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    for rel in files:
        path = os.path.join(logs_dir, rel)
        for line in tail_lines(path):
            if ip not in line:
                continue
            if rel == AUTH_LOG and not line.startswith(stamp[:16]):
                continue
            found.append(line.strip())
    return found[-limit:] if found else []


def run_unit(unit, args, logs_dir):
    t0 = now()
    log_files = []
    status = None
    detail = {}

    if unit["scenario"] == "E1" and unit["type"] == "subumbral":
        results = []
        for i in range(3):
            rc, out = ssh_attempt(unit["src_ip"], args.target, args.user, WRONG_PASSWORD)
            results.append({"attempt": i + 1, "rc": rc,
                            "auth_fail": "permission denied" in out.lower()})
            time.sleep(args.attempt_gap)
        detail["attempts"] = results
        log_files = [AUTH_LOG]

    elif unit["scenario"] == "E1" and unit["type"] == "exitosa":
        rc, out = ssh_attempt(unit["src_ip"], args.target, args.user, args.password,
                              command="true")
        detail["rc"] = rc
        detail["accepted"] = ("accepted password" in out.lower())
        log_files = [AUTH_LOG]

    elif unit["scenario"] == "E3" and unit["type"] == "union_legit":
        path = args.e3_path
        status, nbytes = http_get(unit["src_ip"], args.target, args.http_port, path)
        detail["request_line"] = "GET %s HTTP/1.1" % path
        detail["bytes_received"] = nbytes
        log_files = [APACHE_LOG]

    else:
        raise SystemExit("unidad no soportada: %r" % (unit,))

    time.sleep(args.capture_wait)
    lines = capture(logs_dir, unit["src_ip"], t0, log_files) if log_files else []

    unit_out = dict(unit)
    unit_out.update({
        "t0_iso": iso(t0),
        "http_status": status,
        "log_line": lines if lines else "ninguna",
        "detail": detail,
    })
    return unit_out


def plan(args):
    """Arma la lista de unidades. Alterna brazos si --arm both."""
    arms = ["n8n", "f2b"] if args.arm == "both" else [args.arm]
    units = []
    ip_counter = 0
    uid = 0
    for arm in arms:
        for i in range(args.n):
            ip = args.ip_base.rsplit(".", 1)[0] + "." + str(
                int(args.ip_base.rsplit(".", 1)[1]) + ip_counter)
            ip_counter += 1
            if args.scenario == "E1":
                for kind in ("subumbral", "exitosa"):
                    uid += 1
                    units.append({"id": uid, "arm": arm, "scenario": "E1", "type": kind, "src_ip": ip})
            else:
                uid += 1
                units.append({"id": uid, "arm": arm, "scenario": "E3",
                              "type": "union_legit", "src_ip": ip})
    return units


def main():
    ap = argparse.ArgumentParser(description="Trafico benigno etiquetado (post campaña)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--arm", default="both", choices=["n8n", "f2b", "both"])
    ap.add_argument("--scenario", default="E1", choices=["E1", "E3"])
    ap.add_argument("--n", type=int, default=10, help="unidades por brazo")
    ap.add_argument("--ip-base", default="10.50.0.230", help="primera IP de origen (dentro de 10.50.0.0/24)")
    ap.add_argument("--target", default="lab-victim")
    ap.add_argument("--user", default="testuser")
    ap.add_argument("--password", default=DEFAULT_PASSWORD)
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--e3-path", default="/?q=union+select+articulos&page=1")
    ap.add_argument("--logs-dir", default="/logs")
    ap.add_argument("--attempt-gap", type=float, default=2.0)
    ap.add_argument("--unit-gap", type=float, default=5.0)
    ap.add_argument("--capture-wait", type=float, default=1.0)
    args = ap.parse_args()

    if not os.path.isdir(args.logs_dir):
        raise SystemExit("no existe el directorio de logs: %s" % args.logs_dir)

    units = plan(args)
    print("unidades: %d | escenario %s | brazo(s) %s" % (len(units), args.scenario, args.arm))
    with open(args.out, "w", encoding="utf-8") as fh:
        for unit in units:
            ensure_src_ip(unit["src_ip"])
            rec = run_unit(unit, args, args.logs_dir)
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            print("  %02d %s %s %-10s %-11s logs=%s" % (
                rec["id"], rec["arm"], rec["scenario"], rec["type"], rec["src_ip"],
                "si" if rec["log_line"] != "ninguna" else "no"))
            time.sleep(args.unit_gap)
    print("listo: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
