#!/usr/bin/env python3
"""Generador de un episodio de ataque para el laboratorio SIEM-SOAR.

Escenarios (--scenario):
  e1  Fuerza bruta SSH (comportamiento original, identico).
  e2  Escaneo de puertos: SYN a >=22 puertos distintos en 30000..30030 desde
      una IP origen; t_k = envio del paquete que cruza el umbral (20o).
  e3  SQL Injection: un GET con payload UNION SELECT contra Apache; t_k = hora
      del request.

En todos los escenarios se mide ademas la contencion con una sonda TCP pura
(socket.connect) hacia un puerto NO bloqueado por SCANLOG; cuando n8n bloquea la
IP origen via block_agent (LABBLOCK DROP), la sonda deja de conectarse -> t_cont.
"""
import argparse
import json
import socket
import subprocess
import time
from datetime import datetime, timezone

PASSWORD = "WrongPass_LAB!"
SCAN_PORT_LO, SCAN_PORT_HI = 30000, 30030


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def iso(t):
    if t is None:
        return None
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ensure_src_ip(src):
    subprocess.run(["ip", "addr", "add", f"{src}/32", "dev", "eth0"], capture_output=True, text=True)


def ssh_attempt(src, target, user, connect_timeout):
    cmd = [
        "sshpass", "-p", PASSWORD, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-b", src,
        f"{user}@{target}",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=connect_timeout + 6)
        return p.returncode, (p.stderr or "") + (p.stdout or "")
    except subprocess.TimeoutExpired as e:
        return 124, str(e)


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def tcp_open(ip, port, timeout, bind_addr=None):
    """True si el handshake TCP se completa; False si timeout/refused/error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if bind_addr:
        try:
            s.bind((bind_addr, 0))
        except Exception:
            pass
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_loop(ip, port, src, poll_timeout, probe_timeout=0.5):
    """Sondea el puerto hasta observar la transicion abierto->cerrado (contencion).

    Exige haber visto el puerto ABIERTO al menos una vez antes de declarar
    contencion: asi un fallo espurio de la primera sonda (ARP aun no resuelto
    para una IP origen recien configurada) no marca t_cont antes de tiempo.
    """
    t_cont = None
    deadline = now_ts() + poll_timeout
    probes = 0
    open_seen = False
    while now_ts() < deadline:
        probes += 1
        if tcp_open(ip, port, probe_timeout, bind_addr=src):
            open_seen = True
        elif open_seen:
            t_cont = now_ts()
            break
        time.sleep(1.0)
    return t_cont, probes


def send_syn(src, target_ip, port):
    """Envia un SYN no-bloqueante desde src hacia target_ip:port (devuelve True si se envio)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.bind((src, 0))
    except Exception:
        pass
    try:
        s.connect_ex((target_ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_e2(args, tip):
    n_packets = 15 if args.benign else max(22, args.n)  # benigno: 15 < umbral 20
    ports = list(range(SCAN_PORT_LO, SCAN_PORT_LO + n_packets))
    t0 = None
    t_k = None
    sent = 0
    for i, port in enumerate(ports):
        t = now_ts()
        if t0 is None:
            t0 = t
        send_syn(args.src, tip, port)
        sent += 1
        if i == 19:  # el 20o paquete cruza el umbral (threshold=20)
            t_k = t
        time.sleep(0.4)
    if t_k is None:
        t_k = now_ts()
    if args.benign:
        return {
            "scenario": "e2", "benign": True, "n_packets": sent, "threshold_packet": 20,
            "ports": f"{ports[0]}-{ports[-1]}", "t0": t0, "t_k": t_k,
            "t_cont": None, "contained": None, "probes": 0,
        }
    t_cont, probes = probe_loop(tip, args.probe_port, args.src, args.poll_timeout)
    return {
        "scenario": "e2", "n_packets": sent, "threshold_packet": 20,
        "ports": f"{ports[0]}-{ports[-1]}",
        "t0": t0, "t_k": t_k, "t_cont": t_cont, "contained": t_cont is not None,
        "probes": probes,
    }


def run_e3(args, tip):
    payload = "/" if args.benign else "/?id=1'%20UNION%20SELECT%20username%20FROM%20users--"
    req = f"GET {payload} HTTP/1.1\r\nHost: lab-victim\r\nConnection: close\r\n\r\n"
    t_k = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.bind((args.src, 0))
        except Exception:
            pass
        s.connect((tip, args.probe_port))
        t_k = now_ts()
        s.sendall(req.encode("latin1"))
        try:
            s.recv(512)
        except Exception:
            pass
        s.close()
    except Exception:
        t_k = t_k or now_ts()
    if args.benign:
        return {
            "scenario": "e3", "benign": True, "payload": payload,
            "request_line": f"GET {payload} HTTP/1.1",
            "t0": t_k, "t_k": t_k, "t_cont": None, "contained": None, "probes": 0,
        }
    t_cont, probes = probe_loop(tip, args.probe_port, args.src, args.poll_timeout)
    return {
        "scenario": "e3", "payload": payload, "request_line": f"GET {payload} HTTP/1.1",
        "t0": t_k, "t_k": t_k, "t_cont": t_cont, "contained": t_cont is not None,
        "probes": probes,
    }


def run_e1(args, tip):
    attempts = []
    for i in range(args.n):
        t = now_ts()
        rc, err = ssh_attempt(args.src, args.target, args.user, 3)
        attempts.append({"i": i + 1, "t": t, "rc": rc, "auth_fail": ("permission denied" in err.lower())})
    t0 = attempts[0]["t"]
    t_k = attempts[-1]["t"]
    t_cont, probes = probe_loop(tip, args.probe_port, args.src, args.poll_timeout)
    return {
        "scenario": "e1", "user": args.user, "n": args.n, "attempts": attempts,
        "t0": t0, "t_k": t_k, "t_cont": t_cont, "contained": t_cont is not None,
        "probes": probes,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--user", default="testuser")
    ap.add_argument("--scenario", default="e1", choices=["e1", "e2", "e3"])
    ap.add_argument("--n", type=int, default=5, help="e1: intentos SSH; e2: paquetes SYN")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--probe-port", type=int, default=22,
                    help="puerto de la sonda de contencion (22 para e1/e2, 80 para e3)")
    ap.add_argument("--probe-timeout", type=float, default=0.5)
    ap.add_argument("--poll-timeout", type=float, default=120.0)
    ap.add_argument("--benign", action="store_true",
                    help="trafico benigno (sin sonda de contencion): e2=15 puertos (<umbral), e3='GET /'")
    args = ap.parse_args()

    # e3 sondea el puerto 80 (httpd); e1/e2 el 22
    if args.scenario == "e3" and args.probe_port == 22:
        args.probe_port = 80

    ensure_src_ip(args.src)
    tip = resolve(args.target)

    # Calentamiento: resolver ARP/ruta para la IP origen recien configurada y
    # confirmar que el puerto de la sonda esta accesible ANTES del ataque.
    if not args.benign:
        for _ in range(20):
            if tcp_open(tip, args.probe_port, 0.5, bind_addr=args.src):
                break
            time.sleep(0.3)

    if args.scenario == "e1":
        res = run_e1(args, tip)
    elif args.scenario == "e2":
        res = run_e2(args, tip)
    else:
        res = run_e3(args, tip)

    res.update({
        "src": args.src,
        "target": args.target,
        "target_ip": tip,
        "probe_port": args.probe_port,
        "t0_iso": iso(res.get("t0")),
        "t_k_iso": iso(res.get("t_k")),
        "t_cont_iso": iso(res.get("t_cont")),
    })
    print(json.dumps(res))


if __name__ == "__main__":
    main()
