#!/usr/bin/env python3
"""Scan logger (userspace sensor) del laboratorio SIEM-SOAR.

En este host (WSL2) el objetivo `iptables -j LOG` NO emite lineas al log del
kernel dentro de un contenedor (limitacion nf_log_all_netns, no configurable),
y `klogd` no puede leer /proc/kmsg sin CAP_SYSLOG. Para mantener la fidelidad de
la tesis (regla id3 `iptables.*DROP.*DPT` sobre /var/log/security/alerts.log) se
usa un sensor AF_PACKET que observa a nivel de interfaz los SYN que llegan a los
puertos escaneados 30000-30030 (que la cadena SCANLOG descarta con DROP) y escribe
una linea identica a la que generaria el kernel:

  Oct 16 18:30:00 <host> kernel: iptables DROP: IN=eth0 ... SRC=<ip> ... DPT=<port> ... SYN

Se deduplica por (src_ip, puerto) con cooldown para que retransmisiones silenciosas
(del DROP) no inflen el conteo y un escaneo benigno sub-umbral no dispare alerta.
"""
import os
import socket
import struct
import time
from datetime import datetime, timezone

SCAN_PORTS = set(range(30000, 30031))
OUT = "/var/log/security/alerts.log"
COOLDOWN = 120  # segundos por (src, dport)
ETH_P_IP = 0x0800


def now_stamp():
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def main():
    os.makedirs("/var/log/security", exist_ok=True)
    hostname = socket.gethostname()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    s.bind(("eth0", 0))
    s.settimeout(1.0)
    last = {}
    f = open(OUT, "a")
    while True:
        try:
            frame = s.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            time.sleep(0.1)
            continue
        if len(frame) < 34:
            continue
        if struct.unpack_from("!H", frame, 12)[0] != ETH_P_IP:
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:  # TCP
            continue
        if len(ip) < ihl + 14:
            continue
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        tcp = ip[ihl:]
        sport, dpt = struct.unpack_from("!HH", tcp, 0)
        flags = tcp[13]
        # solo SYN inicial (SYN=1, ACK=0)
        if not (flags & 0x02) or (flags & 0x10):
            continue
        if dpt not in SCAN_PORTS:
            continue
        key = (src, dpt)
        t = time.time()
        if key in last and t - last[key] < COOLDOWN:
            continue
        last[key] = t
        if len(last) > 1000:
            for k in [k for k, v in last.items() if t - v > COOLDOWN]:
                del last[k]
        line = (
            "%s %s kernel: iptables DROP: IN=eth0 OUT= MAC=00:00:00:00:00:00 "
            "SRC=%s DST=%s LEN=60 PROTO=TCP SPT=%d DPT=%d WINDOW=1024 SYN"
            % (now_stamp(), hostname, src, dst, sport, dpt)
        )
        f.write(line + "\n")
        f.flush()


if __name__ == "__main__":
    main()
