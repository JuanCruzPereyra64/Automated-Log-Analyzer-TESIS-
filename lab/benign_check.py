#!/usr/bin/env python3
"""Chequeos benignos (Tabla 10 / VN) para E2 (escaneo de puertos) y E3 (SQLi).

Genera trafico benigno desde 10 IPs unicas por escenario y verifica que el
pipeline n8n NO genere alertas (FP=0, VN=10). Guarda results/benign_e2_e3_summary.json.

E2 benigno: escaneo de solo 15 puertos (30000-30014) < umbral 20.
E3 benigno: peticion 'GET /' sin payload de inyeccion.
"""
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

LAB = Path(__file__).resolve().parent
RESULTS = LAB / "results"
DB = "security_monitoring"
N = 10
PG = ["docker", "exec", "lab-postgres", "psql", "-U", "admin", "-d", DB, "-t", "-A", "-c"]
VICTIM = ["docker", "exec", "lab-victim", "sh", "-c"]
ATT = ["docker", "exec", "lab-attacker"]


def sh(args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def psql(sql):
    return sh(PG + [sql])[1]


def reset_db():
    sh(["docker", "exec", "lab-postgres", "psql", "-U", "admin", "-d", DB, "-f", "/tmp/reset_db.sql"])


def reset_victim():
    return sh(VICTIM + ["/opt/reset_victim.sh"])[1]


def benign(src, scenario):
    rc, out, err = sh(ATT + ["python3", "/opt/attack.py", "--src", src,
                             "--target", "lab-victim", "--scenario", scenario,
                             "--benign", "--poll-timeout", "1"])
    try:
        return json.loads(out.splitlines()[-1])
    except Exception:
        return {"error": "parse", "raw": out, "stderr": err}


def alerts_count(src):
    v = psql(f"SELECT count(*) FROM alerts WHERE source_ip='{src}';")
    return int(v or 0)


def run_benign(scenario, base, label):
    reset_db()
    reset_victim()
    time.sleep(3)
    srcs = []
    for i in range(N):
        src = f"{base}.{10 + i}"
        srcs.append(src)
        r = benign(src, scenario)
        print(f"[{label}] {i + 1}/{N} src={src} sent={r.get('n_packets', r.get('request_line', ''))}", flush=True)
        time.sleep(5)
    print(f"[{label}] esperando drenaje del pipeline (90s)...", flush=True)
    time.sleep(90)
    details = []
    fp = 0
    for src in srcs:
        n = alerts_count(src)
        details.append({"src": src, "alerts": n})
        if n > 0:
            fp += 1
    return {"scenario": scenario, "n": N, "fp": fp, "vn": N - fp, "details": details}


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)

    before = int(psql("SELECT count(*) FROM alerts;") or 0)
    e2 = run_benign("e2", "10.50.1", "benignE2")
    e3 = run_benign("e3", "10.50.2", "benignE3")
    after = int(psql("SELECT count(*) FROM alerts;") or 0)

    summary = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "arm": "n8n",
        "alerts_before": before,
        "alerts_after_e3": after,
        "total_alerts_generated": after - before,
        "e2": e2,
        "e3": e3,
    }
    out = RESULTS / "benign_e2_e3_summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    print(f"guardado en {out}", flush=True)


if __name__ == "__main__":
    main()
