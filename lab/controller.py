#!/usr/bin/env python3
"""Controlador de la campana experimental (escenario E1, fuerza bruta SSH).

Orquesta episodios para un brazo (n8n o f2b):
  - congela estado (iptables, logs, BD),
  - alterna Fail2ban segun el brazo,
  - ejecuta el generador de ataque desde una IP de origen unica,
  - lee t_det (alerts.timestamp para n8n; linea 'Ban' para Fail2ban),
  - calcula MTTD = t_det - t_k y MTTR = t_cont - t_det,
  - persiste resultados en JSONL/CSV.

Uso:
  python controller.py --arm n8n --n 10 --spacing 300
  python controller.py --arm f2b --n 10 --spacing 300
"""
import argparse
import json
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

LAB = Path(__file__).resolve().parent
RESULTS = LAB / "results"
DB = "security_monitoring"

PG = ["docker", "exec", "lab-postgres", "psql", "-U", "admin", "-d", DB, "-t", "-A", "-c"]
VICTIM = ["docker", "exec", "lab-victim", "sh", "-c"]
ATT = ["docker", "exec", "lab-attacker"]


def sh(args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def psql(sql, quiet=True):
    rc, out, err = sh(PG + [sql])
    if rc != 0 and not quiet:
        print("psql err:", err)
    return out


def utc_iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def set_arm(arm):
    psql("CREATE TABLE IF NOT EXISTS lab_config(key text primary key, value text);")
    psql(f"INSERT INTO lab_config(key,value) VALUES('arm','{arm}') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;")


def reset_db():
    rc, out, err = sh(["docker", "exec", "lab-postgres", "psql", "-U", "admin", "-d", DB, "-f", "/tmp/reset_db.sql"])
    return out


def reset_victim():
    return sh(VICTIM + ["/opt/reset_victim.sh"])[1]


def stop_f2b():
    return sh(VICTIM + ["/opt/stop_f2b.sh"])[1]


def start_f2b():
    return sh(VICTIM + ["/opt/start_f2b.sh"])[1]


def install_scripts():
    """Copia los scripts de control a los contenedores (idempotente)."""
    for src, dst in [
        (LAB / "scripts" / "reset_db.sql", "lab-postgres:/tmp/reset_db.sql"),
        (LAB / "scripts" / "reset_victim.sh", "lab-victim:/opt/reset_victim.sh"),
        (LAB / "scripts" / "stop_f2b.sh", "lab-victim:/opt/stop_f2b.sh"),
        (LAB / "scripts" / "start_f2b.sh", "lab-victim:/opt/start_f2b.sh"),
    ]:
        rc, out, err = sh(["docker", "cp", str(src), dst])
        if rc != 0:
            print(f"  ! docker cp {src} -> {dst} fallo: {err}", flush=True)


def attack(src, n, scenario, poll_timeout=180):
    rc, out, err = sh(ATT + ["python3", "/opt/attack.py", "--src", src,
                             "--target", "lab-victim", "--n", str(n),
                             "--scenario", scenario,
                             "--poll-timeout", str(poll_timeout)])
    try:
        return json.loads(out.splitlines()[-1])
    except Exception:
        return {"error": "parse", "raw": out, "stderr": err}


def wait_alert_n8n(src, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = psql(f"SELECT extract(epoch from timestamp) FROM alerts WHERE source_ip='{src}' ORDER BY id DESC LIMIT 1;")
        if v:
            try:
                return float(v), int(psql(f"SELECT id FROM alerts WHERE source_ip='{src}' ORDER BY id DESC LIMIT 1;") or 0)
            except ValueError:
                pass
        time.sleep(2)
    return None, None


def wait_ban_f2b(src, since_epoch, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out, err = sh(VICTIM + [f"grep '\\[sshd\\] Ban {src}' /var/log/fail2ban.log 2>/dev/null | tail -1"])
        if out:
            # '2026-10-16 11:59:28,477 fail2ban.actions ...'
            ts = out.split(" fail2ban")[0].strip()
            try:
                dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)
                ep = dt.timestamp()
                if ep >= since_epoch - 5:
                    return ep
            except Exception:
                pass
        time.sleep(1)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=["n8n", "f2b"])
    ap.add_argument("--scenario", default="e1", choices=["e1", "e2", "e3"])
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--spacing", type=float, default=300.0)
    ap.add_argument("--spacing-jitter", type=float, default=60.0,
                    help="Jitter aleatorio (s) sumado al espaciado para romper el "
                         "phase-locking con el sondeo periodico del pipeline")
    ap.add_argument("--seed", type=int, default=12345)
    ap.add_argument("--n-attempts", type=int, default=5)
    ap.add_argument("--start-index", type=int, default=0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else RESULTS / f"{args.arm}_{args.scenario}.jsonl"
    fout = open(out_path, "a", encoding="utf-8")
    rng = random.Random(args.seed)

    print(f"=== campana arm={args.arm} scenario={args.scenario} n={args.n} spacing={args.spacing}s "
          f"jitter={args.spacing_jitter}s seed={args.seed} -> {out_path}", flush=True)
    set_arm(args.arm)
    install_scripts()

    for i in range(args.n):
        idx = args.start_index + i
        src = f"10.50.0.{200 + idx}"
        ep_start = time.time()
        print(f"[{args.arm}] episodio {i+1}/{args.n} src={src}", flush=True)

        if args.arm == "n8n":
            print("  ", stop_f2b(), flush=True)
        else:
            print("  ", start_f2b(), flush=True)

        print("  ", reset_victim(), flush=True)
        reset_db()
        time.sleep(4)  # settle

        res = attack(src, args.n_attempts, args.scenario)
        t0, tk, tcont = res.get("t0"), res.get("t_k"), res.get("t_cont")
        contained = res.get("contained", False)

        since = tk if tk else time.time()
        if args.arm == "n8n":
            tdet, alert_id = wait_alert_n8n(src)
        else:
            tdet = wait_ban_f2b(src, since)
            alert_id = None

        mttd = (tdet - tk) if (tdet and tk) else None
        mttr = (tcont - tdet) if (tcont and tdet) else None
        rec = {
            "arm": args.arm, "scenario": args.scenario, "episode": i + 1, "index": idx, "src_ip": src,
            "t0": t0, "t_k": tk, "t_det": tdet, "t_cont": tcont,
            "t0_iso": utc_iso(t0) if t0 else None,
            "t_k_iso": utc_iso(tk) if tk else None,
            "t_det_iso": utc_iso(tdet) if tdet else None,
            "t_cont_iso": utc_iso(tcont) if tcont else None,
            "detected": tdet is not None,
            "contained": contained,
            "MTTD": mttd, "MTTR": mttr,
            "alert_id": alert_id,
            "probes": res.get("probes"),
            "seed": args.seed,
            "gen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        fout.write(json.dumps(rec) + "\n")
        fout.flush()
        print(f"  -> detected={rec['detected']} contained={rec['contained']} "
              f"MTTD={mttd and round(mttd,2)} MTTR={mttr and round(mttr,2)}", flush=True)

        if i < args.n - 1:
            elapsed = time.time() - ep_start
            gap = args.spacing + rng.uniform(0.0, args.spacing_jitter)
            wait = max(0.0, gap - elapsed)
            print(f"  reposo {wait:.0f}s (gap objetivo {gap:.0f}s)", flush=True)
            time.sleep(wait)

    fout.close()
    print(f"=== campana {args.arm} finalizada ===", flush=True)


if __name__ == "__main__":
    main()
