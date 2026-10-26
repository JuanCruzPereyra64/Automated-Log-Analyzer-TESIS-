#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_manifest.py  —  POSTERIOR A LA CAMPANA (no participa de la medicion)

Registra la trazabilidad de una campana del laboratorio:
  * commit de git (git rev-parse HEAD) y estado del arbol de trabajo
  * SHA-256 de los archivos que definen el sistema medido
  * SHA-256 de cada archivo de resultados (.jsonl)
  * semilla y orden de corridas reconstruido desde los registros
  * versiones de los contenedores e imagenes (docker)
  * fecha UTC de inicio y de fin

Uso:
    python lab/make_manifest.py --campaign e1_e3
    python lab/make_manifest.py --campaign e1_rerun --seed 20261016 --out lab/results/manifest_e1_rerun.json

Salida por defecto: lab/results/manifest_<campaign>.json

No modifica ningun archivo del laboratorio ni de los resultados: solo lee.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# Archivos que definen el sistema medido (rutas relativas a la raiz del repo).
TRACKED = [
    "lab/pipeline.js",
    "lab/pipeline-wf.json",
    "lab/victim/block_agent.py",
    "lab/victim/jail.local",
    "lab/scripts/seed_rules.sql",
    "lab/docker-compose.yml",
]

# Archivos de resultados de la campana original.
RESULT_FILES = [
    "lab/results/n8n_e1.jsonl",
    "lab/results/n8n_e2.jsonl",
    "lab/results/n8n_e3.jsonl",
    "lab/results/f2b_e1.jsonl",
]


def find_root(start):
    """Sube desde `start` hasta encontrar un directorio con lab/ y Database/.

    Si no lo encuentra, busca un unico subdirectorio que los contenga (caso del
    repositorio clonado dentro de la carpeta de trabajo de la tesis).
    """
    cur = os.path.abspath(start)
    for _ in range(6):
        if os.path.isdir(os.path.join(cur, "lab")) and os.path.isdir(os.path.join(cur, "Database")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    base = os.path.abspath(start)
    for _ in range(6):
        cands = [
            os.path.join(base, d) for d in sorted(os.listdir(base))
            if os.path.isdir(os.path.join(base, d, "lab"))
            and os.path.isdir(os.path.join(base, d, "Database"))
        ]
        if len(cands) == 1:
            return cands[0]
        parent = os.path.dirname(base)
        if parent == base:
            break
        base = parent
    return os.path.abspath(start)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None):
    try:
        out = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=30,
        )
        return out.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def git_info(root):
    head = run(["git", "rev-parse", "HEAD"], cwd=root)
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    dirty = run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root)
    tags = run(["git", "tag", "--points-at", "HEAD"], cwd=root)
    if not head:
        return {
            "commit": "NO VERIFICABLE CON EL MATERIAL DISPONIBLE",
            "branch": None,
            "dirty": None,
            "tags": [],
            "nota": "El directorio no es un repositorio git o git no esta en PATH.",
        }
    return {
        "commit": head,
        "branch": branch or None,
        "dirty": bool(dirty),
        "working_tree_changes": len([l for l in dirty.splitlines() if l.strip()]) if dirty else 0,
        "tags": [t for t in tags.splitlines() if t.strip()],
    }


def read_jsonl(path):
    recs = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except ValueError:
                continue
    return recs


def iso_to_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def campaign_window(root, files):
    """Ventana UTC de la campana: min t0 y max de t_cont/t0 de los registros."""
    start = None
    end = None
    order = []
    seeds = set()
    for rel in files:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        for rec in read_jsonl(path):
            t0 = iso_to_dt(rec.get("t0_iso"))
            tc = iso_to_dt(rec.get("t_cont_iso")) or iso_to_dt(rec.get("t_det_iso"))
            if t0 and (start is None or t0 < start):
                start = t0
            last = tc or t0
            if last and (end is None or last > end):
                end = last
            if rec.get("seed") is not None:
                seeds.add(rec["seed"])
            order.append(
                {
                    "episode": rec.get("episode"),
                    "index": rec.get("index"),
                    "scenario": rec.get("scenario"),
                    "arm": rec.get("arm"),
                    "src_ip": rec.get("src_ip"),
                    "t0_iso": rec.get("t0_iso"),
                }
            )
    order.sort(key=lambda r: (r["t0_iso"] or "", str(r["episode"])))
    return start, end, order, sorted(seeds)


def container_versions(root):
    """Versiones de imagenes y engine, si docker responde. Si no, se declara."""
    info = {}
    engine = run(["docker", "version", "--format", "{{.Server.Version}}"])
    info["docker_engine"] = engine or "NO VERIFICABLE CON EL MATERIAL DISPONIBLE"
    images = {}
    for name in ("docker.n8n.io/n8nio/n8n:latest", "postgres:15-alpine"):
        out = run(["docker", "image", "inspect", name, "--format",
                   "{{index .RepoDigests 0}}|{{.Id}}"])
        images[name] = out if out else "no disponible en el host que genera el manifiesto"
    images["nota"] = ("Las etiquetas son las que usaba el laboratorio al medir. La imagen de n8n se "
                      "obtuvo con la etiqueta latest: el digest registrado permite fijarla (accion 8 de "
                      "Decisiones_y_acciones_para_los_autores.md).")
    info["images"] = images
    # Versiones dentro de los contenedores del laboratorio (si estan corriendo).
    probes = {
        "n8n": ["docker", "exec", "lab-n8n", "n8n", "--version"],
        "postgres": ["docker", "exec", "lab-postgres", "psql", "--version"],
        "victim_alpine": ["docker", "exec", "lab-victim", "cat", "/etc/os-release"],
        "victim_openssh": ["docker", "exec", "lab-victim", "ssh", "-V"],
        "victim_apache": ["docker", "exec", "lab-victim", "httpd", "-v"],
        "victim_fail2ban": ["docker", "exec", "lab-victim", "fail2ban-client", "--version"],
        "victim_iptables": ["docker", "exec", "lab-victim", "iptables", "--version"],
        "attacker_python": ["docker", "exec", "lab-attacker", "python3", "--version"],
    }
    live = {}
    for key, cmd in probes.items():
        out = run(cmd)
        first = out.splitlines()[0].strip() if out else ""
        live[key] = first if first else "no disponible (contenedor detenido)"
    info["containers"] = live
    return info


def main():
    ap = argparse.ArgumentParser(description="Manifiesto de trazabilidad de una campana")
    ap.add_argument("--campaign", default="e1_e3", help="nombre de la campana (define el archivo de salida)")
    ap.add_argument("--seed", type=int, default=None, help="semilla declarada; si se omite, se toma de los registros")
    ap.add_argument("--root", default=None, help="raiz del repositorio (por defecto se autodetecta)")
    ap.add_argument("--out", default=None, help="ruta de salida (por defecto lab/results/manifest_<campaign>.json)")
    ap.add_argument("--files", nargs="*", default=None, help="archivos .jsonl de la campana")
    args = ap.parse_args()

    root = find_root(args.root or os.path.dirname(os.path.abspath(__file__)))
    files = args.files or RESULT_FILES

    manifest = {
        "campaign": args.campaign,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "make_manifest.py (posterior a la campana; no participa de la medicion)",
        "root": ".",
        "git": git_info(root),
    }

    # Hashes de los archivos del sistema medido.
    hashes = {}
    for rel in TRACKED:
        path = os.path.join(root, rel)
        hashes[rel] = sha256(path) if os.path.isfile(path) else "archivo ausente"
    manifest["system_files_sha256"] = hashes

    # Hashes de los resultados.
    results = {}
    for rel in files:
        path = os.path.join(root, rel)
        if os.path.isfile(path):
            results[rel] = {"sha256": sha256(path), "bytes": os.path.getsize(path)}
        else:
            results[rel] = {"sha256": "archivo ausente", "bytes": None}
    manifest["results_sha256"] = results

    # Ventana, semilla y orden.
    start, end, order, seeds = campaign_window(root, files)
    manifest["window_utc"] = {
        "start": start.strftime("%Y-%m-%dT%H:%M:%SZ") if start else "no determinable",
        "end": end.strftime("%Y-%m-%dT%H:%M:%SZ") if end else "no determinable",
        "duration_s": round((end - start).total_seconds(), 3) if (start and end) else None,
    }
    manifest["seed"] = {
        "declared": args.seed,
        "found_in_records": seeds,
        "nota": "El generador usa la semilla solo para el jitter del espaciado; el orden de corridas no se aleatorizo.",
    }
    manifest["run_order"] = order
    manifest["n_episodes"] = len(order)
    manifest["environment"] = container_versions(root)

    out = args.out or os.path.join(root, "lab", "results", "manifest_%s.json" % args.campaign)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print("manifiesto: %s" % out)
    print("episodios: %d | ventana: %s -> %s" % (
        len(order), manifest["window_utc"]["start"], manifest["window_utc"]["end"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
