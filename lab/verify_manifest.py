#!/usr/bin/env python3
"""Verifica los manifiestos de campaña contra el contenido del repositorio.

Los manifiestos se generaron en Windows, con `core.autocrlf=true`, de modo que
registran el SHA-256 de cada archivo con fines de línea CRLF. El repositorio
guarda el mismo contenido con LF. Este script toma el contenido del commit
(`git show HEAD:<ruta>`) y compara en ambas convenciones.

Uso:
    python lab/verify_manifest.py

Salida: una línea por entrada con `OK (LF)`, `OK (CRLF)` o `DISCORDANCIA`.
El código de salida es 0 si todas las entradas coinciden en alguna convención.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GROUP_LABEL = {
    "results_sha256": "registros y salidas",
    "system_files_sha256": "archivos del sistema medido",
}


def git_blob(rel):
    """Contenido del archivo en HEAD, o None si no está versionado."""
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "show", "HEAD:" + rel],
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def to_crlf(data):
    """Convierte a CRLF el contenido de un blob, que viene con LF."""
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def main():
    manifests = sorted((ROOT / "lab" / "results").glob("manifest_*.json"))
    if not manifests:
        print("No se encontraron manifiestos en lab/results/.")
        return 1

    total = 0
    discordancias = 0

    for path in manifests:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        commit = (manifest.get("git") or {}).get("commit", "")[:10]
        print()
        print(f"{path.name}  commit {commit}  episodios {manifest.get('n_episodes')}")
        for group, label in GROUP_LABEL.items():
            entries = manifest.get(group) or {}
            if not entries:
                continue
            print(f"  {label}:")
            for rel, record in entries.items():
                esperado = record["sha256"] if isinstance(record, dict) else record
                total += 1
                blob = git_blob(rel)
                if blob is None:
                    print(f"    SIN ARCHIVO   {rel}")
                    discordancias += 1
                    continue
                if sha256(blob) == esperado:
                    estado = "OK (LF)"
                elif sha256(to_crlf(blob)) == esperado:
                    estado = "OK (CRLF)"
                else:
                    estado = "DISCORDANCIA"
                    discordancias += 1
                print(f"    {estado:13} {rel}")

    print()
    print(f"{total} entradas verificadas, {discordancias} discordancia(s).")
    if discordancias == 0:
        print("Cada hash corresponde al contenido del commit en alguna de las dos convenciones.")
    return 0 if discordancias == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
