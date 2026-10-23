"""T-2: métricas adicionales del informe (párr. 232 y nota Tabla 9).

Calcula para cada comparación (E1 n8n vs f2b):
  - U (Mann-Whitney, convención brazo n8n) y p exacta (re-verificación)
  - Diferencia de medianas de Hodges-Lehmann con IC 95% (bootstrap)
  - A12 (Vargha-Delaney = P(X>Y)+0.5*P(X=Y)) con IC 95% (bootstrap)
Y las métricas de reporte con sus denominadores:
  - cobertura de parseo
  - completitud de la bitácora
  - proporción de alertas con enriquecimiento
  - número de bloqueos automáticos
"""
import json
import random
import sys
from itertools import combinations
from math import comb
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
RES = Path(__file__).resolve().parents[1] / "lab" / "results"


def load(name):
    out = []
    for line in (RES / name).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    out.sort(key=lambda r: r["episode"])
    return out


def mttd(r):
    return float(r["t_det"]) - float(r["t_k"])


def mttr(r):
    return float(r["t_cont"]) - float(r["t_det"])


def a12(a, b):
    """Vargha-Delaney A12 = P(X>Y) + 0.5*P(X=Y)."""
    c = t = 0
    for x in a:
        for y in b:
            if x > y:
                c += 1
            elif x == y:
                t += 1
    return (c + 0.5 * t) / (len(a) * len(b))


def hodges_lehmann(a, b):
    diffs = sorted(x - y for x in a for y in b)
    n = len(diffs)
    mid = n // 2
    if n % 2:
        return diffs[mid]
    return (diffs[mid - 1] + diffs[mid]) / 2.0


def a12_bootstrap_ci(a, b, reps=10000, seed=12345):
    rng = random.Random(seed)
    boots = []
    for _ in range(reps):
        ab = [a[rng.randrange(len(a))] for _ in range(len(a))]
        bb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        boots.append(a12(ab, bb))
    boots.sort()
    return boots[int(reps * 0.025)], boots[int(reps * 0.975) - 1]


def hl_bootstrap_ci(a, b, reps=10000, seed=12345):
    rng = random.Random(seed)
    boots = []
    for _ in range(reps):
        ab = [a[rng.randrange(len(a))] for _ in range(len(a))]
        bb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        boots.append(hodges_lehmann(ab, bb))
    boots.sort()
    return boots[int(reps * 0.025)], boots[int(reps * 0.975) - 1]


def mannwhitney_exact(a, b):
    """U (brazo a) y p bilateral por permutación exacta (con empates)."""
    n1, n2 = len(a), len(b)
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    N = len(combined)
    ranks = [0.0] * N
    i = 0
    while i < N:
        j = i
        while j + 1 < N and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    Ra = sum(ranks[k] for k in range(N) if combined[k][1] == 0)
    U1 = Ra - n1 * (n1 + 1) / 2.0  # convención analyze.py: U del brazo a
    mean_U = n1 * n2 / 2.0
    dev = abs(U1 - mean_U)
    total = comb(N, n1)
    cnt = 0
    for combo in combinations(range(N), n1):
        r = sum(ranks[k] for k in combo)
        u = r - n1 * (n1 + 1) / 2.0
        if abs(u - mean_U) >= dev - 1e-9:
            cnt += 1
    return U1, cnt / total


def main():
    e1n = load("n8n_e1.jsonl")
    e1f = load("f2b_e1.jsonl")
    e2 = load("n8n_e2.jsonl")
    e3 = load("n8n_e3.jsonl")

    print("=" * 72)
    print("T-2a) COMPARACIÓN E1 (n8n vs f2b) — U, p, Hodges-Lehmann+IC95%, A12")
    print("=" * 72)
    for name, fn in (("MTTD", mttd), ("MTTR", mttr)):
        a = [fn(r) for r in e1n]
        b = [fn(r) for r in e1f]
        U, p = mannwhitney_exact(a, b)
        hl = hodges_lehmann(a, b)
        hlo, hhi = hl_bootstrap_ci(a, b)
        av = a12(a, b)
        alo, ahi = a12_bootstrap_ci(a, b)
        print(f"\n{name}:")
        print(f"  U = {U:.1f}   p exacta = {p:.4e}")
        print(f"  HL (n8n-f2b) = {hl:.3f} s   IC95% = [{hlo:.3f}; {hhi:.3f}]")
        print(f"  A12 = {av:.3f}   IC95% = [{alo:.3f}; {ahi:.3f}]")

    print("\n" + "=" * 72)
    print("T-2b) MÉTRICAS DE REPORTE CON DENOMINADOR (párr. 232)")
    print("=" * 72)
    mal = e1n + e2 + e3
    total_mal = len(mal)
    det = sum(1 for r in mal if r.get("detected"))
    cont = sum(1 for r in mal if r.get("contained"))
    complete = sum(
        1 for r in mal
        if r.get("t_k") is not None and r.get("t_det") is not None and r.get("t_cont") is not None
    )
    print(f"\nCobertura de parseo         = {det}/{total_mal} = {det/total_mal:.3f}")
    print(f"Completitud de bitácora     = {complete}/{total_mal} = {complete/total_mal:.3f}")
    print(f"Alertas con enriquecimiento = 0/{total_mal} = 0.000  (AbuseIPDB R7 fuera de alcance)")
    print(f"Bloqueos automáticos        = {cont}/{total_mal} = {cont/total_mal:.3f}")


if __name__ == "__main__":
    main()
