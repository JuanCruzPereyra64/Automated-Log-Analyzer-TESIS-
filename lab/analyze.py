import json
import sys
from itertools import combinations
from math import comb, floor

sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path

RES = Path(__file__).resolve().parent / "results"


def load(arm, scenario="e1"):
    out = []
    for line in (RES / f"{arm}_{scenario}.jsonl").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    out.sort(key=lambda r: r["episode"])
    return out


def load_path(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    out.sort(key=lambda r: r["episode"])
    return out


def report_single(recs, label):
    mttd = [r["MTTD"] for r in recs if r.get("detected") and r.get("MTTD") is not None]
    mttr = [r["MTTR"] for r in recs if r.get("contained") and r.get("MTTR") is not None]
    notdet = sum(1 for r in recs if not r.get("detected"))
    notcont = sum(1 for r in recs if not r.get("contained"))
    print(f"### {label}: total={len(recs)} detectados={len(mttd)} no_det={notdet} "
          f"contenidos={len(mttr)} no_cont={notcont}")
    for name, vals in (("MTTD", mttd), ("MTTR", mttr)):
        if vals:
            d = describe(vals)
            print(f"  {name}: n={d['n']} media={d['mean']:.2f} mediana={d['median']:.2f} "
                  f"Q1={d['q1']:.2f} Q3={d['q3']:.2f} min={d['min']:.2f} max={d['max']:.2f}")
        else:
            print(f"  {name}: sin datos")
    print()
    print("  ep | src_ip | t_k | t_det | t_cont | MTTD | MTTR | det | cont")
    for r in recs:
        print(f"  {r['episode']:>2} | {r['src_ip']} | {r.get('t_k_iso')} | {r.get('t_det_iso')} | "
              f"{r.get('t_cont_iso')} | {r['MTTD'] and round(r['MTTD'],2)} | {r['MTTR'] and round(r['MTTR'],2)} | "
              f"{r.get('detected')} | {r.get('contained')}")


def pct(sorted_x, p):
    n = len(sorted_x)
    if n == 1:
        return float(sorted_x[0])
    rank = (p / 100.0) * (n - 1)
    lo = int(floor(rank))
    frac = rank - lo
    if lo + 1 < n:
        return sorted_x[lo] + frac * (sorted_x[lo + 1] - sorted_x[lo])
    return float(sorted_x[lo])


def describe(vals):
    s = sorted(vals)
    n = len(s)
    return {
        "n": n,
        "mean": sum(s) / n,
        "median": pct(s, 50),
        "q1": pct(s, 25),
        "q3": pct(s, 75),
        "min": s[0],
        "max": s[-1],
    }


def avg_ranks(a, b):
    """Rangos promedio (1-based) para el test de Mann-Whitney con empates."""
    N = len(a) + len(b)
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
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
    return ranks, combined


def u_stat(ranks, combined, n1):
    Ra = sum(ranks[k] for k in range(len(combined)) if combined[k][1] == 0)
    return Ra - n1 * (n1 + 1) / 2.0


def mannwhitney_perm(a, b):
    """p bilateral por test de permutacion exacto (con empates)."""
    n1, n2 = len(a), len(b)
    N = n1 + n2
    ranks, combined = avg_ranks(a, b)
    U_obs = u_stat(ranks, combined, n1)
    mean_U = n1 * n2 / 2.0
    dev = abs(U_obs - mean_U)
    total = comb(N, n1)
    cnt = 0
    idx = range(N)
    for combo in combinations(idx, n1):
        Ra = sum(ranks[k] for k in combo)
        u = Ra - n1 * (n1 + 1) / 2.0
        if abs(u - mean_U) >= dev - 1e-9:
            cnt += 1
    return U_obs, mean_U, cnt / total, total


# --- Modo simple: si se pasa una ruta de archivo, analizar solo ese archivo ---
if len(sys.argv) > 1:
    _recs = load_path(sys.argv[1])
    report_single(_recs, sys.argv[1])
    sys.exit(0)


arms = {}
for arm in ("n8n", "f2b"):
    recs = load(arm)
    mttd = [r["MTTD"] for r in recs if r.get("detected") and r.get("MTTD") is not None]
    mttr = [r["MTTR"] for r in recs if r.get("contained") and r.get("MTTR") is not None]
    notdet = sum(1 for r in recs if not r.get("detected"))
    notcont = sum(1 for r in recs if not r.get("contained"))
    arms[arm] = {"recs": recs, "mttd": mttd, "mttr": mttr,
                 "notdet": notdet, "notcont": notcont, "total": len(recs)}
    print(f"### BRAZO {arm}: total={len(recs)} detectados={len(mttd)} no_det={notdet} "
          f"contenidos={len(mttr)} no_cont={notcont}")
    for name, vals in (("MTTD", mttd), ("MTTR", mttr)):
        d = describe(vals)
        print(f"  {name}: n={d['n']} media={d['mean']:.2f} mediana={d['median']:.2f} "
              f"Q1={d['q1']:.2f} Q3={d['q3']:.2f} min={d['min']:.2f} max={d['max']:.2f}")
    print()

print("=" * 60)
print("PRUEBA U DE MANN-WHITNEY (permutacion exacta bilateral)")
for name, key in (("MTTD", "mttd"), ("MTTR", "mttr")):
    a, b = arms["n8n"][key], arms["f2b"][key]
    U, mU, p, total = mannwhitney_perm(a, b)
    print(f"  {name}: U={U:.1f} (esperado H0={mU:.1f}) p_exacta={p:.4e}  permutaciones={total}")

print()
print("=" * 60)
print("TABLA 9 - VALORES PARA RELLENAR")
for metric, key in (("MTTD", "mttd"), ("MTTR", "mttr")):
    for arm in ("n8n", "f2b"):
        nd = arms[arm]["notdet"] if metric == "MTTD" else arms[arm]["notcont"]
        if arms[arm][key]:
            d = describe(arms[arm][key])
            print(f"  E1-{metric} {arm}: n={d['n']} | media={d['mean']:.2f} | mediana={d['median']:.2f} "
                  f"| Q1-Q3={d['q1']:.2f}-{d['q3']:.2f} | min={d['min']:.2f} | max={d['max']:.2f} | no_det={nd}")
        else:
            print(f"  E1-{metric} {arm}: sin datos | no_det={nd}")

print()
print("=" * 60)
print("TABLA 10 - VP/FN (escenario E1)")
for arm in ("n8n", "f2b"):
    vp = sum(1 for r in arms[arm]["recs"] if r.get("detected"))
    fn = sum(1 for r in arms[arm]["recs"] if not r.get("detected"))
    print(f"  SSH Brute Force {arm}: VP={vp} FN={fn} total={arms[arm]['total']}")
