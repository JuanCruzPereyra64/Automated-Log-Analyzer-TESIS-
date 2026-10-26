# Artefacto del experimento (campañas E1–E3)

Este directorio contiene la implementación que se **midió** y los registros crudos de la campaña del 16/10/2026. No es la implementación de referencia por etapas que está en `Logic/` (raíz del repositorio): es la versión serializada que corrió en el laboratorio y con la que se calcularon las Tablas 9 y 10 del informe.

## Composición del flujo medido

`pipeline-wf.json` (generado por `build_workflow.py`) tiene **cuatro nodos**:

| Nodo | Tipo | Función |
|---|---|---|
| `ScheduleTrigger` | scheduleTrigger | Dispara el flujo cada **60 s** (período T) |
| `ManualTrigger` | manualTrigger | Disparo manual para pruebas |
| `Webhook` | webhook | Disparo por evento |
| `Pipeline` | code | Ejecuta las etapas lógicas en una sola unidad serializada |

Las etapas lógicas están implementadas dentro de `pipeline.js`:

| Etapa | Dónde | Requisito |
|---|---|---|
| Lectura incremental de logs | `readNew()` (offset por archivo e inodo) | R2 |
| Parseo por fuente | `parseAuth`, `parseSec`, `parseApache` | — |
| Validación de IP de origen | `IPV4.test()` antes de persistir o bloquear | R4 (IPv4) |
| Correlación por ventana deslizante | CTE `recent` / `anch` sobre `parsed_events` | R1 |
| Exclusión de IPs críticas | conjunto `EXCLUDE` | R5 (parcial) |
| Registro de alertas y patrones | `INSERT` en `alerts` y `attack_patterns` | — |
| Respuesta activa | `GET http://lab-victim:9000/block?ip=...&ttl=600` | R6 |
| Bitácora de corrida | `INSERT` en `pipeline_runs` | R8 (parcial) |

El bloqueo lo aplica `victim/block_agent.py` sobre la cadena `LABBLOCK` de iptables, con `subprocess.run([...])` (sin shell) y TTL configurable.

## Estructura

```
lab/
├── pipeline.js            # pipeline medido (nodo Code)
├── pipeline-wf.json       # flujo exportado de n8n (4 nodos)
├── build_workflow.py      # regenera pipeline-wf.json
├── controller.py          # orquesta un episodio y la campaña completa
├── run_campaigns.ps1      # corridas E2 y E3 con la semilla registrada
├── analyze.py             # descriptivos + Mann-Whitney (E1)
├── benign_check.py        # inyección de tráfico benigno y conteo de FP/VN
├── enrichment.js          # lógica R7 (cuota/caché) y R9 (bifurcación por puntaje)
├── verify_r7_r9.js        # 11 comprobaciones con respuestas simuladas
├── attacker/attack.py     # generador de episodios (e1/e2/e3) con marcas propias
├── victim/                # sshd, apache, block_agent, jail.local de Fail2ban
├── scripts/               # seed_rules.sql, reset_db.sql, arranque de Fail2ban
└── results/               # registros crudos y salidas de la campaña
```

## Reproducción

```bash
docker compose -f lab/docker-compose.yml up -d
docker exec -i lab-postgres psql -U admin -d security_monitoring < lab/scripts/seed_rules.sql
python lab/build_workflow.py          # regenera pipeline-wf.json
# importar lab/pipeline-wf.json en n8n (o crearlo con la API)
python lab/controller.py --arm n8n --scenario e1 --n 10 --spacing 300 --spacing-jitter 60 --seed 12345
python analysis/t2_metrics.py         # U, p exacta, Hodges-Lehmann, A12 y métricas de reporte
```

`controller.py` reinicia el estado entre episodios (iptables, `alerts`, `attack_patterns`, offset de lectura) y espera el espaciado indicado. Para el brazo de control: `--arm f2b --scenario e1` con Fail2ban activo (`scripts/start_f2b.sh`).

## De dónde salen las tablas del informe

| Tabla / cifra | Script |
|---|---|
| Tabla 9 (media, mediana, cuartiles, mín, máx) | `lab/analyze.py`, `analysis/t2_metrics.py` |
| Tabla 10 (VP, FN, FP, VN, precisión, FPR) | `lab/benign_check.py`, `analysis/t2_metrics.py` |
| U, p exacta, Hodges–Lehmann, A12 con IC 95 % | `analysis/t2_metrics.py` |
| Análisis de potencia (A12 ≥ 0,9 → potencia ≥ 0,85) | `analysis/power_analysis.py` |
| Verificación R7/R9 (11 comprobaciones) | `lab/verify_r7_r9.js` → `lab/results/r7_r9_verification.json` |

## Registros

- `results/n8n_e1.jsonl`, `results/n8n_e2.jsonl`, `results/n8n_e3.jsonl`, `results/f2b_e1.jsonl`: un registro por episodio con `t0`, `t_k`, `t_det`, `t_cont`, `MTTD`, `MTTR`, `detected`, `contained`. Corresponden a la campaña del 16/10/2026.
- `results/n8n_e1_v2.jsonl`, `results/f2b_e1_v2.jsonl`: repetición de E1 del 26/10/2026 sobre el flujo publicado; son la fuente de los valores de E1 del informe. El número de episodio vuelve a empezar en cada bloque de cinco.
- `results/manifest_e1_e3.json`, `results/manifest_e1_v2.json`: commit, hashes SHA-256, semilla, orden y ventana de cada campaña.
- `results/workflow_export_e1_v2.json`: exportación del flujo que ejecutó la repetición; su nodo Code coincide byte por byte con `pipeline.js` del commit medido.
- `results/report_e2_e3.md`, `results/benign_e2_e3_summary.json`: resumen de E2/E3 y del tráfico benigno.
- `results/*_campaign.out`, `results/n8n_campaigns.log`: salida cruda de las corridas.
- `results/smoke_*.jsonl`: corridas de humo previas a la campaña; **no** forman parte de las Tablas 9 y 10.

## Cómo verificar los manifiestos

Los manifiestos registran el SHA-256 de cada archivo tal como estaba en el disco de la máquina de medición: Windows con `core.autocrlf=true`. En ese equipo los archivos se ven con CRLF; el repositorio guarda el mismo contenido con LF.

Por eso un hash calculado sobre un clon limpio no coincide con el del manifiesto, aunque el contenido sea el mismo. Para comprobarlo hay que ejecutar `python lab/verify_manifest.py`. El script toma el contenido del commit con `git show HEAD:<ruta>` y prueba las dos convenciones; informa `OK (LF)`, `OK (CRLF)` o `DISCORDANCIA` por entrada.

La publicación no alteró el contenido medido: Git solo normalizó los fines de línea. Las 18 entradas de los dos manifiestos coinciden con el contenido del commit al aplicarle CRLF.

## Límites conocidos (leer antes de interpretar)

1. **T = 60 s**: el `ScheduleTrigger` dispara cada minuto, y el generador sondea la contención cada 1 s. El MTTD del brazo n8n está dominado por ese piso de sondeo (sección 7.1 del informe).
2. **E3 se bloquea**: el pipeline aplica la misma respuesta activa a toda alerta, incluida la de inyección SQL. El diseño de referencia preveía no bloquear en E3.
3. **Sin enriquecimiento en la campaña**: `pipeline.js` no consulta AbuseIPDB; la lógica R7/R9 se verificó aparte con respuestas simuladas (`enrichment.js`, `verify_r7_r9.js`), sin clave de API.
4. **R4** valida IPv4 canónico; no admite IPv6.
5. **R5** tiene lista de exclusión fija y no tiene límite de bloqueos por unidad de tiempo.
6. **R8** registra cada corrida en `pipeline_runs`, pero no emite alerta de latido ni serializa ejecuciones con un candado explícito.
7. **Credenciales del laboratorio**: `admin/admin` es una credencial local del compose, no endurecida; no debe reutilizarse fuera del laboratorio.
8. **No se publican** `n8n-data/` ni `postgres-data/` (configuración y base de n8n con material sensible).

## Nota sobre rutas

Los scripts se publican con rutas relativas al repositorio. Los archivos `.out` de `results/` conservan la línea de comando original, que incluye la ruta absoluta de la máquina donde se ejecutó la campaña.
