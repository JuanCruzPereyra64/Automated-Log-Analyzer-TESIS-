# Reporte de campanas E2 (Port Scan) y E3 (SQL Injection) — Brazo n8n

Fecha de ejecucion: 2026-10-16
Brazo (arm): `n8n` (pipeline SIEM/SOAR en n8n 2.43.6, workflow `SIEM_SOAR_Pipeline`, id `AZj9XoI9f4EiKcY1`)
Episodios por escenario: 10
Artefactos crudos: `results/n8n_e2.jsonl`, `results/n8n_e3.jsonl`

---

## 1. Objetivo

Medir, para dos escenarios de ataque, la capacidad de deteccion y contencion del
pipeline implementado en n8n sobre el laboratorio Docker, registrando por episodio:

- `t_k`: instante de lanzamiento del ataque (reloj UTC).
- `t_det`: instante de la alerta generada por la regla de deteccion.
- `t_cont`: instante en que la respuesta activa (bloqueo) queda efectiva.
- MTTD = `t_det - t_k`; MTTR = `t_cont - t_det`.
- `detected`, `contained`.

Ademas: verificacion de falsos positivos (FP) y verdaderos negativos (VN) con
trafico benigno.

## 2. Escenarios y reglas

| Escenario | Ataque | Regla (id) | Patron | Umbral/ventana | Severidad |
|-----------|--------|------------|--------|----------------|-----------|
| E2 | Port Scan (SYN a 22 puertos 30000-30021) | Port Scan Detection (id3) | `iptables.*DROP.*DPT` | 20 eventos / 60 s | medium |
| E3 | SQL Injection (1 peticion `GET /?id=1' UNION SELECT ...`) | SQL Injection Pattern (id5) | `(union.*select\|drop.*table)` | 1 evento / 1 s | high |

Respuesta activa: bloqueo via `GET http://lab-victim:9000/block?ip=<src>&ttl=600`.

## 3. Metodologia

- Pipeline de sondeo periodico (Cron cada 60 s): lee los logs compartidos
  (`/var/log/auth.log`, `/var/log/security/alerts.log`,
  `/var/log/apache_access/all.log`), parsea, evalua reglas, correlaciona en
  ventana deslizante y, ante un `hit`, crea alerta y ejecuta la accion de
  contencion (idempotente).
- Por episodio se ejecuta `reset_db` (`TRUNCATE alerts, attack_patterns,
  parsed_events`) y `reset_victim`, de modo que cada episodio se evalua de forma
  aislada. La IP origen es unica por episodio (`10.50.0.2xx`).
- Campana: `python controller.py --arm n8n --scenario <e2|e3> --n 10
  --spacing 300 --spacing-jitter 60 --seed 12345`.
- Intervalo entre episodios ~300 s > intervalo de sondeo (60 s) para permitir
  deteccion y contencion completas.
- Trafico benigno (Tabla VN): E2 = scan de 15 puertos (30000-30014) desde
  `10.50.1.10-.19`; E3 = `GET /` simple desde `10.50.2.10-.19`. Se espera FP=0 y
  VN=10 en cada escenario (no deben cruzar los umbrales).

## 4. Resultados por episodio

### 4.1 E2 — Port Scan

| Ep | src | t_k (UTC) | t_det (UTC) | t_cont (UTC) | MTTD (s) | MTTR (s) | det | cont |
|----|-----|-----------|-------------|--------------|----------|----------|-----|------|
| 1 | 10.50.0.200 | 20:04:23.751 | 20:04:36.903 | 20:04:37.654 | 13.15 | 0.75 | si | si |
| 2 | 10.50.0.201 | 20:10:00.822 | 20:10:37.070 | 20:10:38.560 | 36.25 | 1.49 | si | si |
| 3 | 10.50.0.202 | 20:14:54.986 | 20:15:37.113 | 20:15:37.780 | 42.13 | 0.67 | si | si |
| 4 | 10.50.0.203 | 20:20:46.688 | 20:21:36.924 | 20:21:37.690 | 50.24 | 0.77 | si | si |
| 5 | 10.50.0.204 | 20:25:54.833 | 20:26:36.678 | 20:26:37.571 | 41.85 | 0.89 | si | si |
| 6 | 10.50.0.205 | 20:31:18.682 | 20:31:36.632 | 20:31:37.635 | 17.95 | 1.00 | si | si |
| 7 | 10.50.0.206 | 20:36:31.485 | 20:36:36.943 | 20:36:38.195 | 5.46 | 1.25 | si | si |
| 8 | 10.50.0.207 | 20:42:05.098 | 20:42:37.997 | 20:42:38.845 | 32.90 | 0.85 | si | si |
| 9 | 10.50.0.208 | 20:47:16.113 | 20:47:36.605 | 20:47:37.831 | 20.49 | 1.23 | si | si |
| 10 | 10.50.0.209 | 20:52:23.771 | 20:52:36.608 | 20:52:37.484 | 12.84 | 0.88 | si | si |

Deteccion: **10/10**. Contencion: **10/10**.

### 4.2 E3 — SQL Injection

| Ep | src | t_k (UTC) | t_det (UTC) | t_cont (UTC) | MTTD (s) | MTTR (s) | det | cont |
|----|-----|-----------|-------------|--------------|----------|----------|-----|------|
| 1 | 10.50.0.200 | 20:52:47.607 | 20:53:36.440 | 20:53:37.382 | 48.83 | 0.94 | si | si |
| 2 | 10.50.0.201 | 20:58:14.752 | 20:58:36.533 | 20:58:37.314 | 21.78 | 0.78 | si | si |
| 3 | 10.50.0.202 | 21:03:15.360 | 21:03:36.648 | 21:03:37.928 | 21.29 | 1.28 | si | si |
| 4 | 10.50.0.203 | 21:09:07.701 | 21:09:36.625 | 21:09:37.326 | 28.92 | 0.70 | si | si |
| 5 | 10.50.0.204 | 21:14:23.958 | 21:14:36.371 | 21:14:37.495 | 12.41 | 1.12 | si | si |
| 6 | 10.50.0.205 | 21:19:45.780 | 21:20:37.034 | 21:20:38.399 | 51.25 | 1.36 | si | si |
| 7 | 10.50.0.206 | 21:24:59.845 | 21:25:36.456 | 21:25:37.473 | 36.61 | 1.02 | si | si |
| 8 | 10.50.0.207 | 21:30:31.793 | 21:30:36.431 | 21:30:37.329 | 4.64 | 0.90 | si | si |
| 9 | 10.50.0.208 | 21:35:44.613 | 21:36:38.600 | 21:36:40.202 | 53.99 | 1.60 | si | si |
| 10 | 10.50.0.209 | 21:41:37.767 | 21:41:39.057 | 21:41:40.329 | 1.29 | 1.27 | si | si |

Deteccion: **10/10**. Contencion: **10/10**.

## 5. Estadisticas MTTD / MTTR (segundos)

| Metrica | E2 mean | E2 mediana | E2 Q1 | E2 Q3 | E2 min | E2 max | E3 mean | E3 mediana | E3 Q1 | E3 Q3 | E3 min | E3 max |
|---------|---------|------------|-------|-------|--------|--------|---------|------------|-------|-------|--------|--------|
| MTTD | 27.32 | 26.70 | 14.35 | 40.45 | 5.46 | 50.24 | 28.10 | 25.35 | 14.63 | 45.78 | 1.29 | 53.99 |
| MTTR | 0.98 | 0.88 | 0.79 | 1.17 | 0.67 | 1.49 | 1.10 | 1.07 | 0.91 | 1.28 | 0.70 | 1.60 |

Observaciones:

- El MTTD esta acotado por el intervalo de sondeo del pipeline (60 s): la
  deteccion ocurre en el siguiente tick de Cron tras la ingesta del evento, por
  lo que la latencia se distribuye aproximadamente uniforme en [0, 60] s mas el
  tiempo de parseo/correlacion. Esto explica los valores E2/E3 (min ~1 s si el
  evento coincide con un tick, max ~54 s si llega justo tras uno).
- El MTTR es sub-segundo a ~1.6 s (llamada HTTP de bloqueo + confirmacion),
  consistente y estable en ambos escenarios.

## 6. Trafico benigno — Falsos positivos / Verdaderos negativos

| Escenario | Trafico | FP | VN | Alertas totales |
|-----------|---------|----|----|-----------------|
| E2 | Scan de 15 puertos (< umbral 20) desde 10.50.1.10-.19 | 0 | 10 | 0 |
| E3 | `GET /` simple desde 10.50.2.10-.19 | 0 | 10 | 0 |

Datos: `results/benign_e2_e3_summary.json`. Ningun umbral cruzado -> sin
alertas -> FP=0 y VN=10 en ambos escenarios.

## 7. Desviaciones y limitaciones

1. **Sensor de port scan en espacio de usuario (AF_PACKET).** En el netns de
   contenedor, la regla `iptables -j LOG` incrementa contadores pero no emite
   lineas de log del kernel (kernel WSL2 6.18.54.1-microsoft-standard-WSL2;
   compuerta `nf_log_all_netns` no configurable; `kernel.printk_ratelimit`
   solo-lectura; lectores netlink NFLOG/NFQUEUE recibieron 0). Se sustituyo por
   un sensor de espacio de usuario (`scan_logger.py`) que captura con AF_PACKET
   los paquetes descartados y escribe lineas en formato kernel
   `iptables DROP: ... SRC=... DPT=...`, de modo que la regla id3 evalua el
   mismo patron y semantica que tendria el log nativo. El LOG+DROP de iptables
   se mantiene; solo cambia la fuente de la linea de log.

2. **Despliegue del workflow n8n 2.x por edicion directa de SQLite.**
   `n8n import:workflow` / `publish:workflow` por `docker exec` fallan con
   `SQLITE_CANTOPEN` mientras el servidor mantiene la DB abierta (bind-mount
   Windows). Modelo 2.x en modo regular: `workflow_entity.activeVersionId`
   (y `versionId`) determina la version en ejecucion; `import --activeState`
   no soporta activacion en modo regular; `workflow_published_version` solo
   aplica a modo cola. Despliegue fiable aplicado: detener el servidor -> editar
   SQLite desde el host (respaldo previo, `UPDATE workflow_entity` +
   `INSERT workflow_history`) -> reiniciar. Version final desplegada:
   `ae5cc17d-4598-4429-9cd6-ae97e80926fe`.

3. **Ventana de correlacion anclada al evento + horizonte de ingesta.** Con
   sondeo por lotes, una regla de ventana corta (E3 = 1 s) no disparaba si el
   evento llegaba "viejo" respecto de `now()`. Se anclo la ventana al evento mas
   reciente de cada `(regla, IP)` y se agrego un horizonte de ingesta GRACE
   (180 s) para que el evento expire y no re-alerte indefinidamente. Esta
   correccion **no altera** los tiempos de deteccion medidos (el primer tick
   posterior a la ingesta produce el mismo `hit`), solo evita alertas
   duplicadas tardias observadas en la version previa.

4. **Caveat E1.** La campana E1 (SSH Brute Force, `results/n8n_e1.jsonl`, 10
   episodios) se genero con la version previa del pipeline (antes de la
   reescritura multi-fuente y de las correcciones de ventana/patron). El smoke
   test de regresion E1 pasa, pero para consistencia estricta del capitulo
   convendria re-ejecutar E1 con la version final.

## 8. Artefactos

- `results/n8n_e1.jsonl`, `results/n8n_e2.jsonl`, `results/n8n_e3.jsonl` — 10
  registros por escenario.
- `results/benign_e2_e3_summary.json` — resumen FP/VN benigno.
- `results/n8n_campaigns.log` — traza del driver de campanas.
- `pipeline.js`, `build_workflow.py`, `pipeline-wf.json` — pipeline y despliegue.
- `controller.py`, `analyze.py`, `benign_check.py`, `attacker/attack.py` — orquestacion y metricas.
