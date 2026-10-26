# Pruebas de requisitos R1–R8 (escritas, **no ejecutadas**)

Estas pruebas son **posteriores a la campaña**: no formaron parte de la medición y no modifican los resultados de E1–E3. Se escribieron para cubrir N-18 («pruebas de R1–R6 y R8 sin reportar»).

**Estado: no ejecutadas.** Este entorno no tiene el laboratorio levantado con el artefacto en la versión medida. No se reporta ningún resultado: lo que sigue son procedimientos y criterios de aceptación.

## Requisitos previos

```bash
cd <raiz-del-repositorio>
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps
```

Contenedores esperados: `lab-victim`, `lab-attacker`, `lab-n8n`, `lab-postgres`.
Base de datos: `psql -U admin -d security_monitoring` (credenciales del compose, rotarlas antes de publicar).
Flujo: `lab/pipeline-wf.json` importado y activo, con sondeo cada 60 s.

## Cómo se corre cada prueba

```bash
bash lab/tests/r1_ventana.sh
bash lab/tests/r2_offset.sh
bash lab/tests/r3_ingesta.sh
bash lab/tests/r4_inyeccion_ip.sh
bash lab/tests/r5_exclusion.sh
bash lab/tests/r6_ttl.sh
bash lab/tests/r7_r9_enriquecimiento.sh
bash lab/tests/r8_latido.sh
```

Cada script imprime `RESULTADO: PASA`, `RESULTADO: FALLA` o `RESULTADO: NO CONCLUYENTE`, y deja la salida cruda en `lab/results/tests/`.

## Matriz de pruebas

| Requisito | Qué se prueba | Resultado esperado según el código medido | Estado |
|---|---|---|---|
| R1 | Ventana deslizante con T < ventana; 5 eventos SSH dentro de 300 s | Dispara. Con los eventos repartidos más de 180 s, la gracia puede impedir la segunda alerta: defecto declarado | Escrita |
| R2 | Offset por archivo e inodo | Dos ciclos sin eventos nuevos no crean alertas | Escrita |
| R3 | Lectura con nodo de archivos o webhook | **No cumple**: requiere `NODE_FUNCTION_ALLOW_BUILTIN` y usa `fs` dentro del nodo Code | Escrita |
| R4 | Validación de IP antes de cualquier comando | El pipeline valida IPv4 canónicas; el agente no valida y no usa shell | Escrita |
| R5 | Lista de exclusión y límite de bloqueos | Excluye 10.50.0.1 y 127.0.0.1; **no hay** límite por tiempo | Escrita |
| R6 | TTL, tope de reglas y desbloqueo | TTL de 600 s en memoria; sin tope; el reinicio borra el estado | Escrita |
| R7 / R9 | Cuota de AbuseIPDB y puntaje como condición | Ya verificado con respuestas simuladas en `lab/verify_r7_r9.js` | Ejecutada en la campaña |
| R8 | Flujo de error y latido | **No cumple**: `pipeline_runs` registra contadores, sin latido ni captura de error | Escrita |

## Advertencias

- Las pruebas escriben en la base y crean reglas de iptables. **No ejecutarlas durante una campaña** ni sobre un entorno con datos que importen.
- `r1_ventana.sh`, `r5_exclusion.sh` y `r6_ttl.sh` dejan reglas de bloqueo si se interrumpen: la limpieza está al final de cada script.
- Los tiempos de espera suman unos 25 minutos en total; `r6_ttl.sh` espera más de 600 s.
- Estas pruebas no se reportan en el informe como evidencia. Si se ejecutan, la salida debe guardarse y citarse en la Tabla 11 con la fecha.
