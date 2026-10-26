# `Logic/` — código base, no el artefacto medido

Esta carpeta contiene el primer esbozo de los nodos del pipeline (`01_nodo_ingesta.js` a
`05_nodo_active_response.js`). Se conserva como referencia del diseño inicial. **No es el
código que produjo los resultados**: el artefacto medido es `lab/pipeline.js`, importado en
n8n desde `lab/pipeline-wf.json`.

## Qué contiene

| Archivo | Rol previsto |
|---|---|
| `01_nodo_ingesta.js` | Lee tres rutas fijas con `fs` y `readline` y filtra las últimas 5 min |
| `02_nodo_parser.js` | Clasifica fuerza bruta SSH, uso de `sudo` e inyección SQL con expresiones regulares |
| `03_nodo_rules_engine.js` | Consulta `detection_rules` en PostgreSQL con el cliente `pg` y agrupa por tipo e IP |
| `04_nodo_threat_intel.js` | Consulta a AbuseIPDB y calcula el puntaje de amenaza |
| `05_nodo_active_response.js` | Decide el bloqueo y ejecuta `iptables` con `child_process` |

## Defectos conocidos del código base

Estos defectos motivaron su reemplazo. Se listan para que nadie lo tome como implementación de
referencia.

1. **Contrato de datos roto entre el parser y el motor de reglas.** `02_nodo_parser.js` emite
   `raw_log`, mientras que `03_nodo_rules_engine.js` evalúa `log.raw`. La expresión regular de
   la regla se aplica sobre `undefined`, de modo que ninguna regla dispara.
2. **Ejecución de comandos con interpolación de la IP.** `05_nodo_active_response.js` arma
   `sudo iptables -A INPUT -s ${alert.source_ip} -j DROP` y lo pasa a `exec`, que invoca un
   shell. Una IP no validada permite inyectar comandos, y el nodo necesita `sudo` dentro del
   contenedor de n8n.
3. **Ejecución simulada.** El propio archivo advierte que «simulamos la ejecución exitosa»
   aunque espera el resultado de `execAsync`: el mensaje de éxito no prueba que la regla exista.
4. **Credenciales de ejemplo** (`tu_usuario`, `tu_password`) y host `postgres` fijo.
5. **Ventana de tiempo eludible.** El motor acepta un evento único sin evaluar la ventana
   (`matchingLogs.length === 1`), y las reglas se agrupan por tipo e IP en lugar de por regla.
6. **Rutas fijas de Syslog-ng** (`/var/log/security/alerts.log`, `/var/log/centralized/all.log`)
   que no existen en el laboratorio del capítulo 4 ni en el artefacto medido.
7. **Dependencias externas en el nodo Code** (`pg`, `child_process`): requieren habilitar
   módulos en n8n, la misma concesión que el informe declara para `fs` (§4.2, Tabla 11).

## Cómo se relaciona con el informe

La sección 4.2 describe el artefacto medido y sus decisiones de diseño. Si se cita `Logic/` en
el informe, debe hacerse como antecedente de diseño, nunca como evidencia de funcionamiento.
