// =====================================================================
// NODO 4 (README): Apply Detection Rules
// Función: Evaluar logs contra las reglas dinámicas de la Base de Datos
// =====================================================================

// Importamos la librería de PostgreSQL (Requiere habilitar módulos externos en n8n)
const { Client } = require('pg');

// Configuración de conexión a tu DB (Ajusta 'db_user' y 'db_pass' a tu entorno)
const client = new Client({
    host: 'postgres', // O 'localhost' si corre por fuera de Docker
    database: 'security_monitoring',
    user: 'tu_usuario',
    password: 'tu_password',
    port: 5432
});

await client.connect();

// 1. Obtener las reglas activas desde PostgreSQL
const rulesResult = await client.query('SELECT * FROM detection_rules WHERE enabled = true');
const rules = rulesResult.rows;

// 2. Obtener los logs ya parseados del nodo anterior
const logs = $input.all();
const alerts = [];

// 3. Agrupar logs por Tipo de Ataque e IP de Origen
const logGroups = {};
logs.forEach(item => {
    const log = item.json;
    const key = `${log.type}_${log.source_ip || 'unknown'}`;

    if (!logGroups[key]) {
        logGroups[key] = [];
    }
    logGroups[key].push(log);
});

// 4. El Motor de Evaluación: Cruzar Logs vs Reglas
for (const rule of rules) {
    for (const [key, logGroup] of Object.entries(logGroups)) {

        // Filtramos los logs que coinciden con el patrón Regex de la regla
        const matchingLogs = logGroup.filter(log => {
            const regex = new RegExp(rule.pattern, 'i');
            return regex.test(log.raw);
        });

        // Validamos el Umbral (Threshold)
        if (matchingLogs.length >= rule.threshold) {

            // Validamos la Ventana de Tiempo (Time Window) en milisegundos
            const timestamps = matchingLogs.map(log => new Date(log.timestamp).getTime());
            const minTime = Math.min(...timestamps);
            const maxTime = Math.max(...timestamps);
            const timeRange = maxTime - minTime;

            // Si ocurrieron suficientes eventos dentro del tiempo permitido...
            if (timeRange <= (rule.time_window * 1000) || matchingLogs.length === 1) {

                alerts.push({
                    rule_id: rule.id,
                    rule_name: rule.name,
                    severity: rule.severity,
                    category: matchingLogs[0].category || 'general',
                    source_ip: matchingLogs[0].source_ip || null,
                    target_host: 'servidor-produccion',
                    event_count: matchingLogs.length,
                    description: `Regla detonada: ${rule.description} - ${matchingLogs.length} eventos detectados.`,
                    raw_logs: matchingLogs.map(log => log.raw),
                    first_occurrence: new Date(minTime).toISOString(),
                    last_occurrence: new Date(maxTime).toISOString()
                });
            }
        }
    }
}

// Cerramos la conexión a la base de datos de forma limpia
await client.end();

// Pasamos las Alertas Oficiales al siguiente nodo
return alerts.map(alert => ({ json: alert }));