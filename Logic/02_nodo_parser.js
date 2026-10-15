// ==========================================
// NODO 3: PARSER Y NORMALIZADOR DE EVENTOS
// Este código se pegará en el nodo "Code" de n8n
// ==========================================

// 1. Obtenemos todos los logs que entraron al nodo
const items = $input.all();
const parsedLogs = [];

// 2. Iteramos sobre cada item (cada línea de log)
for (const item of items) {
    // Asumimos que el log crudo viene en una propiedad llamada 'raw' o 'message'
    const rawLog = item.json.raw || item.json.message || "";

    let parsed = {
        timestamp: new Date().toISOString(), // Fallback por si no hay fecha
        raw_log: rawLog,
        type: 'unknown',
        category: 'unknown',
        severity: 'low'
    };

    // --- REGLA 1: Detección de Fuerza Bruta SSH ---
    // Ej: "Failed password for root from 192.168.1.100 port 22"
    const sshFailedMatch = rawLog.match(/Failed password for (invalid user )?(\w+) from ([\d.]+) port/);
    if (sshFailedMatch) {
        parsed.type = 'ssh_failed';
        parsed.username = sshFailedMatch[2];
        parsed.source_ip = sshFailedMatch[3];
        parsed.category = 'authentication_failure';
        parsed.severity = 'high';
    }

    // --- REGLA 2: Detección de Abuso de Privilegios (Sudo) ---
    // Ej: "sudo: juan : TTY=pts/0 ; PWD=/home/juan ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    const sudoMatch = rawLog.match(/sudo:\s+(\w+)\s+:.*COMMAND=(.+)/);
    if (sudoMatch) {
        parsed.type = 'sudo_usage';
        parsed.username = sudoMatch[1];
        parsed.command = sudoMatch[2];
        parsed.category = 'privilege_escalation';
        parsed.severity = 'medium';

        // Si intentan leer archivos críticos como /etc/shadow, subimos la severidad a crítica
        if (parsed.command.includes('/etc/shadow') || parsed.command.includes('su -')) {
            parsed.severity = 'critical';
        }
    }

    // --- REGLA 3: Detección de Inyección SQL (Web) ---
    // Ej: "GET /login.php?user=admin' OR '1'='1"
    const sqlInjectionMatch = rawLog.match(/(union.*select|drop.*table|'.*or.*'='|%27.*OR.*%27)/i);
    if (sqlInjectionMatch) {
        parsed.type = 'sql_injection_attempt';
        parsed.pattern = sqlInjectionMatch[0];
        parsed.category = 'web_attack';
        parsed.severity = 'critical';

        // Intentamos extraer la IP si es un log de Apache/Nginx (suele estar al principio)
        const ipMatch = rawLog.match(/^([\d.]+)/);
        if (ipMatch) parsed.source_ip = ipMatch[1];
    }

    // 3. Solo guardamos los logs que hicieron "match" con alguna amenaza
    if (parsed.type !== 'unknown') {
        parsedLogs.push({ json: parsed });
    }
}

// 4. Devolvemos la lista limpia y estructurada al siguiente nodo
return parsedLogs;