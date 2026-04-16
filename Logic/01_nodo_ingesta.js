// =====================================================================
// NODO 2: Ingesta Real de Logs (Read Security Logs)
// Función: Leer archivos físicos del disco duro del servidor Linux
// =====================================================================

// Importamos librerías nativas de Node.js para manejo de archivos
const fs = require('fs');
const readline = require('readline');

// Estas son las rutas donde Syslog-ng guardará los logs (Lo configuraremos luego)
const logFiles = [
    '/var/log/security/alerts.log',
    '/var/log/security/failed_ssh.log',
    '/var/log/centralized/all.log'
];

// Calculamos exactamente hace 5 minutos (para no leer logs viejos repetidos)
const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);

// Función asíncrona para leer línea por línea sin saturar la memoria RAM
async function readRecentLogs(filePath) {
    const logs = [];

    try {
        // Verificamos si el archivo existe antes de leerlo
        if (!fs.existsSync(filePath)) {
            return logs;
        }

        const fileStream = fs.createReadStream(filePath);
        const rl = readline.createInterface({
            input: fileStream,
            crlfDelay: Infinity
        });

        for await (const line of rl) {
            // Extraemos la fecha del log (Asumiendo formato ISO Syslog-ng)
            const match = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);

            if (match) {
                const logDate = new Date(match[1]);

                // Solo guardamos la línea si ocurrió en los últimos 5 minutos
                if (logDate.getTime() >= fiveMinutesAgo) {
                    logs.push({
                        timestamp: logDate.toISOString(),
                        raw: line,
                        file: filePath
                    });
                }
            }
        }
    } catch (error) {
        console.error(`Error de Ingesta en ${filePath}:`, error.message);
    }

    return logs;
}

// Ejecutamos la lectura para todos los archivos configurados
let allLogs = [];
for (const file of logFiles) {
    const logs = await readRecentLogs(file);
    allLogs = allLogs.concat(logs);
}

// Convertimos el array al formato JSON que n8n necesita para el siguiente nodo (el Parser)
return allLogs.map(log => ({ json: log }));