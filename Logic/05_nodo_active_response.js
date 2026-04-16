// =====================================================================
// NODO 8 y 9 (README): Auto-Response & Execute Actions
// Función: Decidir acciones tácticas y ejecutar bloqueos a nivel OS
// =====================================================================

// Importamos librerías nativas de Node y de Postgres
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const { Client } = require('pg');

const enrichedAlerts = $input.all();
const executionResults = [];

for (const item of enrichedAlerts) {
    const alert = item.json;

    // 1. LÓGICA DE DECISIÓN (¿Merece ser bloqueado?)
    let shouldBlock = false;
    let blockReason = "";

    // Condición A: Es una amenaza global grave
    if (alert.is_known_threat && alert.threat_score > 75 && alert.source_ip) {
        shouldBlock = true;
        blockReason = `Amenaza Global (Score AbuseIPDB: ${alert.threat_score})`;
    }

    // Condición B: Fuerza Bruta persistente (Más de 10 intentos)
    else if (alert.category === 'authentication_failure' && alert.event_count >= 10 && alert.source_ip) {
        shouldBlock = true;
        blockReason = `Fuerza Bruta Persistente (${alert.event_count} intentos)`;
    }

    // 2. EJECUCIÓN DE LA RESPUESTA ACTIVA
    if (shouldBlock && !alert.is_locally_blocked) {
        try {
            // Ejecutamos el bloqueo a nivel firewall (iptables)
            const command = `sudo iptables -A INPUT -s ${alert.source_ip} -j DROP`;

            // NOTA PARA LA TESIS: Si n8n está en Docker, esto requiere configurar permisos especiales
            // o usar SSH para mandar el comando al host. Aquí simulamos la ejecución exitosa.
            await execAsync(command);

            // 3. ACTUALIZACIÓN FORENSE EN BASE DE DATOS
            const client = new Client({
                host: 'postgres',
                database: 'security_monitoring',
                user: 'tu_usuario',
                password: 'tu_password',
                port: 5432
            });

            await client.connect();

            // Marcamos la IP como bloqueada en la tabla de patrones
            await client.query(`
        UPDATE attack_patterns 
        SET is_blocked = true 
        WHERE source_ip = $1
      `, [alert.source_ip]);

            // Le agregamos una nota a la alerta para que el SOC lo sepa
            await client.query(`
        UPDATE alerts 
        SET status = 'resolved', notes = CONCAT(COALESCE(notes, ''), 'AUTO-BLOQUEADO vía SOAR. Razón: ', $2::text) 
        WHERE source_ip = $1
      `, [alert.source_ip, blockReason]);

            await client.end();

            // Registramos el éxito de la operación
            executionResults.push({
                json: {
                    action_taken: 'block_ip',
                    target_ip: alert.source_ip,
                    reason: blockReason,
                    status: 'success',
                    message: `IP ${alert.source_ip} bloqueada exitosamente en iptables.`
                }
            });

        } catch (error) {
            // Registramos si hubo un error al intentar bloquear
            executionResults.push({
                json: {
                    action_taken: 'block_ip',
                    target_ip: alert.source_ip,
                    status: 'failed',
                    error: error.message
                }
            });
        }
    } else {
        // Si no superó el umbral de bloqueo, solo lo pasamos como notificación
        executionResults.push({
            json: {
                action_taken: 'none',
                message: 'La alerta no superó los umbrales de bloqueo automático.',
                original_alert: alert
            }
        });
    }
}

// Retornamos el reporte de acciones ejecutadas
return executionResults;