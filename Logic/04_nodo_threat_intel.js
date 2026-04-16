// =====================================================================
// NODO 5 (README): Enrich Alerts with Threat Intelligence
// Función: Consultar API de AbuseIPDB y base de datos local (attack_patterns)
// =====================================================================

// Importamos librerías (Requiere habilitar 'axios' y 'pg' en n8n)
const axios = require('axios');
const { Client } = require('pg');

const alerts = $input.all();
const enrichedAlerts = [];

// 🔑 IMPORTANTE: Acá deberás poner tu API Key gratuita de AbuseIPDB
const ABUSEIPDB_API_KEY = 'TU_API_KEY_AQUI';

for (const item of alerts) {
    const alert = item.json;
    let enriched = { ...alert };

    if (alert.source_ip && alert.source_ip !== 'unknown') {
        try {
            // 1. Consultar Inteligencia Global (AbuseIPDB)
            const abuseIPDB = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
                headers: {
                    'Key': ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                },
                params: {
                    ipAddress: alert.source_ip,
                    maxAgeInDays: 90 // Buscar reportes de los últimos 90 días
                }
            });

            // Guardamos el puntaje de amenaza (0 a 100) y el país
            enriched.threat_score = abuseIPDB.data.data.abuseConfidenceScore;
            enriched.is_known_threat = abuseIPDB.data.data.abuseConfidenceScore > 50;
            enriched.country = abuseIPDB.data.data.countryCode;

        } catch (error) {
            console.log(`No se pudo consultar la IP ${alert.source_ip}: ${error.message}`);
            enriched.threat_score = 0;
            enriched.is_known_threat = false;
        }

        // 2. Consultar Inteligencia Local (PostgreSQL)
        const client = new Client({
            host: 'postgres',
            database: 'security_monitoring',
            user: 'tu_usuario',
            password: 'tu_password',
            port: 5432
        });

        await client.connect();

        // Verificamos si la IP ya está bloqueada en nuestro sistema
        const blocklistCheck = await client.query(
            'SELECT * FROM attack_patterns WHERE source_ip = $1 AND is_blocked = true',
            [alert.source_ip]
        );

        enriched.is_locally_blocked = blocklistCheck.rows.length > 0;
        await client.end();
    }

    // 3. Modificador SOAR: Subir severidad si es un hacker global
    if (enriched.is_known_threat && enriched.severity !== 'critical') {
        enriched.severity = 'critical';
        enriched.description += ` [AMENAZA GLOBAL - Score AbuseIPDB: ${enriched.threat_score}/100]`;
    }

    enrichedAlerts.push({ json: enriched });
}

// Pasamos las alertas enriquecidas al siguiente nodo
return enrichedAlerts;