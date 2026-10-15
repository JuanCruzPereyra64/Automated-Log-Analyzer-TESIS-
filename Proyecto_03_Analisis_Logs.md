# Proyecto 3: Análisis Automatizado de Registros y Detección de Anomalías

## 📋 Información General

**Nivel de Dificultad**: Intermedio-Avanzado
**Tiempo Estimado**: 12-16 horas
**Categoría**: Security Monitoring & Incident Detection

## 🎯 Objetivos de Aprendizaje

Al completar este proyecto, los estudiantes serán capaces de:

1. Implementar sistemas centralizados de recolección de logs
2. Analizar patrones y detectar anomalías en registros de sistema
3. Crear reglas de detección para eventos de seguridad
4. Automatizar respuestas ante incidentes detectados
5. Generar alertas y reportes de seguridad en tiempo real
6. Comprender el ciclo de vida de la gestión de eventos de seguridad (SIEM básico)

## 🔧 Herramientas Requeridas

### Software Principal
- **N8N**: Orquestación de flujos de análisis
- **Elasticsearch** o **Splunk**: Indexación y búsqueda de logs (opcional pero recomendado)
- **Syslog-ng** o **Fluentd**: Recolección centralizada de logs
- **Grafana**: Visualización de métricas (opcional)
- **PostgreSQL**: Almacenamiento de alertas y eventos

### Herramientas de Análisis
- **Fail2ban**: Detección de intentos de intrusión
- **OSSEC** o **Wazuh**: Sistema de detección de intrusiones basado en host (HIDS)
- **Alertmanager**: Gestión avanzada de alertas

## 🏗️ Configuración del Laboratorio

### Arquitectura del Sistema

```
┌────────────────────────────────────────────────────────┐
│         Infraestructura de Análisis de Logs            │
│                                                        │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────┐  │
│  │ Web Server   │   │  Database    │   │ Firewall │  │
│  │  (Apache)    │   │  (MySQL)     │   │ (iptables│  │
│  │              │   │              │   │          │  │
│  └──────┬───────┘   └──────┬───────┘   └────┬─────┘  │
│         │                  │                 │        │
│         └──────────────────┴─────────────────┘        │
│                            │                          │
│                    ┌───────▼────────┐                 │
│                    │   Syslog-ng    │                 │
│                    │  (Collector)   │                 │
│                    └───────┬────────┘                 │
│                            │                          │
│         ┌──────────────────┴──────────────────┐      │
│         │                                      │      │
│   ┌─────▼──────┐                      ┌───────▼────┐ │
│   │Elasticsearch│                      │     N8N    │ │
│   │  (Storage)  │◀────────────────────│  (Analysis)│ │
│   └─────┬───────┘                      └───────┬────┘ │
│         │                                      │      │
│   ┌─────▼──────┐                      ┌───────▼────┐ │
│   │  Grafana   │                      │PostgreSQL  │ │
│   │(Dashboard) │                      │  (Alerts)  │ │
│   └────────────┘                      └────────────┘ │
└────────────────────────────────────────────────────────┘
```

### Paso 1: Instalación de Syslog-ng

```bash
# Instalar Syslog-ng
sudo apt update
sudo apt install syslog-ng -y

# Backup de configuración original
sudo cp /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf.backup
```

Configuración de Syslog-ng:
```conf
# /etc/syslog-ng/syslog-ng.conf

@version: 3.35
@include "scl.conf"

# Opciones globales
options {
    chain_hostnames(off);
    flush_lines(0);
    use_dns(no);
    use_fqdn(no);
    owner("root");
    group("adm");
    perm(0640);
    stats_freq(0);
    bad_hostname("^gconfd$");
    time_reopen(10);
};

# Fuentes de logs
source s_local {
    system();
    internal();
};

source s_network {
    tcp(ip(0.0.0.0) port(514) max-connections(100));
    udp(ip(0.0.0.0) port(514));
};

# Filtros por tipo de servicio
filter f_auth { facility(auth, authpriv); };
filter f_syslog { facility(syslog); };
filter f_cron { facility(cron); };
filter f_daemon { facility(daemon); };
filter f_kern { facility(kern); };
filter f_mail { facility(mail); };
filter f_user { facility(user); };

# Filtros por severidad
filter f_emerg { level(emerg); };
filter f_alert { level(alert); };
filter f_crit { level(crit); };
filter f_err { level(err); };
filter f_warn { level(warn); };

# Filtros personalizados para detección
filter f_ssh_failed {
    facility(auth, authpriv) and
    match("Failed password" value("MESSAGE"));
};

filter f_sudo_usage {
    facility(auth, authpriv) and
    match("sudo" value("PROGRAM"));
};

filter f_iptables_drop {
    facility(kern) and
    match("iptables.*DROP" value("MESSAGE"));
};

# Destinos de logs
destination d_auth { file("/var/log/auth.log"); };
destination d_syslog { file("/var/log/syslog"); };
destination d_cron { file("/var/log/cron.log"); };
destination d_daemon { file("/var/log/daemon.log"); };
destination d_kern { file("/var/log/kern.log"); };

# Destino centralizado para análisis
destination d_centralized {
    file("/var/log/centralized/all.log"
        template("${ISODATE} ${HOST} ${PROGRAM}[${PID}]: ${MESSAGE}\n")
        create_dirs(yes)
    );
};

# Destino JSON para Elasticsearch (opcional)
destination d_elasticsearch {
    file("/var/log/centralized/json/${HOST}/${YEAR}.${MONTH}.${DAY}.log"
        template("$(format-json --scope rfc5424 --exclude DATE --key ISODATE)\n")
        create_dirs(yes)
    );
};

# Destinos específicos para eventos de seguridad
destination d_security_alerts {
    file("/var/log/security/alerts.log"
        template("${ISODATE} ${HOST} [ALERT] ${PROGRAM}: ${MESSAGE}\n")
        create_dirs(yes)
    );
};

destination d_failed_ssh {
    file("/var/log/security/failed_ssh.log"
        template("${ISODATE} ${HOST} ${MESSAGE}\n")
        create_dirs(yes)
    );
};

# Conexiones (source -> filter -> destination)
log { source(s_local); filter(f_auth); destination(d_auth); };
log { source(s_local); filter(f_syslog); destination(d_syslog); };
log { source(s_local); filter(f_cron); destination(d_cron); };

# Logs de red
log { source(s_network); destination(d_centralized); };
log { source(s_network); destination(d_elasticsearch); };

# Logs de seguridad
log { source(s_local); source(s_network); filter(f_ssh_failed); destination(d_failed_ssh); };
log { source(s_local); source(s_network); filter(f_sudo_usage); destination(d_security_alerts); };
log { source(s_local); source(s_network); filter(f_iptables_drop); destination(d_security_alerts); };

# Logs críticos
log { source(s_local); source(s_network); filter(f_emerg); destination(d_security_alerts); };
log { source(s_local); source(s_network); filter(f_alert); destination(d_security_alerts); };
log { source(s_local); source(s_network); filter(f_crit); destination(d_security_alerts); };
```

```bash
# Crear directorios necesarios
sudo mkdir -p /var/log/centralized/json
sudo mkdir -p /var/log/security
sudo chown -R syslog:adm /var/log/centralized /var/log/security

# Validar configuración
sudo syslog-ng --syntax-only

# Reiniciar servicio
sudo systemctl restart syslog-ng
sudo systemctl enable syslog-ng

# Verificar que está escuchando
sudo netstat -tulnp | grep syslog-ng
```

### Paso 2: Configurar Clientes para Enviar Logs

En cada servidor que desees monitorear:

```bash
# Configurar rsyslog para enviar a servidor central
sudo nano /etc/rsyslog.d/50-default.conf
```

Agregar al final:
```conf
# Enviar todos los logs al servidor central
*.* @@192.168.100.5:514  # TCP (recomendado)
# *.* @192.168.100.5:514  # UDP (alternativa)
```

```bash
# Reiniciar rsyslog
sudo systemctl restart rsyslog
```

### Paso 3: Instalación de Elasticsearch (Opcional)

```bash
# Importar clave GPG de Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Agregar repositorio
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Instalar Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# Configurar Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Configuración básica:
```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: security-logs
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200

# Seguridad básica
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
```

```bash
# Iniciar Elasticsearch
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# Obtener contraseña del usuario elastic
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

# Probar conexión
curl -X GET "localhost:9200/" -u elastic:YOUR_PASSWORD
```

### Paso 4: Instalación de Logstash (Para procesar logs a Elasticsearch)

```bash
# Instalar Logstash
sudo apt install logstash -y

# Configurar pipeline
sudo nano /etc/logstash/conf.d/syslog-pipeline.conf
```

```conf
# /etc/logstash/conf.d/syslog-pipeline.conf

input {
  file {
    path => "/var/log/centralized/json/*/*.log"
    start_position => "beginning"
    codec => "json"
    type => "syslog"
  }

  file {
    path => "/var/log/security/alerts.log"
    start_position => "beginning"
    type => "security_alert"
  }

  file {
    path => "/var/log/security/failed_ssh.log"
    start_position => "beginning"
    type => "failed_ssh"
  }
}

filter {
  if [type] == "failed_ssh" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:hostname} Failed password for (invalid user )?%{USERNAME:username} from %{IP:source_ip} port %{NUMBER:port}"
      }
    }

    mutate {
      add_field => { "alert_level" => "warning" }
      add_field => { "category" => "authentication_failure" }
    }
  }

  if [type] == "security_alert" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:hostname} \[ALERT\] %{WORD:program}: %{GREEDYDATA:alert_message}"
      }
    }

    mutate {
      add_field => { "alert_level" => "high" }
      add_field => { "category" => "security_event" }
    }
  }

  # Enriquecimiento con GeoIP
  if [source_ip] {
    geoip {
      source => "source_ip"
      target => "geoip"
    }
  }

  # Agregar timestamp
  date {
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    user => "elastic"
    password => "YOUR_PASSWORD"
    index => "security-logs-%{+YYYY.MM.dd}"
  }

  # Debug (opcional, comentar en producción)
  # stdout { codec => rubydebug }
}
```

```bash
# Iniciar Logstash
sudo systemctl start logstash
sudo systemctl enable logstash

# Verificar logs
sudo tail -f /var/log/logstash/logstash-plain.log
```

### Paso 5: Configuración de Base de Datos para Alertas

```sql
-- Crear base de datos
CREATE DATABASE security_monitoring;

\c security_monitoring

-- Tabla de alertas
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    category VARCHAR(50) NOT NULL, -- auth_failure, brute_force, anomaly, etc.
    source_host VARCHAR(255),
    source_ip INET,
    target_host VARCHAR(255),
    event_count INTEGER DEFAULT 1,
    description TEXT,
    raw_log TEXT,
    status VARCHAR(20) DEFAULT 'new', -- new, investigating, resolved, false_positive
    assigned_to VARCHAR(100),
    notes TEXT,
    resolved_at TIMESTAMP
);

-- Tabla de patrones de ataque detectados
CREATE TABLE attack_patterns (
    id SERIAL PRIMARY KEY,
    pattern_type VARCHAR(50) NOT NULL,
    source_ip INET NOT NULL,
    target_host VARCHAR(255),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1,
    is_blocked BOOLEAN DEFAULT false
);

-- Tabla de métricas de sistema
CREATE TABLE system_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hostname VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC,
    unit VARCHAR(20)
);

-- Tabla de reglas de detección
CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    pattern TEXT NOT NULL, -- Expresión regular o patrón
    severity VARCHAR(20) NOT NULL,
    threshold INTEGER DEFAULT 1, -- Número de ocurrencias para activar alerta
    time_window INTEGER DEFAULT 300, -- Ventana de tiempo en segundos
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insertar reglas de detección predefinidas
INSERT INTO detection_rules (name, description, pattern, severity, threshold, time_window) VALUES
('SSH Brute Force', 'Detecta múltiples intentos fallidos de SSH', 'Failed password.*ssh', 'high', 5, 300),
('Sudo Abuse', 'Detecta uso sospechoso de sudo', 'sudo.*COMMAND=.*', 'medium', 10, 600),
('Port Scan Detection', 'Detecta posibles escaneos de puertos', 'iptables.*DROP.*DPT', 'medium', 20, 60),
('Root Login Attempt', 'Detecta intentos de login como root', 'Failed password for root', 'critical', 1, 1),
('SQL Injection Pattern', 'Detecta patrones de inyección SQL en logs web', '(union.*select|drop.*table)', 'high', 1, 1);

-- Índices para mejorar rendimiento
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_attack_patterns_ip ON attack_patterns(source_ip);
CREATE INDEX idx_attack_patterns_last_seen ON attack_patterns(last_seen);
CREATE INDEX idx_system_metrics_hostname ON system_metrics(hostname, timestamp);
```

## 🔄 Implementación del Flujo N8N

### Workflow de Análisis

```
[Cron: Every 5 min] → [Read Logs] → [Parse & Analyze] → [Check Rules]
                                                               ↓
                                                      [Anomaly Detected?]
                                                         ↓           ↓
                                                       YES          NO
                                                         ↓           ↓
                                           [Store Alert] → [Send Email/Slack]
                                                         ↓
                                              [Update Attack Patterns]
```

### Nodo 1: Cron Trigger

```json
{
  "cronExpression": "*/5 * * * *",
  "triggerTimes": {
    "item": [
      {
        "mode": "everyX",
        "value": 5,
        "unit": "minutes"
      }
    ]
  }
}
```

### Nodo 2: Read Security Logs

```javascript
// Nodo: Function
const fs = require('fs');
const readline = require('readline');

const logFiles = [
  '/var/log/security/alerts.log',
  '/var/log/security/failed_ssh.log',
  '/var/log/centralized/all.log'
];

// Leer logs de los últimos 5 minutos
const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);

async function readRecentLogs(filePath) {
  const logs = [];

  try {
    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    for await (const line of rl) {
      // Parsear línea de log
      const match = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
      if (match) {
        const logDate = new Date(match[1]);
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
    console.error(`Error reading ${filePath}:`, error.message);
  }

  return logs;
}

// Leer todos los archivos de log
let allLogs = [];
for (const file of logFiles) {
  const logs = await readRecentLogs(file);
  allLogs = allLogs.concat(logs);
}

return allLogs.map(log => ({ json: log }));
```

### Nodo 3: Parse Log Entries

```javascript
// Parsear diferentes tipos de logs
const items = $input.all();

const parsedLogs = items.map(item => {
  const log = item.json;
  let parsed = {
    timestamp: log.timestamp,
    raw: log.raw,
    file: log.file,
    type: 'unknown'
  };

  // Detectar SSH fallido
  const sshFailedMatch = log.raw.match(/Failed password for (invalid user )?(\w+) from ([\d.]+) port (\d+)/);
  if (sshFailedMatch) {
    parsed.type = 'ssh_failed';
    parsed.username = sshFailedMatch[2];
    parsed.source_ip = sshFailedMatch[3];
    parsed.port = sshFailedMatch[4];
    parsed.category = 'authentication_failure';
  }

  // Detectar uso de sudo
  const sudoMatch = log.raw.match(/sudo.*?(\w+).*?COMMAND=(.+)/);
  if (sudoMatch) {
    parsed.type = 'sudo_usage';
    parsed.user = sudoMatch[1];
    parsed.command = sudoMatch[2];
    parsed.category = 'privilege_escalation';
  }

  // Detectar DROP de iptables
  const iptablesMatch = log.raw.match(/iptables.*DROP.*SRC=([\d.]+).*DPT=(\d+)/);
  if (iptablesMatch) {
    parsed.type = 'iptables_drop';
    parsed.source_ip = iptablesMatch[1];
    parsed.dest_port = iptablesMatch[2];
    parsed.category = 'network_attack';
  }

  // Detectar patrones de inyección SQL en logs de Apache
  const sqlInjectionMatch = log.raw.match(/(union.*select|drop.*table|'.*or.*'=')/i);
  if (sqlInjectionMatch) {
    parsed.type = 'sql_injection_attempt';
    parsed.pattern = sqlInjectionMatch[0];
    parsed.category = 'web_attack';
  }

  // Detectar escaneo de directorios web
  const dirScanMatch = log.raw.match(/GET.*\/(admin|phpmyadmin|wp-admin|\.env).*404/);
  if (dirScanMatch) {
    parsed.type = 'directory_scan';
    parsed.target = dirScanMatch[1];
    parsed.category = 'reconnaissance';
  }

  return { json: parsed };
});

return parsedLogs.filter(log => log.json.type !== 'unknown');
```

### Nodo 4: Apply Detection Rules

```javascript
// Consultar reglas de detección desde la base de datos
const { Client } = require('pg');
const client = new Client({
  host: 'localhost',
  database: 'security_monitoring',
  user: 'db_user',
  password: 'db_pass'
});

await client.connect();

// Obtener reglas activas
const rulesResult = await client.query('SELECT * FROM detection_rules WHERE enabled = true');
const rules = rulesResult.rows;

const logs = $input.all();
const alerts = [];

// Agrupar logs por tipo y source_ip
const logGroups = {};
logs.forEach(item => {
  const log = item.json;
  const key = `${log.type}_${log.source_ip || 'unknown'}`;

  if (!logGroups[key]) {
    logGroups[key] = [];
  }
  logGroups[key].push(log);
});

// Aplicar reglas de detección
for (const rule of rules) {
  for (const [key, logGroup] of Object.entries(logGroups)) {
    // Verificar si los logs coinciden con el patrón de la regla
    const matchingLogs = logGroup.filter(log => {
      const regex = new RegExp(rule.pattern, 'i');
      return regex.test(log.raw);
    });

    // Verificar threshold
    if (matchingLogs.length >= rule.threshold) {
      // Verificar time window
      const timestamps = matchingLogs.map(log => new Date(log.timestamp).getTime());
      const timeRange = Math.max(...timestamps) - Math.min(...timestamps);

      if (timeRange <= rule.time_window * 1000) {
        alerts.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          category: matchingLogs[0].category || 'general',
          source_ip: matchingLogs[0].source_ip || null,
          target_host: require('os').hostname(),
          event_count: matchingLogs.length,
          description: `${rule.description} - ${matchingLogs.length} eventos detectados`,
          raw_logs: matchingLogs.map(log => log.raw),
          first_occurrence: new Date(Math.min(...timestamps)).toISOString(),
          last_occurrence: new Date(Math.max(...timestamps)).toISOString()
        });
      }
    }
  }
}

await client.end();

return alerts.map(alert => ({ json: alert }));
```

### Nodo 5: Enrich Alerts with Threat Intelligence

```javascript
// Enriquecer alertas con información de amenazas
const axios = require('axios');

const alerts = $input.all();
const enrichedAlerts = [];

for (const item of alerts) {
  const alert = item.json;
  let enriched = { ...alert };

  if (alert.source_ip) {
    try {
      // Consultar AbuseIPDB
      const abuseIPDB = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
        headers: { 'Key': process.env.ABUSEIPDB_API_KEY },
        params: {
          ipAddress: alert.source_ip,
          maxAgeInDays: 90
        }
      });

      enriched.threat_score = abuseIPDB.data.data.abuseConfidenceScore;
      enriched.is_known_threat = abuseIPDB.data.data.abuseConfidenceScore > 50;
      enriched.country = abuseIPDB.data.data.countryCode;
      enriched.isp = abuseIPDB.data.data.isp;

    } catch (error) {
      console.log(`Could not enrich IP ${alert.source_ip}: ${error.message}`);
    }

    // Verificar si la IP está en listas negras locales
    const { Client } = require('pg');
    const client = new Client({
      host: 'localhost',
      database: 'security_monitoring',
      user: 'db_user',
      password: 'db_pass'
    });

    await client.connect();

    const blocklistCheck = await client.query(
      'SELECT * FROM attack_patterns WHERE source_ip = $1 AND is_blocked = true',
      [alert.source_ip]
    );

    enriched.is_locally_blocked = blocklistCheck.rows.length > 0;

    await client.end();
  }

  // Aumentar severidad si es amenaza conocida
  if (enriched.is_known_threat && enriched.severity !== 'critical') {
    enriched.severity = enriched.severity === 'high' ? 'critical' : 'high';
    enriched.description += ` [AMENAZA CONOCIDA - Score: ${enriched.threat_score}]`;
  }

  enrichedAlerts.push({ json: enriched });
}

return enrichedAlerts;
```

### Nodo 6: Store Alerts in Database

```javascript
// Almacenar alertas en PostgreSQL
const { Client } = require('pg');
const client = new Client({
  host: 'localhost',
  database: 'security_monitoring',
  user: 'db_user',
  password: 'db_pass'
});

await client.connect();

const alerts = $input.all();
const storedAlerts = [];

for (const item of alerts) {
  const alert = item.json;

  // Insertar alerta
  const result = await client.query(`
    INSERT INTO alerts (
      timestamp, severity, category, source_host, source_ip,
      target_host, event_count, description, raw_log, status
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING id
  `, [
    alert.first_occurrence || new Date().toISOString(),
    alert.severity,
    alert.category,
    null,
    alert.source_ip,
    alert.target_host,
    alert.event_count,
    alert.description,
    JSON.stringify(alert.raw_logs),
    'new'
  ]);

  alert.alert_id = result.rows[0].id;
  storedAlerts.push({ json: alert });

  // Actualizar attack_patterns
  if (alert.source_ip) {
    await client.query(`
      INSERT INTO attack_patterns (pattern_type, source_ip, target_host, occurrence_count)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (source_ip, pattern_type)
      DO UPDATE SET
        last_seen = CURRENT_TIMESTAMP,
        occurrence_count = attack_patterns.occurrence_count + 1
    `, [alert.category, alert.source_ip, alert.target_host, alert.event_count]);
  }
}

await client.end();

return storedAlerts;
```

### Nodo 7: Send Notifications

```javascript
// Enviar notificaciones según severidad
const alerts = $input.all();

const criticalAlerts = alerts.filter(item => item.json.severity === 'critical');
const highAlerts = alerts.filter(item => item.json.severity === 'high');

let notifications = [];

// Notificaciones críticas - Email inmediato + Slack
if (criticalAlerts.length > 0) {
  notifications.push({
    json: {
      type: 'email',
      priority: 'high',
      to: 'security-team@example.com',
      subject: `🚨 CRÍTICO: ${criticalAlerts.length} Alertas de Seguridad`,
      body: criticalAlerts.map(item => {
        const alert = item.json;
        return `
**${alert.rule_name}**
Severidad: ${alert.severity.toUpperCase()}
IP Origen: ${alert.source_ip || 'N/A'}
Eventos: ${alert.event_count}
Descripción: ${alert.description}
Timestamp: ${alert.first_occurrence}
---
`;
      }).join('\n')
    }
  });

  notifications.push({
    json: {
      type: 'slack',
      channel: '#security-alerts',
      text: `🚨 *ALERTA CRÍTICA DE SEGURIDAD*\n${criticalAlerts.length} eventos críticos detectados`,
      attachments: criticalAlerts.map(item => {
        const alert = item.json;
        return {
          color: 'danger',
          title: alert.rule_name,
          fields: [
            { title: 'IP Origen', value: alert.source_ip || 'N/A', short: true },
            { title: 'Eventos', value: alert.event_count.toString(), short: true },
            { title: 'Descripción', value: alert.description, short: false }
          ],
          footer: `Alert ID: ${alert.alert_id}`,
          ts: new Date(alert.first_occurrence).getTime() / 1000
        };
      })
    }
  });
}

// Notificaciones altas - Solo email digest
if (highAlerts.length > 0) {
  notifications.push({
    json: {
      type: 'email',
      priority: 'normal',
      to: 'security-team@example.com',
      subject: `⚠️ ${highAlerts.length} Alertas de Alta Prioridad`,
      body: `Se han detectado ${highAlerts.length} eventos de alta prioridad. Revise el dashboard para más detalles.`
    }
  });
}

return notifications;
```

### Nodo 8: Auto-Response Actions

```javascript
// Acciones automáticas de respuesta
const alerts = $input.all();
const actions = [];

for (const item of alerts) {
  const alert = item.json;

  // Bloquear IPs con score alto de amenaza
  if (alert.is_known_threat && alert.threat_score > 75 && alert.source_ip) {
    actions.push({
      json: {
        action: 'block_ip',
        ip: alert.source_ip,
        reason: `Threat score: ${alert.threat_score}`,
        alert_id: alert.alert_id
      }
    });
  }

  // Bloquear después de múltiples intentos SSH fallidos
  if (alert.category === 'authentication_failure' && alert.event_count >= 10) {
    actions.push({
      json: {
        action: 'block_ip',
        ip: alert.source_ip,
        reason: `Brute force attempt: ${alert.event_count} failed attempts`,
        alert_id: alert.alert_id,
        duration: 3600 // 1 hora
      }
    });
  }

  // Alertar SOC para posibles inyecciones SQL
  if (alert.category === 'web_attack') {
    actions.push({
      json: {
        action: 'create_ticket',
        severity: 'high',
        title: `Possible web attack: ${alert.rule_name}`,
        description: alert.description,
        alert_id: alert.alert_id
      }
    });
  }
}

return actions;
```

### Nodo 9: Execute Response Actions

```javascript
// Ejecutar acciones de respuesta
const actions = $input.all();
const results = [];

for (const item of actions) {
  const action = item.json;

  try {
    if (action.action === 'block_ip') {
      // Bloquear IP usando iptables
      const { exec } = require('child_process');
      const { promisify } = require('util');
      const execAsync = promisify(exec);

      const command = `sudo iptables -A INPUT -s ${action.ip} -j DROP`;
      await execAsync(command);

      // Registrar en base de datos
      const { Client } = require('pg');
      const client = new Client({
        host: 'localhost',
        database: 'security_monitoring',
        user: 'db_user',
        password: 'db_pass'
      });

      await client.connect();

      await client.query(`
        UPDATE attack_patterns
        SET is_blocked = true
        WHERE source_ip = $1
      `, [action.ip]);

      await client.query(`
        UPDATE alerts
        SET notes = CONCAT(COALESCE(notes, ''), 'AUTO-BLOCKED at ', NOW()::text, E'\\n')
        WHERE id = $1
      `, [action.alert_id]);

      await client.end();

      results.push({
        json: {
          action: 'block_ip',
          ip: action.ip,
          status: 'success',
          message: `IP ${action.ip} blocked successfully`
        }
      });

    } else if (action.action === 'create_ticket') {
      // Crear ticket en sistema de gestión
      // (Integración con Jira, ServiceNow, etc.)
      results.push({
        json: {
          action: 'create_ticket',
          status: 'success',
          ticket_id: `SEC-${Date.now()}`,
          message: 'Ticket created for SOC review'
        }
      });
    }

  } catch (error) {
    results.push({
      json: {
        action: action.action,
        status: 'failed',
        error: error.message
      }
    });
  }
}

return results;
```

## 📊 Dashboard y Reportes

### Script SQL para Estadísticas

```sql
-- Reporte diario de alertas
SELECT
    DATE(timestamp) AS date,
    severity,
    COUNT(*) AS alert_count
FROM alerts
WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(timestamp), severity
ORDER BY date DESC, severity;

-- Top 10 IPs atacantes
SELECT
    source_ip,
    COUNT(DISTINCT id) AS alert_count,
    STRING_AGG(DISTINCT category, ', ') AS attack_types,
    MAX(timestamp) AS last_seen
FROM alerts
WHERE source_ip IS NOT NULL
    AND timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY source_ip
ORDER BY alert_count DESC
LIMIT 10;

-- Tendencias por categoría
SELECT
    category,
    DATE_TRUNC('hour', timestamp) AS hour,
    COUNT(*) AS events
FROM alerts
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY category, hour
ORDER BY hour DESC, events DESC;

-- Efectividad de respuestas automáticas
SELECT
    ap.source_ip,
    ap.pattern_type,
    ap.occurrence_count,
    ap.is_blocked,
    COUNT(a.id) AS alerts_after_block
FROM attack_patterns ap
LEFT JOIN alerts a ON a.source_ip = ap.source_ip
    AND a.timestamp > ap.last_seen
WHERE ap.is_blocked = true
GROUP BY ap.source_ip, ap.pattern_type, ap.occurrence_count, ap.is_blocked
ORDER BY alerts_after_block DESC;
```

## 📝 Ejercicios para Estudiantes

### Ejercicio 1: Configuración Básica (3 horas)
1. Instalar y configurar Syslog-ng
2. Configurar 3 clientes para enviar logs
3. Verificar recepción centralizada de logs

### Ejercicio 2: Reglas de Detección (4 horas)
1. Crear 5 reglas personalizadas de detección
2. Implementar workflow básico de análisis en N8N
3. Generar alertas de prueba

### Ejercicio 3: Análisis Avanzado (5 horas)
1. Integrar Elasticsearch y Logstash
2. Crear visualizaciones en Grafana/Kibana
3. Implementar enriquecimiento con threat intelligence

### Ejercicio 4: Respuesta Automatizada (4 horas)
1. Implementar auto-bloqueo de IPs maliciosas
2. Crear sistema de tickets automático
3. Configurar notificaciones multi-canal

## 🎓 Preguntas de Evaluación

1. ¿Cuál es la diferencia entre logs, eventos y alertas?
2. ¿Qué es un SIEM y cómo se relaciona con este proyecto?
3. ¿Por qué es importante la centralización de logs?
4. ¿Cómo se puede evitar que las respuestas automáticas generen falsos positivos dañinos?
5. ¿Qué métricas usarías para evaluar la efectividad del sistema de detección?

## 🏆 Criterios de Evaluación

| Criterio | Puntos | Descripción |
|----------|--------|-------------|
| Recolección de logs | 20 | Centralización funcionando correctamente |
| Reglas de detección | 25 | Reglas efectivas y sin falsos positivos excesivos |
| Análisis automatizado | 25 | Workflow N8N completo y funcional |
| Respuestas automáticas | 15 | Acciones de mitigación implementadas |
| Reportes y documentación | 15 | Análisis claro de resultados |

---

**Autor**: Materia de Seguridad Ofensiva
**Última actualización**: 2025
**Licencia**: Uso Educativo
