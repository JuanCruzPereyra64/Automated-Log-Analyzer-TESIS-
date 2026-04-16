-- Borrar tablas previas para empezar de cero
DROP TABLE IF EXISTS system_metrics;
DROP TABLE IF EXISTS detection_rules;
DROP TABLE IF EXISTS attack_patterns;
DROP TABLE IF EXISTS alerts;

-- 1. TABLA DE ALERTAS: El corazón del sistema para persistencia forense
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

-- 2. TABLA DE PATRONES DE ATAQUE: Para seguimiento de amenazas recurrentes
CREATE TABLE attack_patterns (
    id SERIAL PRIMARY KEY,
    pattern_type VARCHAR(50) NOT NULL,
    source_ip INET NOT NULL,
    target_host VARCHAR(255),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1,
    is_blocked BOOLEAN DEFAULT false,
    UNIQUE(source_ip, pattern_type) -- Evita duplicados para la misma IP/Ataque
);

-- 3. TABLA DE REGLAS DE DETECCIÓN: Motor dinámico para n8n
CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    pattern TEXT NOT NULL, -- Expresión regular o patrón de búsqueda
    severity VARCHAR(20) NOT NULL,
    threshold INTEGER DEFAULT 1, -- Ocurrencias mínimas
    time_window INTEGER DEFAULT 300, -- Ventana en segundos (ej. 5 min)
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. INSERTAR REGLAS INICIALES (Configuración de Cátedra)
INSERT INTO detection_rules (name, description, pattern, severity, threshold, time_window) VALUES
('SSH Brute Force', 'Múltiples intentos fallidos de SSH detectados', 'Failed password.*ssh', 'high', 5, 300),
('Sudo Abuse', 'Uso sospechoso o no autorizado de sudo', 'sudo.*COMMAND=.*', 'medium', 10, 600),
('Root Login Attempt', 'Intento crítico de acceso como root', 'Failed password for root', 'critical', 1, 1),
('SQL Injection Pattern', 'Detección de inyección SQL en logs web', '(union.*select|drop.*table)', 'high', 1, 1);

-- 5. ÍNDICES DE RENDIMIENTO (Crucial para auditoría rápida)
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_attack_patterns_ip ON attack_patterns(source_ip);