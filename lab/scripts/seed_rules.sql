-- Seed unico de reglas de deteccion (fidelidad tesis: exactamente 5 reglas con IDs explicitos).
-- reset_db.sql NO toca detection_rules, por lo que este seed persiste entre episodios.
TRUNCATE detection_rules RESTART IDENTITY;

INSERT INTO detection_rules (id, name, description, pattern, severity, threshold, time_window, enabled) VALUES
  (1, 'SSH Brute Force',      'Intentos fallidos de autenticacion SSH',                       'Failed password.*ssh',              'high',     5,  300, true),
  (2, 'Sudo Abuse',           'Uso abusivo de sudo (comandos privilegiados)',                 'sudo.*COMMAND=.*',                  'medium',   10, 600, true),
  (3, 'Port Scan Detection',  'Escaneo de puertos: paquetes descartados por iptables (DROP)',  'iptables.*DROP.*DPT',               'medium',   20, 60,  true),
  (4, 'Root Login Attempt',   'Intento de login como root',                                   'Failed password for root',          'critical', 1,  1,   true),
  (5, 'SQL Injection Pattern','Patron de inyeccion SQL en peticiones web',                    '(union.*select|drop.*table)',       'high',     1,  1,   true);

SELECT setval('detection_rules_id_seq', (SELECT max(id) FROM detection_rules));
SELECT id, name, pattern, severity, threshold, time_window, enabled FROM detection_rules ORDER BY id;
