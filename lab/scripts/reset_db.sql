-- Reset de estado por episodio.
-- IMPORTANTE: NO borrar file_offsets (el pipeline lee incrementalmente por
-- inode+offset; borrarlo hace que relea la region NUL que deja el truncado
-- concurrente de syslogd). Tampoco borrar pipeline_runs (historial de depuracion).
TRUNCATE alerts, attack_patterns, parsed_events RESTART IDENTITY;
SELECT 'db reset ok' AS status;
