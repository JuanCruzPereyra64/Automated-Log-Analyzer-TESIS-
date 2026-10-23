#!/bin/sh
# Inyecta 20 unidades de trafico benigno via syslogd (logger).
#   - 10 unidades sub-umbral: 3 intentos fallidos por IP (umbral SSH = 5)
#   - 10 unidades benignas claras: 1 login exitoso por IP
# Ninguna debe generar alerta ni ban.
for i in 10 11 12 13 14 15 16 17 18 19; do
  for k in 1 2 3; do
    logger -p auth.info -t "sshd[$((2000+i))]" "Failed password for testuser from 10.50.1.$i port $((40000+i)) ssh2"
  done
  logger -p auth.info -t "sshd[$((2100+i))]" "Accepted password for testuser from 10.50.2.$i port $((41000+i)) ssh2"
done
echo "inyectado: 30 fallos sub-umbral en 10 IPs + 10 logins exitosos"
