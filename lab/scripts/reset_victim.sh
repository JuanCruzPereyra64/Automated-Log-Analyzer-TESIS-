#!/bin/sh
# Reset de estado del brazo (corre dentro de lab-victim)
#
# NO truncar /var/log/auth.log ni /var/log/fail2ban.log: syslogd y fail2ban
# mantienen el fd abierto y seguirian escribiendo en su offset viejo, dejando
# un hueco de bytes NUL al inicio del archivo (rompe el parseo incremental).
# Tampoco truncar /var/log/security/alerts.log ni /var/log/apache_access/all.log
# (los escriben scan_logger.py y httpd con fds abiertos). Cada episodio usa una
# IP de origen unica, por lo que el aislamiento entre episodios es automatico.
wget -qO- http://127.0.0.1:9000/reset >/dev/null 2>&1 || true
iptables -F LABBLOCK 2>/dev/null || true
iptables -F f2b-SSH 2>/dev/null || true
iptables -F f2b-sshd 2>/dev/null || true

# SCANLOG (deteccion de escaneo): conservar la cadena y sus reglas; solo asegurar
# que existan (idempotente) para no perder el DROP de 30000-30030 entre episodios.
iptables -N SCANLOG 2>/dev/null || true
iptables -C INPUT -j SCANLOG 2>/dev/null || iptables -I INPUT 1 -j SCANLOG
# Si la cadena quedo vacia, recrear sus dos reglas (LOG + DROP) sin borrar la cadena.
if ! iptables -C SCANLOG -p tcp --dport 30000:30030 -j DROP 2>/dev/null; then
  iptables -F SCANLOG 2>/dev/null || true
  iptables -A SCANLOG -p tcp --dport 30000:30030 -j LOG --log-prefix "iptables DROP: "
  iptables -A SCANLOG -p tcp --dport 30000:30030 -j DROP
fi

fail2ban-client status sshd >/dev/null 2>&1 && fail2ban-client unban --all >/dev/null 2>&1 || true
: > /var/log/blocks.log
echo "victim reset ok"
