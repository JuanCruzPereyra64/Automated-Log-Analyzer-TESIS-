#!/bin/sh
set -e

# --- Log a archivo compartido (volumen) ---
: > /var/log/auth.log
touch /var/log/fail2ban.log /var/log/blocks.log

# Directorios de log del thesis (nunca truncarlos: solo append)
mkdir -p /var/log/security /var/log/apache_access
touch /var/log/security/alerts.log /var/log/apache_access/all.log /var/log/apache_access/error.log

# busybox syslogd escribe todo a /var/log/auth.log (facility AUTH incluida)
syslogd -n -O /var/log/auth.log &

# klogd: reenvia mensajes del kernel a syslogd (requiere CAP_SYSLOG).
# NOTA: en este host (WSL2) iptables -j LOG no genera mensajes de kernel dentro
# del contenedor (nf_log_all_netns), por lo que las lineas DROP reales las produce
# el sensor userspace scan_logger.py de abajo. klogd se mantiene por fidelidad.
klogd 2>/dev/null || true

# Intento documentado de desactivar el rate-limit del kernel (falla: /proc/sys ro)
sysctl -w kernel.printk_ratelimit=0 >/dev/null 2>&1 \
  && echo "[victim] net_ratelimit sysctl OK" \
  || echo "[victim] sysctl kernel.printk_ratelimit NO escribible (esperado en contenedor)"

# --- Cadenas iptables base ---
iptables -N LABBLOCK 2>/dev/null || true
iptables -C INPUT -j LABBLOCK 2>/dev/null || iptables -I INPUT 1 -j LABBLOCK

# --- SCANLOG: descarta (DROP) y registra el escaneo de puertos cerrados 30000-30030 ---
# El objetivo LOG del kernel no es visible en contenedor; el DROP si funciona y el
# sensor scan_logger.py escribe las lineas 'iptables DROP: ... DPT=...' en alerts.log.
iptables -N SCANLOG 2>/dev/null || true
iptables -F SCANLOG 2>/dev/null || true
iptables -A SCANLOG -p tcp --dport 30000:30030 -j LOG --log-prefix "iptables DROP: "
iptables -A SCANLOG -p tcp --dport 30000:30030 -j DROP
iptables -C INPUT -j SCANLOG 2>/dev/null || iptables -I INPUT 1 -j SCANLOG

# --- Sensores / forwarders de log ---
# Sensor AF_PACKET (fuente real de las lineas DROP en alerts.log)
python3 /opt/scan_logger.py &

# Forwarder estructural (fidelidad tesis): lineas 'iptables.*DROP' de auth.log -> alerts.log
( tail -f /var/log/auth.log 2>/dev/null | grep --line-buffered 'iptables.*DROP' >> /var/log/security/alerts.log & )

# --- Apache (web server para SQLi / combined access log) ---
echo "[victim] starting httpd..."
httpd -f /etc/apache2/httpd.conf

# --- Agente de bloqueo (active response executor) ---
python3 /opt/block_agent.py &

# --- Host keys si no existen ---
ssh-keygen -A

echo "[victim] starting sshd..."
exec /usr/sbin/sshd -D
