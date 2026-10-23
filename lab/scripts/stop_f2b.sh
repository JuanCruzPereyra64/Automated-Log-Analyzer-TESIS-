#!/bin/sh
# Detiene Fail2ban y limpia sus cadenas (corre dentro de lab-victim)
fail2ban-client stop 2>/dev/null || true
sleep 1
iptables -F f2b-SSH 2>/dev/null || true
iptables -F f2b-sshd 2>/dev/null || true
echo "f2b stopped"
