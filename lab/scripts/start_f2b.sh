#!/bin/sh
# Inicia Fail2ban (corre dentro de lab-victim)
if fail2ban-client status >/dev/null 2>&1; then
  echo "f2b already running"
  exit 0
fi
fail2ban-client -x start 2>&1 | tail -1
echo "f2b started"
