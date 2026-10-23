FROM alpine:3.20

RUN apk add --no-cache \
      openssh \
      openssh-client \
      iptables \
      iproute2 \
      python3 \
      fail2ban \
      busybox-extras \
      apache2 \
      tzdata

# usuario cuyas credenciales fallidas usaremos como "Failed password for testuser"
RUN adduser -D -s /bin/sh testuser \
 && echo 'testuser:CorrectHorseBattery' | chpasswd

# Apache: access log combined a /var/log/apache_access/all.log (thesis), error separado.
# Los directorios se crean en entrypoint (el bind mount /var/log reemplaza el arbol).
RUN sed -i 's#^ErrorLog logs/error.log#ErrorLog /var/log/apache_access/error.log#' /etc/apache2/httpd.conf \
 && sed -i 's#^[[:space:]]*CustomLog logs/access.log combined#CustomLog /var/log/apache_access/all.log combined#' /etc/apache2/httpd.conf \
 && grep -q '/var/log/apache_access/all.log combined' /etc/apache2/httpd.conf \
 && grep -q 'ErrorLog /var/log/apache_access/error.log' /etc/apache2/httpd.conf

COPY sshd_config /etc/ssh/sshd_config
COPY block_agent.py /opt/block_agent.py
COPY scan_logger.py /opt/scan_logger.py
COPY entrypoint.sh /opt/entrypoint.sh
COPY jail.local /etc/fail2ban/jail.local
RUN chmod +x /opt/entrypoint.sh /opt/block_agent.py /opt/scan_logger.py

EXPOSE 22 80 9000
ENTRYPOINT ["/opt/entrypoint.sh"]
