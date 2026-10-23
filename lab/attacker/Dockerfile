FROM alpine:3.20
RUN apk add --no-cache openssh-client sshpass python3 iproute2 tzdata
WORKDIR /opt
COPY attack.py /opt/attack.py
ENTRYPOINT ["sleep", "infinity"]
