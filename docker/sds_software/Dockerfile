FROM ubuntu@sha256:a4fab1802f08df089c4b2e0a1c8f1a06f573bd1775687d07fef4076d3a2e4900 as app
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip iputils-ping
RUN pip3 install pwntools
COPY . /app

FROM pwn.red/jail 
COPY --from=app / /srv
COPY hook.sh /jail/
ENV JAIL_MEM 4G
ENV JAIL_TIME 400
ENV JAIL_DEV null,zero,urandom