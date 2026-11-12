# Reference host for the profile generator and the default-tell checks (spec 1.3).
# Debian 12 with the real packages every MIRAGE decoy claims to be: OpenSSH, nginx, Redis and
# MariaDB from Debian's own archive. `make profile-ref` starts it, probes it and writes
# decoys/profiles/reference/debian-12.json. It never faces the internet: ports bind to 127.0.0.1.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server nginx redis-server mariadb-server procps iproute2 ca-certificates \
 && mkdir -p /run/sshd /run/mysqld && chown mysql:mysql /run/mysqld && ssh-keygen -A \
 # Kernel facts cannot come from a container (it shares the host's kernel). Record what the
 # archive's current kernel package is; the changelog date becomes uname's build date.
 && (apt-cache show linux-image-arm64 linux-image-amd64 2>/dev/null | grep -E '^(Package|Version|Depends):' > /ref-kernel.txt || true) \
 # linux-libc-dev is built from the same source package and carries its changelog; the top
 # entry's date is the build date uname prints (the kernel image itself is ~70 MB).
 && (cd /tmp && apt-get download linux-libc-dev \
     && dpkg-deb --fsys-tarfile linux-libc-dev_*.deb | tar -xO ./usr/share/doc/linux-libc-dev/changelog.Debian.gz \
        | gzip -dc | sed -n '1p;/^ -- /{p;q}' > /ref-kernel-changelog.txt; rm -f /tmp/*.deb) \
 && rm -rf /var/lib/apt/lists/*

# An exposed server is reachable from outside: listen on all addresses, as a misconfigured real
# one would. Everything else stays at Debian's defaults.
RUN sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf \
 && sed -i -e 's/^bind 127.0.0.1 -::1/bind 0.0.0.0/' -e 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf \
 && sed -i -e 's/^daemonize yes/daemonize no/' /etc/redis/redis.conf

COPY entrypoint.sh /entrypoint.sh
EXPOSE 22 80 3306 6379
CMD ["/bin/sh", "/entrypoint.sh"]
