#!/bin/sh
# Start the four reference services. A probe user lets the extractor run MariaDB queries; it
# uses mysql_native_password, as the decoy does.
set -e
/usr/sbin/sshd
nginx
su redis -s /bin/sh -c 'redis-server /etc/redis/redis.conf' &
mariadbd --user=mysql &
for i in $(seq 1 60); do mariadb -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
mariadb -e "CREATE USER IF NOT EXISTS 'probe'@'%' IDENTIFIED VIA mysql_native_password USING PASSWORD('probe');
            GRANT SELECT, INSERT, CREATE, DROP ON *.* TO 'probe'@'%';
            CREATE DATABASE IF NOT EXISTS probe;
            CREATE TABLE IF NOT EXISTS probe.t (id INT PRIMARY KEY, name VARCHAR(32));"
touch /ready
wait
