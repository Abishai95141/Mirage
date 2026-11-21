#!/bin/sh
# Arm R: a real Debian host that the depth scenarios run against, as the ceiling the decoys
# are compared with. It takes from the deployment's profile (mounted read-only at /profile)
# what a real host of that description would have: its accounts, its web root and its
# identity files. Everything sent here really runs, so the container is thrown away after one
# scenario and has no network beyond the lab edge in front of it.
set -e
P=/profile

# Root may log in with a password, as on the decoy.
sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin yes/; s/^#?PasswordAuthentication.*/PasswordAuthentication yes/' \
  /etc/ssh/sshd_config

# Accounts from the profile's user database (user:x:password). A real host has one password
# per account: for root it is the first, which is the one the runner logs in with.
root_done=""
while IFS=: read -r user _ pass; do
  case "$user" in '' | '#'*) continue ;; esac
  case "$pass" in '' | '!'* | '*') continue ;; esac
  if [ "$user" = root ]; then
    [ -n "$root_done" ] && continue
    root_done=1
  elif ! id "$user" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$user"
  fi
  printf '%s:%s\n' "$user" "$pass" | chpasswd
done <"$P/cowrie/userdb.txt"
[ -n "$root_done" ] || { echo "the profile has no root password" >&2; exit 1; }

# The profile's files: the web root, and the identity files that hold no accounts.
if [ -d "$P/cowrie/honeyfs/var" ]; then
  cp -r "$P/cowrie/honeyfs/var/." /var/
fi
for f in machine-id issue issue.net debian_version; do
  if [ -f "$P/cowrie/honeyfs/etc/$f" ]; then cp "$P/cowrie/honeyfs/etc/$f" "/etc/$f"; fi
done

# The four services, as the reference image starts them, without its probe account.
/usr/sbin/sshd
nginx
su redis -s /bin/sh -c 'redis-server /etc/redis/redis.conf' &
mariadbd --user=mysql &
for _ in $(seq 1 60); do
  mariadb -e 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
touch /ready
wait
