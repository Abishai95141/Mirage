#!/bin/sh
# From inside the reference host: can it reach each of these? One line per target, "connected"
# or "blocked". Used by tools/lab-host/arm-r-check.sh, which knows which answer is right.
for target in "$@"; do
  host=${target%:*}
  port=${target##*:}
  if timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
    echo "$target connected"
  else
    echo "$target blocked"
  fi
done
