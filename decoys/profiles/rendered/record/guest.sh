#!/bin/sh
# Run the render library's commands on this reference host and keep what each printed: on
# which stream, with which exit code, and how long it took. Runs once, as root, inside a
# throwaway reference container with no network (see record.sh). Reports only: the commands
# come from the render inventory, which lists nothing that changes a machine.
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
out=/record/out
rm -rf "$out"
mkdir -p "$out"
chmod 755 /record "$out"

n=0
grep -v '^#' /record/commands.txt | grep . | while IFS= read -r cmd; do
    n=$((n + 1))
    id=$(printf '%03d' "$n")
    verb=${cmd%% *}
    rest=${cmd#"$verb"}
    printf '%s\n' "$cmd" > "$out/$id.cmd"
    program=$(command -v "$verb" 2> /dev/null)
    printf '%s\n' "$program" > "$out/$id.program"
    [ -n "$program" ] || continue

    # As root, five times: the first run's output is the record, the times are all kept.
    times=""
    for run in 1 2 3 4 5; do
        t0=$(date +%s%N)
        # No locale variable at all, as in a session over SSH: `locale` itself is one of
        # the commands, and with LC_ALL set it would print this script's and not a host's.
        env -u LC_ALL -u LANG sh -c "$cmd" > "$out/$id.out.$run" 2> "$out/$id.err.$run" < /dev/null
        code=$?
        t1=$(date +%s%N)
        times="$times $(((t1 - t0) / 1000000))"
        [ "$run" = 1 ] && first=$code
    done
    mv "$out/$id.out.1" "$out/$id.out"
    mv "$out/$id.err.1" "$out/$id.err"
    # Whether the five runs printed the same: a command that does not is not a fixed answer.
    same=yes
    for run in 2 3 4 5; do
        cmp -s "$out/$id.out" "$out/$id.out.$run" && cmp -s "$out/$id.err" "$out/$id.err.$run" || same=no
        rm -f "$out/$id.out.$run" "$out/$id.err.$run"
    done
    printf '%s %s%s\n' "$first" "$same" "$times" > "$out/$id.meta"

    # Once as an account with no privileges, by the program's full path: is the answer the
    # same for any user, or root's alone?
    su -s /bin/sh nobody -c "unset LC_ALL LANG; $program$rest" > "$out/$id.user.out" 2> "$out/$id.user.err" < /dev/null
    printf '%s\n' "$?" > "$out/$id.user.code"
done

# What a server of this image can run: its shell's builtins and the programs on root's PATH.
# The inventory uses the list to tell a command the decoy lacks from one no server has.
{
    bash -c 'compgen -b'
    ls /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin 2> /dev/null | grep -v ':$' | grep .
} | sort -u > "$out/available.txt"

{
    echo "hostname=$(hostname)"
    echo "debian_version=$(cat /etc/debian_version)"
    echo "epoch=$(date +%s)"
    echo "arch=$(dpkg --print-architecture)"
} > "$out/identity.txt"
