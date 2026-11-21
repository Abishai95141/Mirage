#!/bin/sh
# Describe this machine: the kernel's own files and directories, and what the reporting
# commands print. Runs once, as root, in a throwaway virtual machine (see run.py), sends
# everything out through the serial console and powers the machine off.
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
out=/root/capture
rm -rf "$out"
mkdir -p "$out/proc" "$out/commands"
sleep 25 # let the boot finish: the load settles and the services are up

# The kernel's files that say what the machine is.
for f in cpuinfo meminfo version cmdline partitions swaps mounts filesystems modules devices \
    loadavg uptime stat diskstats interrupts iomem ioports misc consoles cgroups crypto \
    net/dev net/arp net/route sys/kernel/osrelease sys/kernel/ostype sys/kernel/version \
    sys/kernel/random/boot_id sys/kernel/pid_max sys/vm/swappiness self/mountinfo; do
    mkdir -p "$out/proc/$(dirname "$f")"
    cat "/proc/$f" > "$out/proc/$f" 2> /dev/null
done

# Listings: type, mode, owner, group, size, change time, path, link target.
fmt='%y\t%m\t%U\t%G\t%s\t%T@\t%p\t%l\n'
find /dev -printf "$fmt" > "$out/dev.tsv" 2> /dev/null
find /proc -maxdepth 3 -not -path '/proc/[0-9]*' -not -path '/proc/self/*' \
    -not -path '/proc/thread-self/*' -printf "$fmt" > "$out/proc.tsv" 2> /dev/null
find /sys -maxdepth 7 -printf "$fmt" 2> /dev/null | gzip -9 > "$out/sys.tsv.gz"
find /boot /lib/modules -maxdepth 2 -printf "$fmt" > "$out/boot.tsv" 2> /dev/null
find /run -maxdepth 2 -printf "$fmt" > "$out/run.tsv" 2> /dev/null

# Small files under /sys that programs read to learn the hardware.
: > "$out/sysfiles.tsv"
for f in /sys/class/dmi/id/* /sys/devices/system/cpu/online /sys/devices/system/cpu/possible \
    /sys/devices/system/cpu/present /sys/devices/system/cpu/cpu*/topology/* \
    /sys/devices/system/cpu/cpu*/cache/index*/size /sys/devices/system/cpu/vulnerabilities/* \
    /sys/block/*/size /sys/block/*/queue/rotational /sys/block/*/device/model \
    /sys/block/*/device/vendor /sys/class/net/*/address /sys/class/net/*/mtu \
    /sys/class/net/*/operstate /sys/class/net/*/speed /sys/hypervisor/type \
    /sys/kernel/mm/transparent_hugepage/enabled /sys/class/block/*/dev; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    printf '%s\t%s\n' "$f" "$(head -c 400 "$f" 2> /dev/null | tr '\n\t' '  ')" >> "$out/sysfiles.tsv"
done

# The reporting commands: what each printed, on which stream, its exit code and its time.
n=0
grep -v '^#' /root/commands.txt | grep . | while IFS= read -r cmd; do
    n=$((n + 1))
    id=$(printf '%03d' "$n")
    printf '%s\n' "$cmd" > "$out/commands/$id.cmd"
    t0=$(date +%s%N)
    sh -c "$cmd" > "$out/commands/$id.out" 2> "$out/commands/$id.err" < /dev/null
    code=$?
    t1=$(date +%s%N)
    printf '%s %s\n' "$code" "$(((t1 - t0) / 1000000))" > "$out/commands/$id.meta"
done

# This machine's own values, so they can be told from what its class fixes.
{
    echo "hostname=$(hostname)"
    echo "machine_id=$(cat /etc/machine-id)"
    echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
    echo "kernel_release=$(uname -r)"
    echo "kernel_version=$(uname -v)"
    echo "epoch=$(date +%s)"
    echo "uptime_s=$(cut -d' ' -f1 /proc/uptime)"
    printf 'commands='
    ls /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin 2> /dev/null |
        grep -v ':$' | grep . | sort -u | tr '\n' ' '
    echo
} > "$out/identity.txt"

# Out through the serial console, the one way out of a machine with no network and no second
# disk, then off.
tar -C /root -czf /root/capture.tgz capture
{
    echo "=====MIRAGE-CAPTURE-BEGIN====="
    base64 -w 76 /root/capture.tgz
    echo "=====MIRAGE-CAPTURE-END====="
} > /dev/ttyS0
sync
systemctl poweroff
