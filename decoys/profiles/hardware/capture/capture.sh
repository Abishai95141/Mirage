#!/usr/bin/env bash
# Record what each hardware class says about itself, on a lab host with KVM.
#
#     decoys/profiles/hardware/capture/capture.sh [class ...]      (default: every class)
#
# Needs Docker and a /dev/kvm the user may open; no root. It downloads Debian 12's official
# "generic" cloud image once (about 430 MB, checked against Debian's published SHA-512) into
# ~/.cache/mirage-hw, builds the small QEMU image beside this file, and boots each class as a
# throwaway virtual machine with no network (run.py). What a class recorded is written to
# build/hardware/<class>/; `mirage-profile hardware` turns that into the committed class.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
hardware="$(dirname "$here")"
root="$(cd "$hardware/../../.." && pwd)"
cache="${MIRAGE_HW_CACHE:-$HOME/.cache/mirage-hw}"
out="$root/build/hardware"
image=debian-12-generic-amd64.qcow2
url=https://cloud.debian.org/images/cloud/bookworm/latest
mkdir -p "$cache" "$out"

if [ ! -f "$cache/$image" ]; then
    echo "fetching $image"
    curl -fL --retry 3 -o "$cache/$image.part" "$url/$image"
    want="$(curl -fsSL "$url/SHA512SUMS" | awk -v f="$image" '$2 == f {print $1}')"
    have="$(sha512sum "$cache/$image.part" | cut -d' ' -f1)"
    if [ -z "$want" ] || [ "$want" != "$have" ]; then
        echo "the image's SHA-512 is not the one Debian publishes; not using it" >&2
        exit 1
    fi
    mv "$cache/$image.part" "$cache/$image"
    echo "$have  $image" > "$cache/$image.sha512"
fi

docker build -q -t mirage/hwcapture:dev "$here" > /dev/null

[ "$#" -gt 0 ] || set -- $(cd "$hardware" && ls ./*.yaml | sed 's#^\./##; s#\.yaml$##')
for class in "$@"; do
    docker rm -f mirage-hwcapture > /dev/null 2>&1 || true
    docker run --name mirage-hwcapture --network none --device /dev/kvm \
        --user "$(id -u):$(id -g)" --group-add "$(stat -c %g /dev/kvm)" \
        -v "$cache:/images:ro" -v "$hardware:/hardware:ro" -v "$out:/out" \
        mirage/hwcapture:dev python3 /hardware/capture/run.py "/hardware/$class.yaml" "/images/$image" /out
    docker rm mirage-hwcapture > /dev/null
    cp "$cache/$image.sha512" "$out/$class/source.sha512"
done
