#!/bin/bash
# packetpy boot setup: re-create the bridge, (re)load+pin the eBPF program,
# attach TC on both ports, and load the active script. Run at boot by
# packetpy.service. The BPF pin lives in tmpfs and is lost across reboots, so
# this re-establishes everything; it does NOT install packages or copy files.
set -uo pipefail
PREFIX=/opt/packetpy
PIN=/sys/fs/bpf/packetpy
STATE="$PREFIX/var/state.json"

jget(){ python3 - "$1" "$2" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")
except Exception: print("")
PY
}
PC_IF="$(jget "$STATE" pc_if)"; [ -n "$PC_IF" ] || PC_IF="${PC_IF_ENV:-eth0}"
BOX_IF="$(jget "$STATE" box_if)"; [ -n "$BOX_IF" ] || BOX_IF="${BOX_IF_ENV:-eth1}"
ACTIVE="$(jget "$STATE" active)"; [ -n "$ACTIVE" ] || ACTIVE="scripts/main.ppy"

echo "[boot] PC_IF=$PC_IF BOX_IF=$BOX_IF active=$ACTIVE"

# compile the object if missing
if [ ! -f "$PREFIX/ebpf/packetpy_vm.bpf.o" ]; then
  ARCH=$(uname -m); case "$ARCH" in aarch64|arm64) TA=arm64;; armv7l|armv6l) TA=arm;; x86_64) TA=x86;; *) TA=x86;; esac
  clang -O2 -g -target bpf -D__TARGET_ARCH_${TA} -I/usr/include/$(uname -m)-linux-gnu \
    -c "$PREFIX/ebpf/packetpy_vm.bpf.c" -o "$PREFIX/ebpf/packetpy_vm.bpf.o"
fi

# bridge
ip link del br0 2>/dev/null || true
ip addr flush dev "$PC_IF" 2>/dev/null || true
ip addr flush dev "$BOX_IF" 2>/dev/null || true
ip link add br0 type bridge 2>/dev/null || true
ip link set dev br0 type bridge stp_state 0
ip link set "$PC_IF" master br0; ip link set "$BOX_IF" master br0
ip link set "$PC_IF" up; ip link set "$BOX_IF" up; ip link set br0 up

# load + pin program/maps
mkdir -p "$PIN/maps" "$PIN/progs"
rm -f "$PIN/progs"/* "$PIN/maps"/* 2>/dev/null || true
bpftool prog loadall "$PREFIX/ebpf/packetpy_vm.bpf.o" "$PIN/progs" type classifier pinmaps "$PIN/maps"
PROG=$(find "$PIN/progs" -type f | head -n1)

# attach TC ingress on both ports
for IF in "$PC_IF" "$BOX_IF"; do
  tc qdisc replace dev "$IF" clsact
  tc filter replace dev "$IF" ingress pref 10 handle 1 bpf da pinned "$PROG"
done

# load the active script (fills the maps)
"$PREFIX/packetpy.py" load "$PREFIX/$ACTIVE" --pc-if "$PC_IF" --box-if "$BOX_IF" || \
  echo "[boot] warning: failed to load $ACTIVE"
echo "[boot] done"
