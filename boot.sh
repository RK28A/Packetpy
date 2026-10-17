#!/bin/bash
# packetpy boot setup (run at boot by packetpy.service). Re-create the bridge,
# (re)load+pin the eBPF program, attach TC, and load the active script.
#
# Safety: idempotent, never blindly destroys an unrelated bridge, backs up the
# network state first, and falls back to a plain pass-through bridge (traffic
# still flows, unmodified) if the eBPF program cannot be loaded — so a bad script
# or update never leaves the device cutting the link it sits on.
set -uo pipefail
PREFIX=/opt/packetpy
PIN=/sys/fs/bpf/packetpy
STATE="$PREFIX/var/state.json"
BK="$PREFIX/var/net-backup.json"

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

# 0. interfaces must exist — never touch the network otherwise
for IF in "$PC_IF" "$BOX_IF"; do
  if [ ! -e "/sys/class/net/$IF" ]; then
    echo "[boot] interface $IF missing — aborting without changing the network"; exit 1
  fi
done

# 1. back up current network state (best effort) for recovery
mkdir -p "$PREFIX/var"
python3 - "$BK" "$PC_IF" "$BOX_IF" <<'PY' 2>/dev/null || true
import json,subprocess,sys
bk,pc,box=sys.argv[1],sys.argv[2],sys.argv[3]
def j(c):
    try: return json.loads(subprocess.run(c,capture_output=True,text=True).stdout or "[]")
    except Exception: return []
json.dump({"addr":j(["ip","-j","addr"]),"route":j(["ip","-j","route"]),
           "pc_if":pc,"box_if":box}, open(bk,"w"))
PY

# 2. compile the object if missing
if [ ! -f "$PREFIX/ebpf/packetpy_vm.bpf.o" ]; then
  ARCH=$(uname -m); case "$ARCH" in aarch64|arm64) TA=arm64;; armv7l|armv6l) TA=arm;; x86_64) TA=x86;; *) TA=x86;; esac
  clang -O2 -g -target bpf -D__TARGET_ARCH_${TA} -I/usr/include/$(uname -m)-linux-gnu \
    -c "$PREFIX/ebpf/packetpy_vm.bpf.c" -o "$PREFIX/ebpf/packetpy_vm.bpf.o" || echo "[boot] eBPF compile failed"
fi

# 3. bridge (idempotent): create br0 only if absent; enslave ports only if needed
bridge_up(){
  if ! ip link show br0 >/dev/null 2>&1; then
    ip link add br0 type bridge && ip link set dev br0 type bridge stp_state 0
  fi
  for IF in "$PC_IF" "$BOX_IF"; do
    master=$(cat "/sys/class/net/$IF/master/ifindex" 2>/dev/null || echo "")
    br=$(cat /sys/class/net/br0/ifindex 2>/dev/null || echo "x")
    if [ "$master" != "$br" ]; then
      ip addr flush dev "$IF" 2>/dev/null || true
      ip link set "$IF" master br0
    fi
    ip link set "$IF" up
  done
  ip link set br0 up
}
bridge_up

# 4. load + pin program/maps, attach TC; fall back to pass-through on failure
attach_ebpf(){
  [ -f "$PREFIX/ebpf/packetpy_vm.bpf.o" ] || return 1
  mkdir -p "$PIN/maps" "$PIN/progs"
  rm -f "$PIN/progs"/* "$PIN/maps"/* 2>/dev/null || true
  bpftool prog loadall "$PREFIX/ebpf/packetpy_vm.bpf.o" "$PIN/progs" type classifier pinmaps "$PIN/maps" || return 1
  PROG=$(find "$PIN/progs" -type f | head -n1); [ -n "$PROG" ] || return 1
  for IF in "$PC_IF" "$BOX_IF"; do
    tc qdisc replace dev "$IF" clsact || return 1
    tc filter replace dev "$IF" ingress pref 10 handle 1 bpf da pinned "$PROG" || return 1
  done
  return 0
}
if attach_ebpf; then
  "$PREFIX/packetpy.py" load "$PREFIX/$ACTIVE" --pc-if "$PC_IF" --box-if "$BOX_IF" \
    || echo "[boot] warning: failed to load $ACTIVE (datapath attached, running previous/empty program)"
  echo "[boot] done (eBPF active)"
else
  echo "[boot] eBPF attach failed — leaving a plain pass-through bridge so traffic still flows"
  echo "[boot] done (PASS-THROUGH; run 'packetpy network status' to inspect)"
fi
