#!/bin/bash
set -euo pipefail
PC_IF="${PC_IF:-eth0}"
BOX_IF="${BOX_IF:-eth1}"
PREFIX=/opt/packetpy
PIN=/sys/fs/bpf/packetpy

if [ "$(id -u)" -ne 0 ]; then echo 'run as root (sudo)'; exit 1; fi

echo '[1/7] packages'
apt update
apt install -y clang llvm libbpf-dev bpftool iproute2 python3 linux-libc-dev

echo '[2/7] install files'
mkdir -p "$PREFIX" "$PREFIX/ebpf" "$PREFIX/scripts" "$PREFIX/config" "$PREFIX/panels" "$PREFIX/agent/static" "$PREFIX/var/logs"
cp packetpy.py "$PREFIX/packetpy.py"
cp boot.sh "$PREFIX/boot.sh"
cp ebpf/packetpy_vm.bpf.c "$PREFIX/ebpf/packetpy_vm.bpf.c"
cp scripts/main.ppy "$PREFIX/scripts/main.ppy"
cp scripts/template.ppy "$PREFIX/scripts/template.ppy"
cp config/fields.json "$PREFIX/config/fields.json"
cp config/fields.example.json "$PREFIX/config/fields.example.json"
cp config/README.md "$PREFIX/config/README.md"
cp DOCS.md "$PREFIX/DOCS.md" 2>/dev/null || true
cp agent/packetpyd.py "$PREFIX/agent/packetpyd.py"
cp agent/static/*.html "$PREFIX/agent/static/"
cp -r panels/. "$PREFIX/panels/" 2>/dev/null || true
chmod +x "$PREFIX/packetpy.py" "$PREFIX/boot.sh" "$PREFIX/agent/packetpyd.py"
ln -sf "$PREFIX/packetpy.py" /usr/local/bin/packetpy

echo '[3/7] compile eBPF'
ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64) TARGET_ARCH=arm64;;
  armv7l|armv6l) TARGET_ARCH=arm;;
  x86_64) TARGET_ARCH=x86;;
  *) echo "unsupported arch: $ARCH"; exit 1;;
esac
clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGET_ARCH} -I/usr/include/$(uname -m)-linux-gnu -c "$PREFIX/ebpf/packetpy_vm.bpf.c" -o "$PREFIX/ebpf/packetpy_vm.bpf.o"

echo '[4/7] bridge'
ip link set "$PC_IF" nomaster 2>/dev/null || true
ip link set "$BOX_IF" nomaster 2>/dev/null || true
ip link del br0 2>/dev/null || true
ip addr flush dev "$PC_IF" || true
ip addr flush dev "$BOX_IF" || true
ip link add br0 type bridge
ip link set dev br0 type bridge stp_state 0
ip link set "$PC_IF" master br0
ip link set "$BOX_IF" master br0
ip link set "$PC_IF" up
ip link set "$BOX_IF" up
ip link set br0 up

echo '[5/7] load + pin program/maps'
mkdir -p "$PIN/maps" "$PIN/progs"
rm -f "$PIN/progs"/* "$PIN/maps"/* 2>/dev/null || true
bpftool prog loadall "$PREFIX/ebpf/packetpy_vm.bpf.o" "$PIN/progs" type classifier pinmaps "$PIN/maps"
PROG=$(find "$PIN/progs" -type f | head -n1)
[ -n "$PROG" ] || { echo 'no pinned BPF program found'; exit 1; }

echo '[6/7] attach TC ingress on both bridge ports'
tc qdisc replace dev "$PC_IF" clsact
tc qdisc replace dev "$BOX_IF" clsact
tc filter replace dev "$PC_IF" ingress pref 10 handle 1 bpf da pinned "$PROG"
tc filter replace dev "$BOX_IF" ingress pref 10 handle 1 bpf da pinned "$PROG"

echo '[7/8] load default script + save device state'
packetpy check "$PREFIX/scripts/main.ppy"
packetpy load "$PREFIX/scripts/main.ppy" --pc-if "$PC_IF" --box-if "$BOX_IF"
mkdir -p "$PREFIX/var"
printf '{"active":"scripts/main.ppy","pc_if":"%s","box_if":"%s","debug":false,"attached":true}\n' "$PC_IF" "$BOX_IF" > "$PREFIX/var/state.json"

echo '[8/8] systemd services (autostart at boot + control agent)'
sed "s/^Environment=PC_IF.*//" systemd/packetpy.service > /etc/systemd/system/packetpy.service
cp systemd/packetpyd.service /etc/systemd/system/packetpyd.service
systemctl daemon-reload
systemctl enable packetpy.service packetpyd.service >/dev/null 2>&1 || true
systemctl restart packetpyd.service || true
TOKEN=$(cat "$PREFIX/var/token" 2>/dev/null || true)

echo
echo 'Installed.'
echo "Panel:  http://$(hostname).local:8080   (master panel)"
echo "Token:  ${TOKEN:-see $PREFIX/var/token}"
echo "Script: nano $PREFIX/scripts/main.ppy"
echo "Config: nano $PREFIX/config/fields.json"
echo "Check:  packetpy check $PREFIX/scripts/main.ppy"
echo "Load:   packetpy load $PREFIX/scripts/main.ppy --pc-if $PC_IF --box-if $BOX_IF"
echo "Stats:  packetpy stats"
echo "Docs:   $PREFIX/DOCS.md"
