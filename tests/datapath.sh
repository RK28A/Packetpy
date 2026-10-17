#!/bin/bash
# Datapath integration test in a network namespace (no physical network touched).
# Proves: a field rewrite works end-to-end; a short payload is handled safely
# (bounds-guarded, no corruption); and a consistent hot reload keeps working.
# Requires root + a kernel with eBPF/TC. Run: sudo tests/datapath.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"; T="$(mktemp -d)"; PIN=/sys/fs/bpf/ppytest
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup(){ ip netns del nsB 2>/dev/null; ip link del vethA 2>/dev/null; rm -rf "$PIN" "$T"; }
trap cleanup EXIT

mount | grep -q 'bpf on /sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
echo "[setup] compiling + loading eBPF"
clang -O2 -g -target bpf -D__TARGET_ARCH_$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
  -I/usr/include/$(uname -m)-linux-gnu -c ebpf/packetpy_vm.bpf.c -o "$T/vm.o" || { echo "compile failed"; exit 1; }
rm -rf "$PIN"; mkdir -p "$PIN/progs" "$PIN/maps"
bpftool prog loadall "$T/vm.o" "$PIN/progs" type classifier pinmaps "$PIN/maps" || { echo "load failed"; exit 1; }
PROG=$(find "$PIN/progs" -type f | head -n1)

echo "[setup] veth + netns"
ip netns del nsB 2>/dev/null; ip link del vethA 2>/dev/null
ip netns add nsB
ip link add vethA type veth peer name vethB
ip link set vethB netns nsB
ip addr add 10.0.0.1/24 dev vethA; ip link set vethA up
ip netns exec nsB ip addr add 10.0.0.2/24 dev vethB; ip netns exec nsB ip link set vethB up; ip netns exec nsB ip link set lo up
tc qdisc replace dev vethA clsact
tc filter replace dev vethA ingress pref 10 handle 1 bpf da pinned "$PROG"

# config: header.value is a u16be at payload offset 4
cat > "$T/fields.json" <<JSON
{"default_udp_port":12345,"constants":{},"fields":{"header.value":{"kind":"u16be","offset":4}}}
JSON
LOAD(){ python3 -I packetpy.py load "$1" --config "$T/fields.json" --pc-if vethA --box-if lo \
  --prog-map "$PIN/maps/ppy_program" --state-map "$PIN/maps/ppy_state" \
  --config-map "$PIN/maps/ppy_config" --stats-map "$PIN/maps/ppy_stats" --reset-stats >/dev/null 2>&1; }
STAT(){ python3 -I packetpy.py stats --json --stats-map "$PIN/maps/ppy_stats" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',0))"; }

# ---- Case 1: field rewrite (value 5 -> 6) ----
cat > "$T/inc.ppy" <<PPY
hits = State(0)
@udp(port=12345)
def packet():
    hits += 1
    v = read_field("header.value", 0)
    write_field("header.value", 0, v + 1)
    accept()
PPY
LOAD "$T/inc.ppy"
python3 -I tests/_recv.py 10.0.0.1 12345 4 > "$T/out1" &
RC=$!; sleep 0.4
ip netns exec nsB python3 -I tests/_send.py 10.0.0.1 12345 0400000000050000 10.0.0.2 >/dev/null
wait $RC; GOT=$(cat "$T/out1")
# payload bytes 4-5 big-endian => value; expect 0006
if [ "${GOT:8:4}" = "0006" ]; then ok "field rewrite 5 -> 6 (got $GOT)"; else no "field rewrite (got $GOT)"; fi
[ "$(STAT modified)" -ge 1 ] && ok "modified counter incremented" || no "modified counter"
[ "$(STAT error)" -eq 0 ] && ok "no VM errors on valid packet" || no "unexpected VM error"

# ---- Case 2: short payload (2 bytes, field at offset 4) must be safe ----
LOAD "$T/inc.ppy"
python3 -I tests/_recv.py 10.0.0.1 12345 4 > "$T/out2" &
RC=$!; sleep 0.4
ip netns exec nsB python3 -I tests/_send.py 10.0.0.1 12345 0005 10.0.0.2 >/dev/null
wait $RC; GOT2=$(cat "$T/out2")
if [ "$GOT2" = "0005" ]; then ok "short payload delivered unchanged (got $GOT2)"; else no "short payload (got $GOT2)"; fi
[ "$(STAT error)" -ge 1 ] && ok "out-of-bounds read was bounds-guarded (error counted, no corruption)" || no "bounds guard did not fire"

# ---- Case 3: consistent hot reload to a pass-through script ----
cat > "$T/pass.ppy" <<PPY
@udp(port=12345)
def packet():
    accept()
PPY
LOAD "$T/pass.ppy"
python3 -I tests/_recv.py 10.0.0.1 12345 4 > "$T/out3" &
RC=$!; sleep 0.4
ip netns exec nsB python3 -I tests/_send.py 10.0.0.1 12345 0400000000050000 10.0.0.2 >/dev/null
wait $RC; GOT3=$(cat "$T/out3")
if [ "${GOT3:8:4}" = "0005" ]; then ok "after reload, passthrough leaves packet unchanged (got $GOT3)"; else no "passthrough after reload (got $GOT3)"; fi
[ "$(STAT modified)" -eq 0 ] && ok "passthrough does not modify" || no "passthrough modified a packet"

echo ""; echo "datapath tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
