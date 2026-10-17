# PacketPy v0.3 — Generic Packet Modifier

PacketPy is a generic transparent packet-modification framework built around a Linux bridge, TC/eBPF and a small script language. It contains no application-specific offsets, message IDs or assumptions: you describe the packet fields you care about and write a short script that reads and rewrites them in flight.

## What changed in v0.3

- **Fixed:** the eBPF program now actually loads. The v0.2 VM advertised 128 instructions but was rejected by the kernel verifier (instruction-budget blow-up); the limit is now a verifier-safe `64`.
- **Fixed:** `packetpy check/build/load` crashed with a `NameError` (`proto` undefined). Compilation works now.
- **Fixed:** `install.sh` referenced a non-existent `scripts/example.ppy`.
- **New debug:** runtime packet counters (`packetpy stats`), a `--debug` flag and `packetpy debug on|off` for kernel `trace_pipe` output, and a `log("label", value)` statement.
- **New language:** `//` and `%` (integer div/mod), ternary `a if cond else b`, `clamp(x, lo, hi)`, `rand()`, `now()`, `ip.ttl`, annotated disassembly, and a `packetpy disasm` command.

## Layout

```text
/opt/packetpy/
├── packetpy.py
├── config/
│   ├── fields.json          <- your named packet fields/constants
│   ├── fields.example.json  <- neutral syntax examples
│   └── README.md
├── scripts/
│   ├── main.ppy             <- active packet script
│   └── template.ppy         <- blank starter
└── ebpf/
    └── packetpy_vm.bpf.c
```

## Install

```text
Endpoint A -> eth0 [ Raspberry Pi ] eth1 -> Endpoint B
```

```bash
sudo PC_IF=eth0 BOX_IF=eth1 ./install.sh
```

Keep administration on another interface such as `wlan0` if desired.

## Configure named packet fields

Edit:

```bash
sudo nano /opt/packetpy/config/fields.json
```

Example:

```json
{
  "constants": {
    "TARGET_PORT": 12345,
    "TYPE_STATUS": 4
  },
  "fields": {
    "header.type":  {"kind":"u8", "offset":0},
    "header.seq":   {"kind":"u16le", "offset":1},
    "header.flags": {"kind":"bits", "offset":24, "width":4}
  }
}
```

## Script

Edit:

```bash
sudo nano /opt/packetpy/scripts/main.ppy
```

Named access:

```python
base = 0
type_value = read_field("header.type", base)
seq = read_field("header.seq", base)
write_field("header.seq", base, seq + 1)
```

Raw access remains available:

```python
payload.u8(offset)
payload.u16le(offset)
payload.u16be(offset)
payload.bits(bit_offset, width)

payload.set_u8(offset, value)
payload.set_u16le(offset, value)
payload.set_u16be(offset, value)
payload.set_bits(bit_offset, width, value)
```

Metadata:

```python
direction
PC_TO_BOX
BOX_TO_PC
udp.src_port
udp.dst_port
ip.src
ip.dst
ip.ttl
payload_len
```

Operators and builtins:

```python
+ - * // %        # arithmetic (// and % are integer div/mod)
& | ^ << >> ~     # bitwise
== != < <= > >=   # comparisons (yield 0/1)
and or not        # boolean
min(a, b)  max(a, b)  abs(x)  clamp(x, lo, hi)
rand()            # 32-bit pseudo-random (bpf_get_prandom_u32)
now()             # monotonic nanoseconds (bpf_ktime_get_ns)
value_a if cond else value_b   # ternary
```

Control flow: `if` / `elif` / `else`, and `for i in range(...)` (unrolled, ≤ 32 iterations).

Persistent scalar state:

```python
counter = State(0)
counter += 1
```

Debug logging (increments the `trace` counter; the label prints under `--debug`):

```python
log("got status packet", seq)
```

## Check, load, inspect

```bash
sudo packetpy check  /opt/packetpy/scripts/main.ppy
sudo packetpy disasm /opt/packetpy/scripts/main.ppy
sudo packetpy load   /opt/packetpy/scripts/main.ppy --pc-if eth0 --box-if eth1
sudo packetpy load   /opt/packetpy/scripts/main.ppy --pc-if eth0 --box-if eth1 --debug --reset-stats
sudo packetpy stats
sudo packetpy stats --json
sudo packetpy debug on     # then: sudo cat /sys/kernel/debug/tracing/trace_pipe
sudo packetpy debug off
```

The field configuration is loaded automatically from `/opt/packetpy/config/fields.json`.

### Runtime counters (`packetpy stats`)

| counter    | meaning                                             |
|------------|-----------------------------------------------------|
| `seen`     | matching UDP packets that ran the VM                |
| `accept`   | packets passed through (`accept()` / fall-through)  |
| `drop`     | packets dropped (`drop()`)                          |
| `modified` | packets whose payload was rewritten                 |
| `error`    | VM aborts (out-of-bounds access, bad opcode)        |
| `trace`    | `log(...)` statements executed                      |

## Current VM limits

- IPv4 / UDP
- fixed packet length
- **64** PacketPy VM instructions (verifier-bounded)
- 24 VM registers
- 64 scalar `State()` slots
- `for range(...)` unrolled to at most 32 iterations
- bit reads/writes up to 16 bits

When the payload is rewritten, the UDP checksum is zeroed (checksum-disabled, valid for IPv4/UDP) so the modified packet is accepted without recomputation. These limits keep the runtime bounded for eBPF.
