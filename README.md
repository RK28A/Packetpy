# PacketPy v0.4 — Generic Packet Modifier

PacketPy is a generic transparent packet-modification framework built around a Linux bridge, TC/eBPF and a small script language called **PyNet**. It contains no application-specific offsets, message IDs or assumptions: you describe the packet fields you care about and write a short PyNet script that reads and rewrites them in flight. A Raspberry Pi sits inline on the cable; you control it from any PC on the LAN at **http://packetpy.local:8080**.

- 🚀 **New? Start here: [GETTING_STARTED.md](GETTING_STARTED.md)** — a zero-to-running walkthrough, including what hardware to buy.
- 📖 **Full documentation: [DOCS.md](DOCS.md)** — PyNet language reference, config, panels, how they interconnect, the packet-targeting model, loops/limits, CLI and API.
- 🧰 **Setup for any OS: [setup/](setup/)** — one script per platform.

## Install (Raspberry Pi / Linux)

```bash
git clone https://github.com/RK28A/Packetpy.git
cd Packetpy
sudo ./setup/raspberry.sh          # asks which interfaces, installs everything
```
Then open **http://packetpy.local:8080** from any PC on the network and paste the API token the installer printed. On Windows, run `python3 setup/scaffold.py` to set up the editing side (the packet datapath itself runs only on the Pi/Linux).

## Recommended hardware

A transparent bridge needs **two** Ethernet ports, so every build is a Pi + one USB Ethernet adapter. Pick the chipsets below — they work on Raspberry Pi OS with no drivers.

| Tier | Board | Second port (USB adapter) | For |
|---|---|---|---|
| 🟢 Cheapest | Raspberry Pi 3B+ | USB 2.0, **ASIX AX88772** | ~100 Mbps links |
| 🔵 Mid-range *(recommended)* | Raspberry Pi 4 (2–4 GB) | USB 3.0 gigabit, **Realtek RTL8153** / **ASIX AX88179** | full gigabit, best value |
| 🔴 High-end | Raspberry Pi 5 (4–8 GB) + cooler | USB 3.0 2.5GbE, **Realtek RTL8156** | lowest latency, 2.5 Gbps headroom |

Plus: A2 microSD, official power supply, two short Cat6 cables. Full buying notes in [GETTING_STARTED.md](GETTING_STARTED.md).

Release history is in [CHANGELOG.md](CHANGELOG.md).

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
