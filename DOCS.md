# PacketPy — Complete Documentation

PacketPy is a transparent UDP packet modifier. A small Linux box (e.g. a
Raspberry Pi) sits as a bridge between two endpoints; every matching UDP packet
runs a tiny program in the kernel (TC/eBPF) that can read and rewrite its
fields in flight. You write that program in a simple Python-like language; it is
compiled to eBPF bytecode when the machine boots, so the datapath stays in the
kernel with no added latency.

```
Endpoint A ── eth0 [ Raspberry Pi: PacketPy ] eth1 ── Endpoint B
                         │
             master panel + per-script panels (web, on the LAN)
```

Contents:
1. [How targeting works — am I modifying the right app?](#1-targeting)
2. [The three building blocks and how they interconnect](#2-building-blocks)
3. [Script language reference](#3-language)
4. [Config reference (`fields.json`)](#4-config)
5. [Script panels](#5-panels)
6. [Create a whole system at once](#6-new-system)
7. [Loops, limits, and the single-thread reality](#7-loops)
8. [CLI reference](#8-cli)
9. [Agent / REST API](#9-api)
10. [Performance](#10-performance)

---

## 1. Targeting
### How do I know I'm modifying the right app's packets?

Four independent things decide *which* bytes of *which* app you touch. Get all
four right and you are editing exactly the packets you mean; get one wrong and
you either see nothing or corrupt the wrong data.

**1. Physical placement — which machines.**
PacketPy only ever sees traffic that physically crosses the bridge. Put the Pi
inline on the cable between the target machine and whatever it talks to. If the
target PC is on `eth0` and the server/console/box is on `eth1`, only that
conversation passes through. Traffic that never crosses the bridge is invisible
to PacketPy. This is what selects the *devices*.

**2. UDP port — which app/protocol.**
`@udp(port=N)` runs your script only for packets whose UDP source **or**
destination port is `N`. Apps and games use known ports (e.g. a game server on
27015). The port is what selects the *application*. If you edit the wrong port,
your script simply never runs on the traffic you care about — `seen` stays 0 in
the stats.

**3. Direction — which way.**
`direction` is `PC_TO_BOX` for packets arriving on the PC-side interface and
`BOX_TO_PC` for the other side. Use it when a field only means something in one
direction (e.g. only rewrite client→server packets).

**4. Field offsets — which bytes inside the payload.**
The config (`fields.json`) says where each field is inside the UDP payload
(`offset`, `kind`). This is the part you must get from the app's actual packet
format — PacketPy is application-neutral and ships with no offsets. You find
offsets by capturing the app's traffic (Wireshark/tcpdump) and inspecting the
UDP payload, or from protocol docs. A wrong offset means you read/write the
wrong bytes; the packet still "matches" (port is right) but your edit lands in
the wrong place.

**So, concretely, the chain is:**

| Question | Decided by |
|---|---|
| Which two machines? | where the Pi is wired in (eth0/eth1) |
| Which app? | the UDP **port** in `@udp(port=…)` |
| Which direction? | `direction` (`PC_TO_BOX` / `BOX_TO_PC`) |
| Which bytes? | the **offsets** in the config |
| What to do with them? | the **script** |

**How to verify you're on the right packets (do this before trusting a script):**
- Load the script and watch `packetpy stats` (or the master panel Overview).
  If `seen` climbs when the app is active, your placement + port are right.
  If `seen` stays 0, the traffic isn't crossing the bridge or the port is wrong.
- Turn on debug (`packetpy load … --debug`, or the Debug button) and read the
  kernel trace: `sudo cat /sys/kernel/debug/tracing/trace_pipe`. You'll see one
  line per matched packet with direction and ports — confirm they match the app.
- Add a `log("value", read_field("header.value", 0))` and compare the logged
  numbers against what Wireshark shows at the same offset. If they match, your
  offsets are correct; if not, fix the config, not the script.

Common pitfalls: editing on the wrong port (script never runs); right port but
wrong offset (you corrupt unrelated bytes — the app may reject or crash);
forgetting direction (you rewrite the reply as well as the request); the UDP
length being variable (PacketPy assumes a fixed layout — guard reads with
`payload_len`).

---

## 2. Building blocks
PacketPy has three kinds of thing. They live in separate folders and point at
each other by name.

```
/opt/packetpy/
├── scripts/         (A) packet scripts        — the .ppy code that edits packets
├── config/          (B) field configs         — where fields live in the packet
└── panels/          (C) script panels         — named groups of scripts + a web page
    └── <name>/
        ├── panel.json
        └── scripts/*.ppy
```

**(A) Script** — one `.ppy` file. Declares a UDP port and a `packet()` function
that reads/writes fields and decides `accept()` / `drop()`. This is the only
part that runs in the kernel.

**(B) Config** — one JSON file. Names the packet fields (offset + kind) and
integer constants your scripts use, and records which `linked_script` and
`linked_panel` this packet format belongs to. The active config is
`config/fields.json`; a script compiles against it automatically.

**(C) Script panel** — a folder under `panels/` with a `panel.json` (title +
categories) and its own `scripts/`. It gets a web page with start/stop/reload
buttons, grouped by category.

### How they interconnect
- A **script** names a **port** in `@udp(port=…)`. A **config** names the same
  port in `default_udp_port` and defines the fields at that port's layout. The
  script calls `read_field("header.x", base)` — the name `header.x` is resolved
  from the config. That's the script↔config link.
- A **config** records `linked_script` and `linked_panel` so the master panel's
  **Systems** tab can show the full chain: *config ↔ script ↔ panel* in one row.
- A **script panel** owns a set of scripts in its `scripts/` folder. Opening the
  panel page lets you start/stop/reload each one.
- Only **one** script is loaded into the kernel at a time (one bridge, one
  program). "Start" a script makes it the active one (replacing the previous);
  "Stop" detaches the datapath entirely. Panels are organization + controls, not
  parallel execution.

---

## 3. Language
The scripting language is called **PyNet**. A `.ppy` script is a restricted,
Python-like language compiled to eBPF.

### Structure
```python
packets = State(0)          # persistent counters (survive between packets)

@udp(port=12345)            # required: which UDP port this script handles
def packet():               # required: runs once per matching packet
    packets += 1
    base = 0                # byte offset the named fields are relative to
    ...
    accept()                # or drop()
```
Exactly one `@udp(port=…)` function. You may also define helper functions that
contain a single `return <expr>` (inlined at the call site).

### Values and variables
- 64-bit integers only. `True`/`False` are `1`/`0`.
- Assign with `x = <expr>`; variables live in VM registers (max 24 in use).
- `State(n)` declares a persistent 64-bit slot initialised to `n` (max 64).
  Assigning/`+=` to it reads/writes the kernel map, so values persist across
  packets (e.g. counters, last-seen values).

### Operators
```
+  -  *  //  %        arithmetic   (// and % are integer div/mod; ÷0 yields 0)
&  |  ^  <<  >>  ~     bitwise
== != <  <= >  >=      comparisons  (yield 1/0)
and  or  not           boolean
a if cond else b       conditional (ternary)
a < b < c              chained comparison  (== (a < b) and (b < c))
```
Multiple assignment works too: `a = b = 0`.

### Control flow
```python
if x == 1:
    ...
elif x == 2:
    ...
else:
    ...

for i in range(4):       # counted loop, unrolled; up to 32 iterations
    total += payload.u8(i)

while cond:              # bounded loop: unrolled up to 8 checks (see §7)
    ...
    if done:
        break            # break works in for and while
```
There is no unbounded `while` and no recursion — the kernel forbids them (§7).

### Built-in functions
```
min(a, b, ...)   max(a, b, ...)   abs(x)   clamp(x, lo, hi)   # min/max take 2+ args
swap16(x)                # swap the two bytes of a 16-bit value (endianness flip)
rand()                   # 32-bit pseudo-random
now()                    # monotonic time in nanoseconds
log("label", value)      # record a trace marker; prints under --debug,
                         # and increments the `trace` stat counter
accept()  /  pass_packet()   # let the packet through
drop()                       # drop the packet
```

### Live controls (panel widgets)
Declare controls at the top level; the panel renders them as widgets you can
change **while the script runs**, with no recompile or reload. Reading the name
in the script gives the current value (read-only in the script).

```python
speed   = Param(2, min=1, max=8, step=1, label="Speed", group="Movement")  # slider
enabled = Toggle(True, label="Enabled", group="Movement")                  # on/off switch
mode    = Choice("fast", ["fast", "slow", "turbo"], label="Mode")          # dropdown (value = index)
level   = Number(50, min=0, max=100, step=5)                               # numeric input
reset   = Button(label="Reset now")                                        # momentary pulse (1 then back to 0)
```
- `group="..."` puts controls into a named, collapsible bubble on the panel.
- Up to 32 controls per script. Values live in the `ppy_params` map; the panel
  writes them live (and they survive a reload — last value is remembered).
- `Choice` with string options stores the selected index; with int options it
  stores the int. `Button` reads as `1` briefly after a click.
- CLI: `packetpy param <slot> <value>` sets one live; `packetpy load … --param slot=value` presets.

### Named field access (uses the config)
```python
v = read_field("header.value", base)       # read a field defined in fields.json
write_field("header.value", base, v + 1)   # write it back
```
`base` is a byte offset into the UDP payload that the field's `offset` is added
to (usually `0`). For `bits` fields, `base` is still given in bytes and
converted internally.

### Raw payload access (no config needed)
```python
payload.u8(off)      payload.u16le(off)   payload.u16be(off)   payload.bits(bitoff, width)
payload.set_u8(off, v)   payload.set_u16le(off, v)   payload.set_u16be(off, v)   payload.set_bits(bitoff, width, v)
```

### Metadata (no config needed)
```
direction      PC_TO_BOX / BOX_TO_PC
udp.src_port   udp.dst_port
ip.src         ip.dst          ip.ttl
payload_len                         # UDP payload length in bytes
```

### Constants
Integer constants declared in the config's `constants` block are usable by name
in any script (e.g. `TARGET_PORT`, `TYPE_STATUS`). `PC_TO_BOX`/`BOX_TO_PC` are
always available.

---

## 4. Config
`config/fields.json` is the active config. Schema:

```json
{
  "name": "my packet format",
  "version": 1,
  "transport": "UDP",
  "default_udp_port": 12345,
  "constants": { "TARGET_PORT": 12345, "TYPE_STATUS": 4 },
  "fields": {
    "header.type":  { "kind": "u8",    "offset": 0 },
    "header.seq":   { "kind": "u16le", "offset": 1 },
    "header.flags": { "kind": "bits",  "offset": 24, "width": 4 },
    "header.value": { "kind": "u16be", "offset": 4 }
  },
  "linked_script": "scripts/main.ppy",
  "linked_panel":  "gmod"
}
```

- **kind**: `u8`, `u16le`, `u16be`, or `bits`.
- **offset**: byte offset for `u8/u16le/u16be`; **bit** offset for `bits`.
- **width**: 1–16, required for `bits`.
- **constants**: integer names usable in scripts.
- **linked_script / linked_panel**: pure metadata the master panel's Systems tab
  reads to show how this packet format, its script, and its panel connect. They
  don't change runtime behavior; the actual script↔config link is the shared
  UDP port plus the field names the script calls.

`config/fields.example.json` is a syntax reference only.

---

## 5. Panels
A **script panel** is a named folder under `panels/` with its own web page.

```
panels/<name>/
  panel.json
  scripts/*.ppy
```

`panel.json` (all customization fields):
```json
{
  "name": "gmod",
  "title": "GMod traffic",
  "description": "Scripts that touch the game's UDP traffic.",
  "accent": "#36d1b7",
  "layout": "rail",
  "categories": [
    { "id": "general", "label": "General", "color": "#36d1b7" },
    { "id": "testing", "label": "Testing", "color": "#c8871b" }
  ],
  "assign": { "speed.ppy": "general", "wip.ppy": "testing" }
}
```

| Field | Meaning |
|---|---|
| `title` | Heading shown on the panel page |
| `description` | One-line subtitle under the title |
| `accent` | Hex accent color for this panel's UI |
| `layout` | `"rail"` (categories on the left) or `"top"` (categories as a top bar) |
| `categories` | List of `{id, label, color}`; the color shows as a dot on the tab |
| `assign` | Maps each script filename to a category id |

- Open a panel at `http://packetpy.local:8080/panel/<name>`.
- Each script card has **Start / Reload / Stop** buttons. Starting a script makes
  it the single active datapath program.
- Edit everything above live from the panel page's **Customize** button (title,
  description, accent, layout, add/rename/recolor categories, assign scripts) —
  it saves `panel.json` via `POST /api/panel`. Every change is written to the
  `system` log.
- Create panels from the master panel (**Panels → Create panel**), with **+ New
  system**, or by hand.
- The master panel's **Systems** tab links each config to its script and panel.

---

## 6. New system
The master panel's **+ New system** button creates all three pieces at once and
wires them:

1. a **script** (`scripts/<name>.ppy`, or inside a panel if you name one),
   pre-filled with `@udp(port=…)` and a `packet()` stub;
2. a **config** (`config/<name>.json`) with that `default_udp_port` and empty
   `fields`, its `linked_script`/`linked_panel` already filled in;
3. the **panel** (created if it doesn't exist yet).

Pick the script name and UDP port, optionally a panel, leave "Link" checked, and
Create. You land in Files with the new script ready to edit. (CLI/automation:
`POST /api/system/new`, see §9.)

---

## 7. Loops
### Limits and the single-thread reality

The kernel runs your program **once per packet, on one CPU, with no loops the
verifier can't bound**. That's what makes it fast (no userspace copy, no
threads to coordinate) and it's also the hard constraint:

- A program is at most **64 VM instructions**. The compiler counts as it emits;
  if a script (usually an unrolled loop) goes over, **compilation fails and the
  script will not load** — the datapath keeps running whatever was loaded
  before. So an oversized loop can never be "launched"; it's rejected up front.
- `for i in range(N)` is unrolled, so `N ≤ 32` **and** `N × (body size)` must
  fit in 64 instructions.
- `while cond` is unrolled up to **8** condition-checks. Use it for short
  convergent loops; for counted scans prefer `for`.

**"Can you dual-thread the loop?"** No — and it's worth being precise about why:
a single packet is processed start-to-finish on one core inside the kernel's
hook; there is no second thread to hand half the loop to, and adding one would
mean copying the packet to userspace, which is exactly the latency you're trying
to avoid. Threads don't help a per-packet budget.

**The real way to do "more work than one pass allows"** is to spread it across
packets using `State()`, which persists between packets:

```python
# Instead of scanning the whole payload in one packet (too many instructions),
# advance a cursor a little each packet and accumulate in persistent state.
cursor = State(0)
acc    = State(0)

@udp(port=12345)
def packet():
    i = cursor
    end = min(i + 4, payload_len)       # do a small chunk this packet
    while i < end:                      # small bounded loop
        acc += payload.u8(i)
        i += 1
    cursor = i if i < payload_len else 0
    accept()
```

This keeps every individual packet's program tiny (fast, verifiable) while the
work completes over several packets. It's the eBPF-native equivalent of
"splitting the loop" — across packets instead of across threads.

If you genuinely need unbounded loops or a full language, that requires a
userspace datapath (NFQUEUE/AF_XDP) and pays per-packet latency; PacketPy
deliberately stays in-kernel for speed.

---

## 8. CLI
`packetpy` (installed as `/usr/local/bin/packetpy`):

```
packetpy check  <script.ppy>              compile and print bytecode + metadata
packetpy disasm <script.ppy>              compile and print the disassembly only
packetpy build  <script.ppy> [-o out]     compile to a .ppyb blob + .json
packetpy load   <script.ppy> --pc-if eth0 --box-if eth1 [--debug] [--reset-stats]
packetpy stats  [--json]                  print runtime packet counters
packetpy debug  on|off                    toggle kernel trace output at runtime
packetpy network status|backup|restore    inspect / save / restore the bridge network state
packetpy recovery [iface ...]             emergency: detach filters, remove br0, bring interfaces up
```
`network` and `recovery` do not depend on the compiler or the web agent, so they
still work to get the box back on the network if PacketPy itself is broken. The
boot sequence is idempotent and falls back to a plain pass-through bridge (traffic
still flows, unmodified) if the eBPF program cannot be loaded, so a bad script or
update never cuts the link the device sits on.
`--config <file>` overrides the auto-detected config.

Runtime counters: `seen` (matched packets), `accept`, `drop`, `modified`
(payload rewritten), `error` (out-of-bounds / bad op), `trace` (`log()` calls).

---

## 9. API
The control agent `packetpyd` serves the panels and a REST API on port 8080.
Every API call must carry the token in the **`X-PPY-Token` header** (never the
URL, so it is not logged by proxies or browser history); the token is in
`/opt/packetpy/var/token` (mode 0600). Tokens are compared in constant time,
failed attempts are rate-limited per IP, request bodies are capped (1 MB; scripts
and configs 256 KB), and configs must be valid JSON. Bind only to a trusted LAN
interface via `PACKETPY_HOST`. Over the LAN only.

```
GET    /                         master panel
GET    /panel/<name>             a script panel page
GET    /api/health
GET    /api/machine              cpu/mem/temp/uptime/load/kernel/hostname
GET    /api/stats                packet counters (from the kernel map)
GET    /api/active               active script, attach state, debug, interfaces
GET    /api/scripts              the script index (fast lookup across all scripts)
GET    /api/index/rebuild        rescan and rebuild the index
GET    /api/script?path=         script source + compile result
POST   /api/script               {path, source}  save a script
DELETE /api/script?path=         delete a script
POST   /api/check   {path}       compile-check (meta + disasm or error)
POST   /api/load    {path,debug,reset}   compile + load + attach (start)
POST   /api/stop                 detach the datapath
POST   /api/reload               reload the active script
GET    /api/configs | /api/config?name= | POST /api/config {name,source}
GET    /api/systems              config ↔ linked script ↔ linked panel table
GET    /api/panels | POST /api/panels {name,title} | DELETE /api/panels?name=
GET    /api/panel?name=          panel metadata + its scripts
POST   /api/panel?name=          save panel.json
POST   /api/panel/action         {action: start|stop|reload, path}
POST   /api/system/new           {script, port, panel?, config?, link?}  create all three
GET    /api/logs?type=system|packet|crash&tail=N
POST   /api/logs/clear?type=
POST   /api/reboot               reboot the device
GET    /events                   SSE stream: machine + stats every 2s
```

Logs live in `/opt/packetpy/var/logs/{system,packet,crash}.log`; lines older
than **3 weeks** are deleted automatically.

---

## 10. Performance
- The datapath is TC/eBPF with **direct-action** on `clsact` — it runs in the
  kernel receive path, edits the packet in place, and returns a verdict. No copy
  to userspace, no per-packet thread hop. This is the lowest-latency option on
  a Linux bridge.
- The control agent and panels are **never on the packet path**; they only fill
  maps and read counters, so using the web UI adds no latency to traffic.
- Keep `--debug` **off** in production: the per-packet kernel trace is only for
  verification and slows the datapath.
- When the payload is rewritten, the UDP checksum is zeroed (valid "no checksum"
  for IPv4/UDP) so the packet is accepted without recomputation.
- Counters are atomic adds on one map entry, read out-of-band — they don't slow
  the datapath.
