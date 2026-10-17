# Changelog

All notable changes to PacketPy are recorded here, newest first.

## v0.6

### Live controls
- PyNet gains **live controls** declared at the top level: `Param` (slider),
  `Toggle` (switch), `Choice` (dropdown), `Number` (numeric input) and `Button`
  (momentary pulse), each optionally assigned to a `group=`.
- Controls live in a new read-only eBPF map (`ppy_params`); the panel writes them
  **while the script runs** — no recompile, no reload — and values survive a
  reload. Up to 32 per script.
- The panel renders each control as its widget inside **collapsible group
  bubbles** (remembered per group).
- Agent: `GET /api/params`, `POST /api/param` (validated against the control's
  range/options, button pulse). CLI: `packetpy param <slot> <value>` and
  `packetpy load --param slot=value`.
- Verified end-to-end in a netns: changing a control alters the modified packets
  immediately with no reload.

## v0.5

### Security & robustness
- **File access locked down.** The script/config endpoints now use a central,
  strict path resolver: `.ppy` scripts are allowed only in `scripts/` or
  `panels/<name>/scripts/`, configs only in `config/`. Path traversal and
  symlink escapes are rejected, names and extensions are validated, and writes
  are atomic (temp file + rename). The eBPF source, the agent, the installer and
  other system files can no longer be modified or deleted through the web API.
- **eBPF memory safety.** The VM now skips IPv4 fragments (only the first
  fragment carries the UDP header) and clamps the payload length to the bytes
  actually present in the packet, so every bounds check is against real data
  regardless of what the UDP length header claims.
- **Request limits.** Script/config saves over 256 KB are rejected; configs must
  be valid JSON before they are written.

### Datapath
- **Consistent hot reload.** Loading a new script sets the instruction count to 0
  before rewriting the program map and back to the real count afterwards, so a
  packet in flight never runs a mix of the old and new program — it runs the old
  one, or passes through unmodified for the brief swap window, then the new one.

### Language (PyNet)
- The scripting language is now named **PyNet**.
- Added chained comparisons (`a < b < c`), multiple assignment (`a = b = 0`),
  variadic `min()`/`max()`, and `swap16()` (endianness flip).

### Panels & UI
- **Config display names.** Scripts are shown in the panels under the name set in
  their config (`config.name`), not the raw filename.
- **Script-panel customization.** `panel.json` gains title, description, accent
  color, layout (rail/top), per-category colors and per-script category
  assignment, all editable live from the panel's Customize button. Panel edits
  and actions are written to the system log.
- **New system** always creates a linked panel (no optional choice), pre-fills a
  working UDP port, and takes a display name.
- Master/panel UI: info "i" popovers, animated bottom-right toasts, content/card/
  modal animations, and more robust connection handling (connected / token
  required / demo).

### Setup & deployment
- Cross-platform setup: `setup/scaffold.py` (Linux/Windows), `setup/raspberry.sh`
  (interactive installer), `setup/windows.ps1`.
- The device is reachable at **http://packetpy.local:8080** (mDNS via avahi).
- `GETTING_STARTED.md` beginner guide with hardware recommendations.

## v0.4

- **Control agent (`packetpyd`)** — a stdlib HTTP server on the device serving
  two web UIs over the LAN and a REST API.
- **Master panel** — device health + live packet stats, a file browser for
  scripts/configs, a Systems table (config ↔ script ↔ panel), logs, panel
  management, remote reboot, and a **+ New system** button that creates a config
  + script + panel wired together in one step.
- **Script panels** — named groups of scripts (`panels/<name>/`) each with their
  own page: categories + Start/Stop/Reload per script.
- **Autostart** — systemd units bring up the bridge, compile+load at boot, and
  run the agent; the active script starts on power-up.
- **Logs** — system / packet / crash logs under `var/logs/`, auto-pruned after
  3 weeks.
- **Language** — added bounded `while` and `break` (eBPF stays single-pass per
  packet), plus register/instruction optimizations.

## v0.3

- **Fixed:** the eBPF program now actually loads. The v0.2 VM advertised 128
  instructions but was rejected by the kernel verifier (instruction-budget
  blow-up); the limit is now a verifier-safe `64`.
- **Fixed:** `packetpy check/build/load` crashed with a `NameError` (`proto`
  undefined). Compilation works now.
- **Fixed:** `install.sh` referenced a non-existent `scripts/example.ppy`.
- **New debug:** runtime packet counters (`packetpy stats`), a `--debug` flag and
  `packetpy debug on|off` for kernel `trace_pipe` output, and a
  `log("label", value)` statement.
- **New language:** `//` and `%` (integer div/mod), ternary `a if cond else b`,
  `clamp(x, lo, hi)`, `rand()`, `now()`, `ip.ttl`, annotated disassembly, and a
  `packetpy disasm` command.

## v0.2

- Initial generic packet-modifier framework: Linux bridge + TC/eBPF datapath, a
  bytecode VM, the `.ppy` script compiler, named packet-field configuration, and
  the `install.sh` bridge setup.
