# Setup

Pick the file for your situation. The **packet datapath only runs on Linux /
Raspberry Pi** (it uses the kernel's eBPF/TC). Windows and macOS are for writing
scripts and running the control panels.

| You are on… | Run | What it does |
|---|---|---|
| **Raspberry Pi / Linux** (real deployment) | `sudo ./setup/raspberry.sh` | asks which interfaces, then runs the full installer: bridge + eBPF + autostart + `packetpy.local` |
| **Raspberry Pi / Linux** (manual) | `sudo PC_IF=eth0 BOX_IF=eth1 ./install.sh` | same, non-interactive |
| **Windows** | `./setup/windows.ps1` | creates the folders, checks Python, self-tests the compiler, shows how to run the panels |
| **Any OS** (folders + check) | `python3 setup/scaffold.py` | creates `scripts/ config/ panels/ var/`, seeds defaults, self-tests the PyNet compiler |
| **Any OS** (+ run panels) | `python3 setup/scaffold.py --agent` | the above, then starts the local control agent |

After installing on the Pi, open **http://packetpy.local:8080** from any
computer on the same network. The installer prints the API token (also stored in
`/opt/packetpy/var/token`); paste it into the panel's token box once.

New here? Read **[../GETTING_STARTED.md](../GETTING_STARTED.md)** — a full
step-by-step from zero.
