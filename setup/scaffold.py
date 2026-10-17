#!/usr/bin/env python3
"""PacketPy cross-platform setup / scaffolder.

Runs on Linux, Raspberry Pi OS and Windows. It creates the folder layout
(scripts / config / panels / var) in the right place, seeds the default files if
missing, checks your environment, and self-tests the PyNet compiler.

- On a Raspberry Pi / Linux box that will actually modify packets, run the full
  installer instead (sudo ./install.sh) — that also sets up the bridge, eBPF and
  the systemd services. This scaffolder is for the editing/management side and
  works on any OS.

Usage:
    python3 setup/scaffold.py            # create folders + self-test
    python3 setup/scaffold.py --agent    # also start the local control agent
"""
import os, sys, subprocess, shutil, platform, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRS = ["scripts", "config", "panels", "panels/example/scripts", "var/logs"]

SEEDS = {
    "scripts/main.ppy": """# PyNet packet script
packets = State(0)

@udp(port=12345)
def packet():
    packets += 1
    base = 0
    # value = read_field("header.value", base)
    # write_field("header.value", base, value)
    accept()
""",
    "config/fields.json": """{
  "name": "Packet field configuration",
  "version": 1,
  "transport": "UDP",
  "default_udp_port": 12345,
  "constants": { "TARGET_PORT": 12345 },
  "fields": {},
  "linked_script": "scripts/main.ppy",
  "linked_panel": null
}
""",
    "panels/example/panel.json": """{
  "name": "example",
  "title": "Example panel",
  "description": "",
  "accent": "#2a7de1",
  "layout": "rail",
  "categories": [{ "id": "general", "label": "General", "color": "#2a7de1" }],
  "assign": {}
}
""",
    "panels/example/scripts/passthrough.ppy": """# Example panel script: count packets, pass everything through.
seen = State(0)

@udp(port=12345)
def packet():
    seen += 1
    accept()
""",
}

def c(s, code): return s if not sys.stdout.isatty() else f"\033[{code}m{s}\033[0m"
def ok(s):   print(c("  ✓ ", "32") + s)
def warn(s): print(c("  ! ", "33") + s)
def info(s): print(c("  · ", "36") + s)

def make_dirs():
    for d in DIRS:
        (ROOT / d).mkdir(parents=True, exist_ok=True)
    ok("folders ready: " + ", ".join(DIRS))

def seed():
    n = 0
    for rel, content in SEEDS.items():
        p = ROOT / rel
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content); n += 1
    ok(f"default files seeded ({n} created, rest already present)")

def check_env():
    v = sys.version_info
    (ok if v >= (3, 8) else warn)(f"Python {v.major}.{v.minor}.{v.micro}")
    is_linux = platform.system() == "Linux"
    for tool, why in [("clang", "compile eBPF"), ("bpftool", "load eBPF"), ("tc", "attach datapath")]:
        if shutil.which(tool): ok(f"{tool} found")
        elif is_linux: warn(f"{tool} missing — needed to run the datapath (apt install, or use ./install.sh)")
        else: info(f"{tool} not on {platform.system()} — the datapath only runs on the Raspberry Pi / Linux")

def self_test():
    try:
        r = subprocess.run([sys.executable, str(ROOT / "packetpy.py"), "check", str(ROOT / "scripts" / "main.ppy")],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0: ok("PyNet compiler works (scripts/main.ppy compiles)")
        else: warn("compiler self-test failed:\n" + (r.stderr or r.stdout).strip())
    except Exception as e:
        warn(f"could not run the compiler: {e}")

def next_steps():
    sysname = platform.system()
    print("\n" + c("Next steps", "1"))
    if sysname == "Linux":
        print("  • Real deployment on this Linux box / Raspberry Pi:")
        print("      sudo PC_IF=eth0 BOX_IF=eth1 ./install.sh")
        print("      then open  http://packetpy.local:8080")
        print("  • Just edit/compile scripts here:")
        print("      python3 packetpy.py check scripts/main.ppy")
    else:
        print(f"  • {sysname} is for editing & managing (the packet datapath needs the Raspberry Pi).")
        print("      python3 packetpy.py check scripts/main.ppy      # compile-check a script")
        print("      python3 agent/packetpyd.py                      # run the panels locally (no datapath)")
        print("  • Deploy on the Pi with ./install.sh, then open http://packetpy.local:8080")

def run_agent():
    env = dict(os.environ, PACKETPY_PREFIX=str(ROOT))
    print("\nStarting the control agent (Ctrl+C to stop)…")
    subprocess.run([sys.executable, str(ROOT / "agent" / "packetpyd.py")], env=env)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="store_true", help="start the local control agent after setup")
    a = ap.parse_args()
    print(c("PacketPy setup", "1") + f"  ({platform.system()} {platform.machine()})\n")
    make_dirs(); seed(); check_env(); self_test(); next_steps()
    if a.agent: run_agent()

if __name__ == "__main__":
    main()
