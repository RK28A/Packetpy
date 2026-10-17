#!/usr/bin/env python3
"""No-root regression tests: PyNet compiler + the file-permission resolver.
Run: python3 tests/test_security.py   (exit code 0 = all passed)"""
import os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("PACKETPY_PREFIX", str(ROOT))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

import packetpy as ppy
import packetpyd as agent

P = F = 0
def check(cond, name):
    global P, F
    if cond: P += 1; print("  PASS:", name)
    else:    F += 1; print("  FAIL:", name)
def rejects(fn, *a):
    try: fn(*a); return False
    except Exception: return True

print("[file-permission resolver]")
# scripts only in scripts/ or panels/<name>/scripts/
check(rejects(agent.resolve_script_path, "ebpf/packetpy_vm.bpf.c"), "reject eBPF source")
check(rejects(agent.resolve_script_path, "agent/packetpyd.py"), "reject agent file")
check(rejects(agent.resolve_script_path, "boot.sh"), "reject installer/boot")
check(rejects(agent.resolve_script_path, "packetpy.py"), "reject compiler")
check(rejects(agent.resolve_script_path, "scripts/../../etc/x.ppy"), "reject traversal")
check(rejects(agent.resolve_script_path, "scripts/x.sh"), "reject non-.ppy extension")
check(rejects(agent.resolve_script_path, "config/fields.json"), "reject config path as script")
check(not rejects(agent.resolve_script_path, "scripts/ok.ppy"), "accept scripts/ok.ppy")
check(not rejects(agent.resolve_script_path, "panels/example/scripts/ok.ppy"), "accept panels/<p>/scripts/ok.ppy")
check(rejects(agent.resolve_config_path, "../packetpy.py"), "reject config traversal")
check(rejects(agent.resolve_config_path, "x.txt"), "reject non-.json config")
check(not rejects(agent.resolve_config_path, "fields.json"), "accept fields.json")

print("[PyNet compiler]")
def compiles(src):
    d = tempfile.mkdtemp(); p = Path(d) / "s.ppy"; p.write_text(src)
    try: ppy.compile_file(str(p), None); return True, None
    except Exception as e: return False, str(e)

ok, _ = compiles("@udp(port=12345)\ndef packet():\n    accept()\n")
check(ok, "minimal valid script compiles")
ok, err = compiles("@udp(port=1)\ndef packet():\n    a = b = 1\n    x = payload.u8(0)\n    y = 1 if 0 < x < 5 else 2\n    accept()\n")
check(ok, "chained compare + multi-assign compile" + (f" [{err}]" if not ok else ""))
ok, err = compiles("@udp(port=0)\ndef packet():\n    accept()\n")
check(not ok, "port 0 rejected")
ok, err = compiles("import os\n@udp(port=1)\ndef packet():\n    accept()\n")
check(not ok, "import rejected")
# oversized loop must be rejected (never loads)
big = "@udp(port=1)\ndef packet():\n    t = 0\n" + "".join(f"    t += payload.u8({i})\n" for i in range(40)) + "    accept()\n"
ok, err = compiles(big)
check(not ok and "instruction" in (err or "").lower(), "oversized program rejected at compile time")

print(f"\nsecurity/compiler tests: {P} passed, {F} failed")
sys.exit(1 if F else 0)
