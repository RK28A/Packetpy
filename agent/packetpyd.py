#!/usr/bin/env python3
"""packetpyd — control agent for PacketPy.

Serves the web panels (master panel + per-script-panels) and a small REST API
that a PC on the LAN uses to manage this device: browse and edit scripts and
configs, compile/load/stop/reload the active packet script, read machine and
packet statistics, read and rotate logs, reboot the device, and create panels.

The datapath itself stays 100% in the kernel (TC/eBPF); this agent is never on
the packet path, it only fills maps and attaches filters, so it adds no latency.

Runs as root (needs bpftool/tc/systemctl). Pure standard library.
"""
import http.server, socketserver, json, os, sys, time, subprocess, threading
import urllib.parse, socket, platform, re, shutil, struct
from pathlib import Path
from datetime import datetime, timezone, timedelta

PREFIX = Path(os.environ.get("PACKETPY_PREFIX", "/opt/packetpy"))
SCRIPTS = PREFIX / "scripts"
CONFIG  = PREFIX / "config"
PANELS  = PREFIX / "panels"
STATIC  = PREFIX / "agent" / "static"
VAR     = PREFIX / "var"
LOGS    = VAR / "logs"
STATEF  = VAR / "state.json"
INDEXF  = VAR / "index.json"
TOKENF  = VAR / "token"

MAPS = Path("/sys/fs/bpf/packetpy/maps")
STAT_MAP = MAPS / "ppy_stats"
LOG_MAX_DAYS = 21
STAT_NAMES = ["seen", "accept", "drop", "modified", "error", "trace"]

for d in (SCRIPTS, CONFIG, PANELS, VAR, LOGS):
    d.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(PREFIX))
try:
    import packetpy as ppy  # compile/disasm in-process
except Exception:
    ppy = None

# ---------------------------------------------------------------- state / auth
def load_state():
    try: return json.loads(STATEF.read_text())
    except Exception: return {"active": None, "pc_if": os.environ.get("PC_IF", "eth0"),
                              "box_if": os.environ.get("BOX_IF", "eth1"), "debug": False,
                              "attached": False}
def save_state(s): STATEF.write_text(json.dumps(s, indent=2))
STATE = load_state()

def token():
    if "PACKETPY_TOKEN" in os.environ: return os.environ["PACKETPY_TOKEN"]
    try: return TOKENF.read_text().strip()
    except Exception:
        t = os.urandom(12).hex();
        try: TOKENF.write_text(t)
        except Exception: pass
        return t
TOKEN = token()

# ------------------------------------------------------------------- logging
def _logfile(kind): return LOGS / f"{kind}.log"
def log(kind, msg):
    line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}\t{msg}\n"
    try:
        with open(_logfile(kind), "a") as f: f.write(line)
    except Exception: pass

def read_log(kind, tail=300):
    p = _logfile(kind)
    if not p.exists(): return []
    try: lines = p.read_text(errors="replace").splitlines()
    except Exception: return []
    return lines[-tail:]

def prune_logs():
    """Delete log lines older than LOG_MAX_DAYS (auto-cleanup of old logs)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOG_MAX_DAYS)
    for p in LOGS.glob("*.log"):
        try: lines = p.read_text(errors="replace").splitlines()
        except Exception: continue
        kept = []
        for ln in lines:
            ts = ln.split("\t", 1)[0]
            try:
                if datetime.fromisoformat(ts) >= cutoff: kept.append(ln)
            except Exception:
                kept.append(ln)  # keep unparseable lines
        if len(kept) != len(lines):
            try: p.write_text("\n".join(kept) + ("\n" if kept else ""))
            except Exception: pass

def prune_loop():
    while True:
        prune_logs(); time.sleep(3600)

# ------------------------------------------------------------------- helpers
def run(cmd, timeout=20):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def safe_path(base, rel):
    """Resolve rel under base, refusing escapes."""
    rel = (rel or "").lstrip("/")
    p = (base / rel).resolve()
    if base.resolve() not in p.parents and p != base.resolve():
        raise ValueError("path outside of allowed directory")
    return p

def machine_stats():
    out = {"hostname": socket.gethostname(), "kernel": platform.release(),
           "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        with open("/proc/uptime") as f: out["uptime_s"] = int(float(f.read().split()[0]))
    except Exception: out["uptime_s"] = None
    try:
        with open("/proc/loadavg") as f: out["load"] = f.read().split()[:3]
    except Exception: out["load"] = None
    try:
        mem = {}
        for ln in open("/proc/meminfo"):
            k, v = ln.split(":"); mem[k] = int(v.strip().split()[0])
        out["mem_total_kb"] = mem.get("MemTotal"); out["mem_avail_kb"] = mem.get("MemAvailable")
        if out["mem_total_kb"]:
            out["mem_used_pct"] = round(100*(1 - out["mem_avail_kb"]/out["mem_total_kb"]), 1)
    except Exception: pass
    # cpu % over a short sample
    try:
        def snap():
            parts = open("/proc/stat").readline().split()[1:8]
            v = list(map(int, parts)); idle = v[3]+v[4]; return sum(v), idle
        t1, i1 = snap(); time.sleep(0.08); t2, i2 = snap()
        dt, di = t2-t1, i2-i1
        out["cpu_pct"] = round(100*(1 - di/dt), 1) if dt else None
    except Exception: out["cpu_pct"] = None
    # temperature (Pi / generic thermal zone)
    try:
        for z in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
            out["temp_c"] = round(int(z.read_text())/1000, 1); break
    except Exception: out["temp_c"] = None
    return out

def packet_stats():
    """Read ppy_stats (single-entry struct of 16 u64) via bpftool."""
    if not STAT_MAP.exists(): return {"loaded": False, **{n: 0 for n in STAT_NAMES}}
    try:
        rc, so, se = run(["bpftool", "-j", "map", "lookup", "pinned", str(STAT_MAP),
                          "key", "hex", "00", "00", "00", "00"])
        if rc != 0: return {"loaded": False, **{n: 0 for n in STAT_NAMES}}
        j = json.loads(so)
        raw = j.get("value") or (j.get("formatted") or {}).get("value") or []
        bs = bytes(int(x, 16) if isinstance(x, str) else int(x) for x in raw)
        counts = struct.unpack_from("<16Q", bs.ljust(128, b"\x00"))
        d = {"loaded": True}
        for i, n in enumerate(STAT_NAMES): d[n] = counts[i]
        return d
    except Exception:
        return {"loaded": False, **{n: 0 for n in STAT_NAMES}}

# ---------------------------------------------------------------- scripts/index
def config_for(path):
    c = CONFIG / "fields.json"
    return c if c.exists() else None

def compile_meta(path):
    """Return (meta, disasm, error) by compiling in-process."""
    if ppy is None: return None, None, "compiler module unavailable"
    try:
        c, _blob, meta = ppy.compile_file(str(path), str(config_for(path)) if config_for(path) else None)
        return meta, ppy.disasm(c, meta), None
    except Exception as e:
        return None, None, str(e)

def rebuild_index():
    """Scan all scripts (top-level + inside panels) into var/index.json for fast lookup."""
    idx = []
    srcs = [(p, None) for p in SCRIPTS.glob("*.ppy")]
    for pd in PANELS.glob("*/scripts/*.ppy"):
        srcs.append((pd, pd.parent.parent.name))
    for p, panel in srcs:
        entry = {"name": p.name, "path": str(p.relative_to(PREFIX)), "panel": panel,
                 "mtime": int(p.stat().st_mtime), "port": None, "instructions": None,
                 "modules": 0, "ok": True, "error": None}
        meta, _dis, err = compile_meta(p)
        if err: entry["ok"] = False; entry["error"] = err
        elif meta:
            entry["port"] = meta.get("port"); entry["instructions"] = meta.get("instructions")
        idx.append(entry)
    idx.sort(key=lambda e: e["name"].lower())
    INDEXF.write_text(json.dumps({"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                  "count": len(idx), "scripts": idx}, indent=2))
    return idx

def read_index():
    try: return json.loads(INDEXF.read_text())
    except Exception: return {"scripts": rebuild_index(), "count": 0}

# ---------------------------------------------------------------- panels
def panel_dir(name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name or ""): raise ValueError("bad panel name")
    return PANELS / name

def panel_meta_path(name): return panel_dir(name) / "panel.json"

def list_panels():
    out = []
    for d in sorted(PANELS.glob("*/")):
        mp = d / "panel.json"
        if mp.exists():
            try: meta = json.loads(mp.read_text())
            except Exception: meta = {}
            meta["name"] = d.name
            meta["script_count"] = len(list((d / "scripts").glob("*.ppy"))) if (d/"scripts").exists() else 0
            out.append(meta)
    return out

SCRIPT_TEMPLATE = """# {name} — packet script for UDP/{port}
# Edit config/{config} to declare the packet fields this script reads/writes.
packets = State(0)

@udp(port={port})
def packet():
    packets += 1
    base = 0
    # value = read_field("header.value", base)
    # write_field("header.value", base, value)
    accept()
"""

def create_system(script_name, port, panel=None, config_name=None, link=True):
    """Create a config + script (+ optional panel), wired together, in one step."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", script_name or ""): raise ValueError("bad script name")
    if not script_name.endswith(".ppy"): script_name += ".ppy"
    port = int(port)
    if not (0 < port <= 65535): raise ValueError("port must be 1..65535")
    config_name = config_name or (script_name[:-4] + ".json")
    if not config_name.endswith(".json"): config_name += ".json"
    if panel:
        d = panel_dir(panel)
        if not d.exists(): create_panel(panel, panel)
        spath = d / "scripts" / script_name
    else:
        spath = SCRIPTS / script_name
    if spath.exists(): raise ValueError("script already exists")
    spath.parent.mkdir(parents=True, exist_ok=True)
    spath.write_text(SCRIPT_TEMPLATE.format(name=script_name, port=port, config=config_name))
    cfg = {"name": config_name[:-5], "version": 1, "transport": "UDP", "default_udp_port": port,
           "constants": {}, "fields": {},
           "linked_script": str(spath.relative_to(PREFIX)) if link else None,
           "linked_panel": panel if link else None}
    (CONFIG / config_name).write_text(json.dumps(cfg, indent=2))
    rebuild_index()
    log("system", f"new system: {script_name} + {config_name}" + (f" + panel {panel}" if panel else ""))
    return {"script": str(spath.relative_to(PREFIX)), "config": config_name, "panel": panel}

def create_panel(name, title=None):
    d = panel_dir(name)
    if d.exists(): raise ValueError("panel already exists")
    (d / "scripts").mkdir(parents=True)
    meta = {"name": name, "title": title or name, "categories": [{"id": "general", "label": "General"}],
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    panel_meta_path(name).write_text(json.dumps(meta, indent=2))
    log("system", f"panel created: {name}")
    return meta

# ---------------------------------------------------------------- datapath ops
def ifaces(): return STATE.get("pc_if", "eth0"), STATE.get("box_if", "eth1")

def attach():
    pc, box = ifaces(); prog = None
    progs = Path("/sys/fs/bpf/packetpy/progs")
    try: prog = next(iter(progs.glob("*")), None)
    except Exception: prog = None
    if not prog: return False, "pinned BPF program not found (run install.sh)"
    for i in (pc, box):
        run(["tc", "qdisc", "replace", "dev", i, "clsact"])
        rc, so, se = run(["tc", "filter", "replace", "dev", i, "ingress", "pref", "10",
                          "handle", "1", "bpf", "da", "pinned", str(prog)])
        if rc != 0: return False, se.strip() or "tc attach failed"
    STATE["attached"] = True; save_state(STATE); return True, "attached"

def detach():
    pc, box = ifaces()
    for i in (pc, box):
        run(["tc", "filter", "del", "dev", i, "ingress"])
    STATE["attached"] = False; save_state(STATE)

def do_load(path, debug=False, reset=False):
    pc, box = ifaces()
    cmd = [sys.executable, str(PREFIX / "packetpy.py"), "load", str(path),
           "--pc-if", pc, "--box-if", box]
    if debug: cmd.append("--debug")
    if reset: cmd.append("--reset-stats")
    rc, so, se = run(cmd, timeout=40)
    if rc != 0:
        log("crash", f"load failed {path}: {se.strip()}")
        return False, (se.strip() or so.strip())
    ok, msg = attach()
    STATE["active"] = str(Path(path).relative_to(PREFIX)); STATE["debug"] = bool(debug); save_state(STATE)
    log("system", f"loaded {path} debug={debug} -> {so.strip()}")
    return ok, (so.strip() + ("" if ok else f" / attach: {msg}"))

# ------------------------------------------------------------------- HTTP
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    # --- plumbing
    def _auth(self):
        q = urllib.parse.urlparse(self.path).query
        tok = urllib.parse.parse_qs(q).get("token", [None])[0] or self.headers.get("X-PPY-Token")
        return tok == TOKEN

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)): body = json.dumps(body).encode()
        elif isinstance(body, str): body = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n: return {}
        try: return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception: return {}

    def _serve_static(self, name):
        p = STATIC / name
        if not p.exists():
            self._send(404, {"error": "not found"}); return
        ctype = {"html": "text/html", "js": "text/javascript", "css": "text/css",
                 "json": "application/json"}.get(p.suffix[1:], "text/plain")
        self._send(200, p.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))

    # --- routing
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); path = u.path; q = urllib.parse.parse_qs(u.query)
        if path in ("/", "/index.html"): return self._serve_static("master.html")
        if path == "/panel" or path.startswith("/panel/"): return self._serve_static("panel.html")
        if path.startswith("/static/"): return self._serve_static(path[len("/static/"):])
        if path == "/api/health": return self._send(200, {"ok": True, "service": "packetpyd"})
        if not path.startswith("/api/") and path != "/events":
            return self._send(404, {"error": "not found"})
        if not self._auth(): return self._send(401, {"error": "bad or missing token"})

        if path == "/events": return self._sse()
        if path == "/api/machine": return self._send(200, machine_stats())
        if path == "/api/stats":   return self._send(200, packet_stats())
        if path == "/api/active":
            pc, box = ifaces()
            return self._send(200, {"active": STATE.get("active"), "attached": STATE.get("attached"),
                                    "debug": STATE.get("debug"), "pc_if": pc, "box_if": box})
        if path == "/api/scripts": return self._send(200, read_index())
        if path == "/api/index/rebuild": return self._send(200, {"scripts": rebuild_index()})
        if path == "/api/script":
            try:
                p = safe_path(PREFIX, q.get("path", [""])[0])
                meta, dis, err = compile_meta(p)
                return self._send(200, {"path": str(p.relative_to(PREFIX)), "source": p.read_text(),
                                        "meta": meta, "disasm": dis, "error": err})
            except Exception as e: return self._send(400, {"error": str(e)})
        if path == "/api/configs":
            return self._send(200, {"configs": [c.name for c in CONFIG.glob("*.json")]})
        if path == "/api/config":
            try:
                p = safe_path(CONFIG, q.get("name", ["fields.json"])[0])
                return self._send(200, {"name": p.name, "source": p.read_text()})
            except Exception as e: return self._send(400, {"error": str(e)})
        if path == "/api/systems":  return self._send(200, {"systems": self._systems()})
        if path == "/api/panels":   return self._send(200, {"panels": list_panels()})
        if path == "/api/panel":
            try:
                name = q.get("name", [""])[0]; d = panel_dir(name)
                meta = json.loads((d / "panel.json").read_text())
                meta["name"] = name
                meta["scripts"] = [self._script_brief(sp, name) for sp in sorted((d/"scripts").glob("*.ppy"))]
                return self._send(200, meta)
            except Exception as e: return self._send(400, {"error": str(e)})
        if path == "/api/logs":
            kind = q.get("type", ["system"])[0]
            if kind not in ("system", "packet", "crash"): return self._send(400, {"error": "bad log type"})
            return self._send(200, {"type": kind, "lines": read_log(kind, int(q.get("tail", ["300"])[0]))})
        return self._send(404, {"error": "unknown endpoint"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path); path = u.path; q = urllib.parse.parse_qs(u.query)
        if not self._auth(): return self._send(401, {"error": "bad or missing token"})
        b = self._json_body()
        try:
            if path == "/api/script":
                p = safe_path(SCRIPTS, b.get("path", "")) if "/" not in b.get("path","") else safe_path(PREFIX, b["path"])
                p.parent.mkdir(parents=True, exist_ok=True); p.write_text(b.get("source", ""))
                log("system", f"saved script {p.name}"); rebuild_index()
                return self._send(200, {"ok": True})
            if path == "/api/config":
                p = safe_path(CONFIG, b.get("name", "fields.json")); p.write_text(b.get("source", ""))
                log("system", f"saved config {p.name}"); return self._send(200, {"ok": True})
            if path == "/api/check":
                p = safe_path(PREFIX, b.get("path", "")); meta, dis, err = compile_meta(p)
                return self._send(200, {"meta": meta, "disasm": dis, "error": err})
            if path == "/api/load":
                p = safe_path(PREFIX, b.get("path", ""))
                ok, msg = do_load(p, debug=bool(b.get("debug")), reset=bool(b.get("reset")))
                return self._send(200 if ok else 500, {"ok": ok, "message": msg})
            if path == "/api/stop":
                detach(); STATE["active"] = None; save_state(STATE); log("system", "datapath stopped")
                return self._send(200, {"ok": True})
            if path == "/api/reload":
                if not STATE.get("active"): return self._send(400, {"error": "no active script"})
                ok, msg = do_load(PREFIX / STATE["active"], debug=STATE.get("debug"))
                return self._send(200 if ok else 500, {"ok": ok, "message": msg})
            if path == "/api/system/new":
                return self._send(200, create_system(b.get("script",""), b.get("port",12345),
                                                     b.get("panel") or None, b.get("config") or None,
                                                     bool(b.get("link", True))))
            if path == "/api/panels":
                return self._send(200, create_panel(b.get("name", ""), b.get("title")))
            if path == "/api/panel":
                name = q.get("name", [b.get("name","")])[0]; d = panel_dir(name)
                if not d.exists(): return self._send(404, {"error": "no such panel"})
                meta = b.get("meta") or b
                (d / "panel.json").write_text(json.dumps(meta, indent=2)); return self._send(200, {"ok": True})
            if path == "/api/panel/action":
                return self._panel_action(b)
            if path == "/api/logs/clear":
                kind = q.get("type", [b.get("type","")])[0]
                if kind in ("system", "packet", "crash"):
                    _logfile(kind).write_text(""); return self._send(200, {"ok": True})
                return self._send(400, {"error": "bad log type"})
            if path == "/api/reboot":
                log("system", "reboot requested"); threading.Timer(1.0, lambda: run(["systemctl", "reboot"])).start()
                return self._send(200, {"ok": True, "message": "rebooting"})
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e:
            log("crash", f"POST {path}: {e}"); return self._send(400, {"error": str(e)})

    def do_DELETE(self):
        u = urllib.parse.urlparse(self.path); path = u.path; q = urllib.parse.parse_qs(u.query)
        if not self._auth(): return self._send(401, {"error": "bad or missing token"})
        try:
            if path == "/api/script":
                p = safe_path(PREFIX, q.get("path", [""])[0]); p.unlink(); rebuild_index()
                log("system", f"deleted script {p.name}"); return self._send(200, {"ok": True})
            if path == "/api/panels":
                d = panel_dir(q.get("name", [""])[0]); shutil.rmtree(d)
                log("system", f"deleted panel {d.name}"); return self._send(200, {"ok": True})
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e: return self._send(400, {"error": str(e)})

    # --- derived
    def _script_brief(self, p, panel):
        meta, _d, err = compile_meta(p)
        active = STATE.get("active") == str(p.relative_to(PREFIX))
        cat = "general"
        return {"name": p.name, "path": str(p.relative_to(PREFIX)), "panel": panel,
                "port": meta.get("port") if meta else None,
                "instructions": meta.get("instructions") if meta else None,
                "ok": err is None, "error": err, "active": active, "category": cat}

    def _systems(self):
        """Table: packet config  ↔  linked script  ↔  linked panel."""
        rows = []
        for c in sorted(CONFIG.glob("*.json")):
            try: data = json.loads(c.read_text())
            except Exception: data = {}
            rows.append({"config": c.name, "port": data.get("default_udp_port"),
                         "fields": len(data.get("fields", {})),
                         "linked_script": data.get("linked_script"),
                         "linked_panel": data.get("linked_panel")})
        return rows

    def _panel_action(self, b):
        action = b.get("action"); p = safe_path(PREFIX, b.get("path", ""))
        if action in ("start", "reload"):
            ok, msg = do_load(p, debug=STATE.get("debug")); return self._send(200 if ok else 500, {"ok": ok, "message": msg})
        if action == "stop":
            detach(); STATE["active"] = None; save_state(STATE); return self._send(200, {"ok": True})
        return self._send(400, {"error": "bad action"})

    # --- SSE live stream
    def _sse(self):
        self.send_response(200); self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store"); self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                payload = {"machine": machine_stats(), "stats": packet_stats(),
                           "active": STATE.get("active"), "attached": STATE.get("attached")}
                self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode()); self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError): return

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def main():
    host = os.environ.get("PACKETPY_HOST", "0.0.0.0")
    port = int(os.environ.get("PACKETPY_PORT", "8080"))
    rebuild_index()
    threading.Thread(target=prune_loop, daemon=True).start()
    log("system", f"packetpyd starting on {host}:{port}")
    print(f"packetpyd on http://{host}:{port}  token={TOKEN}")
    Server((host, port), H).serve_forever()

if __name__ == "__main__":
    main()
