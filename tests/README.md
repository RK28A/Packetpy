# Tests

Run from the repository root.

| Test | Needs root | What it covers |
|---|---|---|
| `python3 tests/test_security.py` | no | File-permission resolver (no writes outside `scripts/`/`panels/*/scripts/` and `config/`, traversal/extension checks) and the PyNet compiler (valid/invalid scripts, oversized programs rejected). |
| `sudo tests/datapath.sh` | yes (eBPF/TC) | End-to-end in a network namespace: a field rewrite (5→6), a short payload handled safely (out-of-bounds read bounds-guarded, no corruption), and a consistent hot reload. Nothing on the physical network is touched. |

The datapath test builds the real eBPF object, loads it via the kernel verifier,
sets up a `veth` pair with one end in a `netns`, loads scripts through the real
`packetpy` CLI, sends crafted UDP packets, and asserts on the received bytes and
the runtime counters.
