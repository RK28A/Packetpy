# Packet field configuration

`fields.json` contains named constants and packet-field definitions. It is intentionally application-neutral.

## Constants

```json
"constants": {
  "TARGET_PORT": 12345,
  "TYPE_DATA": 7
}
```

Integer constants become names usable in PacketPy.

## Named fields

Supported fixed field kinds:

```json
"fields": {
  "header.type": {"kind":"u8", "offset":0},
  "header.sequence": {"kind":"u16le", "offset":1},
  "header.flags": {"kind":"bits", "offset":24, "width":4}
}
```

Offsets are relative to the `base` byte offset supplied by the script:

```python
kind = read_field("header.type", base)
seq = read_field("header.sequence", base)
write_field("header.sequence", base, seq)
```

For `bits`, `offset` is a bit offset relative to `base`. For `u8/u16le/u16be`, `offset` is a byte offset relative to `base`.

`fields.example.json` contains syntax examples only.

## Metadata (no config needed)

Besides named fields, scripts can read packet metadata directly: `direction`
(`PC_TO_BOX` / `BOX_TO_PC`), `udp.src_port`, `udp.dst_port`, `ip.src`,
`ip.dst`, `ip.ttl` and `payload_len`.
