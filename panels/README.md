# Script panels

Each sub-folder here is a **script panel**: a named group of packet scripts with
its own web page (categories, start/stop/reload buttons). Create panels from the
master panel (Panels tab → Create panel) or by hand:

```
panels/
  <name>/
    panel.json        # title + categories
    scripts/*.ppy     # the packet scripts this panel manages
```

`panel.json`:

```json
{
  "name": "example",
  "title": "Example panel",
  "categories": [{"id": "general", "label": "General"}]
}
```

Open a panel at `http://<device>:8080/panel/<name>`.
