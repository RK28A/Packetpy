# Getting started with PacketPy (the very simple version)

This guide assumes you know nothing. Follow it top to bottom.

PacketPy is a little box (a Raspberry Pi) that you plug **in the middle** of a
network cable. Everything that passes through can be read and changed by a small
script you write. You control it from your normal PC in a web browser.

---

## What you need to buy

You need a Raspberry Pi and a **second** Ethernet port (the Pi only has one), so
you buy **one USB-to-Ethernet adapter**. Three builds depending on budget:

### 🟢 Cheapest (works, ~100 Mbps)
- **Raspberry Pi 3 Model B+**
- **1× USB 2.0 Ethernet adapter** — chipset **ASIX AX88772** (plug-and-play on Raspberry Pi OS)
- microSD card (16 GB, class A1+), official power supply, 2 short Cat6 cables

### 🔵 Mid-range (recommended — best value, full gigabit)
- **Raspberry Pi 4 (2 GB or 4 GB)**
- **1× USB 3.0 Gigabit Ethernet adapter** — chipset **Realtek RTL8153** or **ASIX AX88179**
- microSD card (32 GB, class A2), official USB-C power supply, 2 short Cat6 cables

### 🔴 High-end (lowest latency, 2.5 Gbps headroom)
- **Raspberry Pi 5 (4 GB or 8 GB)** with the active cooler
- **1× USB 3.0 2.5GbE adapter** — chipset **Realtek RTL8156**
- NVMe HAT + SSD (optional, for logs), 32 GB A2 microSD, official PSU, Cat6 cables

**Why the adapter?** The Pi has one Ethernet port; a transparent bridge needs
two. Use the Pi's built-in port for one side and the USB adapter for the other.
Stick to the chipsets above — they work on Raspberry Pi OS with no drivers.

---

## Step 1 — Flash Raspberry Pi OS
1. On your PC, install **Raspberry Pi Imager** (raspberrypi.com/software).
2. Choose **Raspberry Pi OS (64-bit)**, write it to the microSD card.
3. In Imager's settings (gear icon) enable **SSH** and set a username/password so
   you can reach the Pi without a screen.
4. Put the card in the Pi, plug in the USB Ethernet adapter, power it on.

## Step 2 — Plug it in the middle
```
[ your PC ] ──cable──> (Pi built-in port = eth0)
                        (Pi USB adapter    = eth1) ──cable──> [ the other device / router / console ]
```
The Pi now sits between your PC and whatever it talks to.

## Step 3 — Install PacketPy on the Pi
Open a terminal to the Pi (SSH or a keyboard/screen) and run:
```bash
git clone https://github.com/RK28A/Packetpy.git
cd Packetpy
sudo ./setup/raspberry.sh
```
It asks which port goes to your PC (usually `eth0`) and which goes to the other
side (usually `eth1`) — press Enter to accept the defaults if unsure. It then
installs everything, starts at boot, and prints an **API token**. Copy it.

## Step 4 — Open the panel from your PC
In your PC's browser go to:
```
http://packetpy.local:8080
```
Paste the **API token** into the box at the top right (once). You'll see the
master panel: device health, live packet counters, files, logs, and panels.

> If `packetpy.local` doesn't resolve on your network, use the Pi's IP address
> instead, e.g. `http://192.168.1.50:8080` (find it with `hostname -I` on the Pi).

## Step 5 — Make your first "system"
1. Click **+ New system** (top right).
2. Type a script name (e.g. `test.ppy`) and the **UDP port** of the app you want
   to touch (the box is pre-filled with a working default). A panel is created
   automatically.
3. Click **Create**. A toast appears bottom-right confirming it.
4. Go to **Files**, open your new script, write your logic (see
   [DOCS.md](DOCS.md) for the PyNet language), click **Check**, then **Load**.
5. Watch **Overview** — when the app sends traffic, `seen` starts counting. That
   means you're on the right packets. (The **ⓘ** icons explain each field.)

That's it. You're modifying packets.

---

## "How do I know I'm editing the right thing?"
Short version (full version in [DOCS.md §1](DOCS.md#1-targeting)):
- **Where you plugged the Pi** decides *which machines* you can see.
- **The UDP port** in `@udp(port=…)` decides *which app*.
- **The offsets in the config** decide *which bytes* inside the packet.
- If `seen` stays 0, the traffic isn't crossing the Pi or the port is wrong.

## Something's wrong?
- Panel won't load → is the Pi on and booted? Try the Pi's IP instead of
  `packetpy.local`. Check the agent: `sudo systemctl status packetpyd`.
- Script won't load → click **Check**; it tells you the exact line. Programs that
  are too big (e.g. a loop that's too large) are rejected on purpose.
- Need the token again → it's in `/opt/packetpy/var/token` on the Pi.
