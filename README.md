# Pirate Security Toolset: Nassau & Pwning Dutchman

Two small, auditable CLI tools themed around the pirate havens of
Nassau — both scoped to **your own devices and networks only**.

```
pirate-security-tools/
├── banner.py                  # shared ASCII flag banner
├── nassau/
│   └── nassau.py              # privacy hardening
└── pwning_dutchman/
    └── dutchman.py            # passive IoT threat monitor
```

## Nassau — Privacy Hardening

Reduces your own exposure to tracking. Does not touch logs or
evidence of your activity for investigative purposes — it's a
privacy tool, not an anti-forensics tool.

```
python3 nassau/nassau.py clean-browser [--browser firefox|chrome|all] [--dry-run]
python3 nassau/nassau.py strip-metadata <file_or_dir> [--recursive] [--dry-run]
python3 nassau/nassau.py audit
python3 nassau/nassau.py mac-random <nmcli-connection-name> [--on|--off]
```

Dependencies: `Pillow` (image metadata), `pypdf` (PDF metadata),
`nmcli`/NetworkManager (MAC randomization, Linux only).

```
pip install Pillow pypdf
```

## Pwning Dutchman — IoT Threat Monitor

Passively watches DNS traffic on a network you control, flags
devices that query known-bad domains, and can contain them via your
**own firewall** (iptables `DROP` rule). It does **not** perform
deauthentication or any other wireless attack — it never forges
frames or targets a device it doesn't have the authority to manage.

```
python3 pwning_dutchman/dutchman.py monitor --iface eth0 --blocklist blocklist.txt [--block] [--dry-run]
python3 pwning_dutchman/dutchman.py update-blocklist --out blocklist.txt
python3 pwning_dutchman/dutchman.py report --log dutchman.log
```

Dependencies: `scapy` (packet capture). Requires root/`CAP_NET_RAW`
to sniff. `update-blocklist` currently writes a tiny seed list —
swap in a real threat-intel feed you're licensed to use.

```
pip install scapy
```

## Scope & ethics

- Only run `monitor --block` and `mac-random` on networks/devices you
  own or are explicitly authorized to administer.
- `clean-browser` and `strip-metadata` only ever touch files on the
  machine you run them on.
- Neither tool includes deauthentication, packet injection, or any
  other attack primitive aimed at third-party devices.
