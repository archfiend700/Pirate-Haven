#!/usr/bin/env python3
"""
Pwning Dutchman — IoT Threat Monitor
=====================================
Passively watches DNS traffic on a network YOU control for devices
contacting known-malicious domains, logs the offending device, and
can optionally block it at the firewall level (iptables/nftables or
your router's own block list).

This tool does NOT perform deauthentication or any other wireless
attack. Blocking happens via local firewall rules on the host it
runs on, or by printing the command you'd run on your router — it
never forges frames or targets devices it doesn't have authorization
to manage.

Legal/ethical note: only run this on networks you own or are
explicitly authorized to monitor.

Usage:
    python3 dutchman.py monitor --iface eth0 --blocklist blocklist.txt [--block] [--dry-run]
    python3 dutchman.py update-blocklist --out blocklist.txt
    python3 dutchman.py report --log dutchman.log
"""

import argparse
import datetime
import json
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import banner  # noqa: E402

LOG_PATH_DEFAULT = "dutchman.log"

# A tiny built-in seed list used only as a last-resort fallback if the
# live feed below can't be reached (offline, feed down, etc).
SEED_BLOCKLIST = [
    "malicious-example.test",
    "iot-botnet-c2.test",
    "tracker-ads-evil.test",
]

# Free, actively-maintained hosts-format feeds, merged together by
# default so one feed being down/rate-limited doesn't leave you with
# nothing. All are published specifically for blocklist consumption.
#
#  - URLhaus (abuse.ch): domains/hosts observed distributing malware
#    or acting as C2 infrastructure. https://urlhaus.abuse.ch/api/
#  - StevenBlack "unified hosts": merges several maintained malware,
#    ad, and tracking blocklists into one file, updated regularly.
#    https://github.com/StevenBlack/hosts
URLHAUS_HOSTFILE = "https://urlhaus.abuse.ch/downloads/hostfile/"
STEVENBLACK_HOSTS = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

DEFAULT_SOURCES = [URLHAUS_HOSTFILE, STEVENBLACK_HOSTS]


# ---------------------------------------------------------------------
# Blocklist handling
# ---------------------------------------------------------------------

def load_blocklist(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        print(f"[!] blocklist not found at {path}.")
        print(f"    Run: python3 dutchman.py update-blocklist --out {path}")
        print("    Writing a tiny fallback seed list for now so you can keep testing.")
        p.write_text("\n".join(SEED_BLOCKLIST) + "\n")
    domains = set()
    for line in p.read_text().splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


def _parse_hostfile(text: str) -> set[str]:
    """Parse a '0.0.0.0 domain' style hosts file into a set of domains."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].strip().lower()
            if domain and domain not in ("localhost", "localhost.localdomain", "local"):
                domains.add(domain)
    return domains


def _fetch(url: str) -> str | None:
    headers = {
        # A browser-like UA and Accept header — some feeds (incl.
        # abuse.ch) reject bare urllib default UAs with a 403.
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) pwning-dutchman/1.1",
        "Accept": "text/plain,*/*",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print(f"    [!] {url} failed: {e}")
        return None


def update_blocklist(out_path: str, sources: list[str] | None = None) -> None:
    """
    Pulls live malware/tracking-domain blocklists from one or more
    free, actively-maintained hosts-format feeds and merges them into
    out_path. Tries every source and merges whatever succeeds; only
    falls back to the tiny built-in seed list if ALL sources fail.
    """
    sources = sources or DEFAULT_SOURCES
    print(f"Fetching {len(sources)} source(s)...")

    all_domains = set()
    ok_sources = []
    for url in sources:
        print(f"  -> {url}")
        raw = _fetch(url)
        if raw is None:
            continue
        found = _parse_hostfile(raw)
        if found:
            print(f"     {len(found)} domains")
            all_domains |= found
            ok_sources.append(url)
        else:
            print("     0 domains parsed (unexpected format?)")

    if not all_domains:
        print("[!] all sources failed; writing fallback seed list instead.")
        Path(out_path).write_text("\n".join(SEED_BLOCKLIST) + "\n")
        print(f"Wrote seed blocklist ({len(SEED_BLOCKLIST)} domains) to {out_path}.")
        return

    header = (
        f"# Pwning Dutchman blocklist\n"
        f"# Sources ({len(ok_sources)}/{len(sources)} reachable):\n"
        + "".join(f"#   {s}\n" for s in ok_sources)
        + f"# Fetched: {datetime.datetime.now().isoformat(timespec='seconds')}\n"
        f"# {len(all_domains)} unique domains\n"
    )
    Path(out_path).write_text(header + "\n".join(sorted(all_domains)) + "\n")
    print(f"\nWrote {len(all_domains)} unique domains to {out_path} "
          f"(from {len(ok_sources)}/{len(sources)} sources).")


# ---------------------------------------------------------------------
# Passive DNS monitoring (scapy)
# ---------------------------------------------------------------------

def monitor(iface: str, blocklist_path: str, do_block: bool, dry_run: bool, log_path: str) -> None:
    try:
        from scapy.all import sniff, DNS, DNSQR, IP, Ether
    except ImportError:
        print("[!] scapy is required: pip install scapy")
        return

    if platform.system() == "Linux" and hasattr(__import__("os"), "geteuid"):
        import os
        if os.geteuid() != 0:
            print("[!] Packet sniffing usually requires root (sudo) or CAP_NET_RAW.")

    blocklist = load_blocklist(blocklist_path)
    print(f"Loaded {len(blocklist)} blocked domain(s) from {blocklist_path}")
    print(f"Listening on {iface}... (Ctrl+C to stop)\n")

    seen_offenders = defaultdict(set)  # mac -> set of bad domains contacted
    log_file = open(log_path, "a")

    def handle_packet(pkt):
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
        except Exception:
            return

        if not any(qname == d or qname.endswith("." + d) for d in blocklist):
            return

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown-mac"
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown-ip"

        if qname not in seen_offenders[src_mac]:
            seen_offenders[src_mac].add(qname)
            event = {
                "time": datetime.datetime.now().isoformat(timespec="seconds"),
                "mac": src_mac,
                "ip": src_ip,
                "domain": qname,
            }
            line = json.dumps(event)
            print(f"[ALERT] {src_ip} ({src_mac}) queried blocked domain: {qname}")
            log_file.write(line + "\n")
            log_file.flush()

            if do_block:
                block_device(src_ip, dry_run)

    try:
        sniff(iface=iface, filter="udp port 53", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Permission denied — try running with sudo.")
    finally:
        log_file.close()
        print(f"\nStopped. {len(seen_offenders)} offending device(s) logged to {log_path}.")


# ---------------------------------------------------------------------
# Containment: local firewall block (NOT a wireless attack)
# ---------------------------------------------------------------------

def block_device(ip: str, dry_run: bool) -> None:
    """
    Blocks an IP at this host's firewall. This only affects traffic
    passing through/to this machine (e.g. if it's acting as a gateway
    or you're running this on your router). It does not send any
    frames to the target device and does not disconnect it from the
    network at the radio level.
    """
    if dry_run:
        print(f"   [dry-run] would block {ip} via iptables")
        return

    if not shutil.which("iptables"):
        print(f"   [!] iptables not found — here's the rule to add manually on your router:")
        print(f"       iptables -A FORWARD -s {ip} -j DROP")
        return

    try:
        result = subprocess.run(
            ["iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"   (already blocked: {ip})")
            return
        result = subprocess.run(
            ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"   blocked {ip} (iptables FORWARD DROP)")
        else:
            print(f"   [!] failed to block {ip}: {result.stderr.strip()}")
    except Exception as e:
        print(f"   [!] failed to block {ip}: {e}")


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------

def report(log_path: str) -> None:
    p = Path(log_path)
    if not p.exists():
        print(f"No log found at {log_path} yet — run `monitor` first.")
        return

    events = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    if not events:
        print("Log is empty.")
        return

    by_device = defaultdict(list)
    for e in events:
        by_device[(e["mac"], e["ip"])].append(e)

    print(f"== Pwning Dutchman Report ({len(events)} event(s), {len(by_device)} device(s)) ==\n")
    for (mac, ip), evs in sorted(by_device.items(), key=lambda kv: -len(kv[1])):
        domains = sorted({e["domain"] for e in evs})
        print(f"Device {ip} ({mac}) — {len(evs)} alert(s)")
        for d in domains:
            print(f"    -> {d}")
        print()


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="dutchman",
        description="Pwning Dutchman — passive IoT threat monitor for your own network.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_mon = sub.add_parser("monitor", help="Watch DNS traffic for devices hitting blocked domains")
    p_mon.add_argument("--iface", required=True, help="Network interface to listen on")
    p_mon.add_argument("--blocklist", default="blocklist.txt", help="Path to blocklist file")
    p_mon.add_argument("--block", action="store_true", help="Auto-block offenders via local firewall")
    p_mon.add_argument("--dry-run", action="store_true", help="Log/alert only, never modify firewall")
    p_mon.add_argument("--log", default=LOG_PATH_DEFAULT, help="Path to write JSONL event log")

    p_up = sub.add_parser("update-blocklist", help="Fetch and merge live malware/tracking blocklists")
    p_up.add_argument("--out", default="blocklist.txt")
    p_up.add_argument("--source", action="append", default=None,
                       help="Hosts-format blocklist URL. Repeatable. "
                            "Default: abuse.ch URLhaus + StevenBlack unified hosts.")

    p_rep = sub.add_parser("report", help="Summarize a past monitoring log")
    p_rep.add_argument("--log", default=LOG_PATH_DEFAULT)

    args = parser.parse_args()

    banner.show("PWNING DUTCHMAN", "passive IoT threat detection & containment")

    if args.command == "monitor":
        monitor(args.iface, args.blocklist, args.block, args.dry_run, args.log)
    elif args.command == "update-blocklist":
        update_blocklist(args.out, args.source)  # args.source is None -> DEFAULT_SOURCES
    elif args.command == "report":
        report(args.log)


if __name__ == "__main__":
    main()
