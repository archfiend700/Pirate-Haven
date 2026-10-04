#!/usr/bin/env python3
"""
Nassau — Privacy Hardening Script
===================================
A simple, auditable CLI for reducing your own exposure to tracking:
  1. Clean browser cache/cookies/history (local profiles only)
  2. Strip EXIF/metadata from files before you share them
  3. Report on local telemetry / tracking settings
  4. Toggle MAC address randomization for your own Wi-Fi adapter

Everything here acts only on YOUR machine, YOUR files, and YOUR
browser profiles. Nothing here touches other people's devices,
accounts, or data, and nothing here destroys evidence of anything —
it just reduces how much of your own activity gets fingerprinted.

Tested target: Linux (Debian/Ubuntu-family). Some features degrade
gracefully with a warning on macOS/Windows.

Usage:
    python3 nassau.py clean-browser [--browser firefox|chrome|all] [--dry-run]
    python3 nassau.py strip-metadata <file_or_dir> [--recursive] [--dry-run]
    python3 nassau.py audit
    python3 nassau.py mac-random <interface> [--on|--off]
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import banner  # noqa: E402

# ---------------------------------------------------------------------
# 1. Browser cache / cookie / history cleanup
# ---------------------------------------------------------------------

# Paths are relative to $HOME. Add more profiles as needed.
BROWSER_PATHS = {
    "firefox": [
        ".mozilla/firefox",
    ],
    "chrome": [
        ".config/google-chrome",
        ".config/chromium",
    ],
}

# Within a profile dir, these are the files/dirs that hold the
# trackable state we're clearing. We deliberately do NOT touch
# bookmarks, saved passwords, or extensions.
FIREFOX_CLEAR_TARGETS = [
    "cookies.sqlite",
    "places.sqlite",  # history + bookmarks are both in here in Firefox;
                        # we only vacuum history rows, see clear_firefox_history()
    "cache2",
    "startupCache",
    "sessionstore.jsonlz4",
]

CHROME_CLEAR_TARGETS = [
    "Default/Cookies",
    "Default/History",
    "Default/Cache",
    "Default/Code Cache",
    "Default/GPUCache",
]


def _human(path: Path) -> str:
    return str(path).replace(str(Path.home()), "~")


def clear_firefox_history(profile_dir: Path, dry_run: bool) -> list[str]:
    """Delete browsing history rows from places.sqlite but keep bookmarks."""
    import sqlite3
    import tempfile

    actions = []
    places = profile_dir / "places.sqlite"
    if not places.exists():
        return actions

    if dry_run:
        actions.append(f"[dry-run] would clear history rows in {_human(places)}")
        return actions

    # sqlite can't be safely edited while Firefox has it open & locked,
    # so copy, edit, and swap back.
    tmp = Path(tempfile.mktemp(suffix=".sqlite"))
    try:
        shutil.copy2(places, tmp)
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        # moz_historyvisits holds visit events; moz_places holds URL rows.
        # Deleting visits + places not referenced by bookmarks clears
        # history while preserving bookmarked URLs.
        cur.execute("DELETE FROM moz_historyvisits;")
        cur.execute("""
            DELETE FROM moz_places
            WHERE id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL);
        """)
        conn.commit()
        conn.close()
        shutil.copy2(tmp, places)
        actions.append(f"cleared history rows in {_human(places)} (bookmarks kept)")
    except Exception as e:
        actions.append(f"could not clear {_human(places)}: {e}")
    finally:
        tmp.unlink(missing_ok=True)
    return actions


def clear_path(path: Path, dry_run: bool) -> str | None:
    if not path.exists():
        return None
    if dry_run:
        return f"[dry-run] would remove {_human(path)}"
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return f"removed {_human(path)}"
    except Exception as e:
        return f"could not remove {_human(path)}: {e}"


def find_firefox_profiles(home: Path) -> list[Path]:
    base = home / ".mozilla/firefox"
    if not base.exists():
        return []
    profiles = []
    ini = base / "profiles.ini"
    if ini.exists():
        for line in ini.read_text(errors="ignore").splitlines():
            if line.startswith("Path="):
                p = base / line.split("=", 1)[1].strip()
                if p.exists():
                    profiles.append(p)
    return profiles


def clean_browser(browser: str, dry_run: bool) -> None:
    home = Path.home()
    system = platform.system()
    if system != "Linux":
        print(f"[!] This cleaner targets Linux browser profile layouts; "
              f"detected {system}. Paths below may not match — review before running for real.")

    targets = ["firefox", "chrome"] if browser == "all" else [browser]
    any_found = False

    for b in targets:
        if b == "firefox":
            profiles = find_firefox_profiles(home)
            if not profiles:
                continue
            any_found = True
            print(f"\n== Firefox ({len(profiles)} profile(s)) ==")
            for prof in profiles:
                print(f"-- profile: {_human(prof)}")
                for name in FIREFOX_CLEAR_TARGETS:
                    if name == "places.sqlite":
                        continue  # handled separately below
                    msg = clear_path(prof / name, dry_run)
                    if msg:
                        print("   " + msg)
                for msg in clear_firefox_history(prof, dry_run):
                    print("   " + msg)

        elif b == "chrome":
            for rel in BROWSER_PATHS["chrome"]:
                base = home / rel
                if not base.exists():
                    continue
                any_found = True
                print(f"\n== {rel} ==")
                for target in CHROME_CLEAR_TARGETS:
                    msg = clear_path(base / target, dry_run)
                    if msg:
                        print("   " + msg)

    if not any_found:
        print("No supported browser profiles found on this machine.")


# ---------------------------------------------------------------------
# 2. Metadata / EXIF stripping
# ---------------------------------------------------------------------

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".heic"}
DOC_EXTS = {".pdf", ".docx", ".xlsx", ".pptx"}


def strip_image_metadata(path: Path, dry_run: bool) -> str:
    try:
        from PIL import Image
    except ImportError:
        return f"skipped {_human(path)}: Pillow not installed (pip install Pillow)"

    if dry_run:
        return f"[dry-run] would strip EXIF/metadata from {_human(path)}"

    try:
        img = Image.open(path)
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)
        clean.save(path)
        return f"stripped metadata: {_human(path)}"
    except Exception as e:
        return f"could not strip {_human(path)}: {e}"


def strip_pdf_metadata(path: Path, dry_run: bool) -> str:
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        return f"skipped {_human(path)}: pypdf not installed (pip install pypdf)"

    if dry_run:
        return f"[dry-run] would strip metadata from {_human(path)}"

    try:
        reader = PdfReader(path)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({})
        with open(path, "wb") as f:
            writer.write(f)
        return f"stripped metadata: {_human(path)}"
    except Exception as e:
        return f"could not strip {_human(path)}: {e}"


def strip_metadata(target: str, recursive: bool, dry_run: bool) -> None:
    root = Path(target).expanduser()
    if not root.exists():
        print(f"[!] path not found: {target}")
        return

    files = []
    if root.is_file():
        files = [root]
    else:
        pattern = "**/*" if recursive else "*"
        files = [p for p in root.glob(pattern) if p.is_file()]

    if not files:
        print("No files found to process.")
        return

    for f in files:
        ext = f.suffix.lower()
        if ext in IMAGE_EXTS:
            print(strip_image_metadata(f, dry_run))
        elif ext == ".pdf":
            print(strip_pdf_metadata(f, dry_run))
        elif ext in DOC_EXTS:
            print(f"skipped {_human(f)}: Office metadata stripping not yet implemented "
                  f"(Office XML docs store metadata in docProps/core.xml inside the zip)")
        # silently skip unrelated file types


# ---------------------------------------------------------------------
# 3. Local telemetry / tracking audit (report only — never disables
#    anything without being asked, and never touches system/security
#    logging).
# ---------------------------------------------------------------------

def audit() -> None:
    print("== Nassau Privacy Audit ==\n")
    system = platform.system()
    print(f"System: {system} / {platform.platform()}\n")

    checks = []

    # Browser telemetry hints (just reads prefs, doesn't change them)
    home = Path.home()
    for prof in find_firefox_profiles(home):
        prefs = prof / "prefs.js"
        if prefs.exists():
            text = prefs.read_text(errors="ignore")
            telemetry_on = '"toolkit.telemetry.enabled", true' in text
            checks.append((
                f"Firefox telemetry ({_human(prof)})",
                "ENABLED" if telemetry_on else "likely disabled/default",
            ))

    # OS-level hints (Linux)
    if system == "Linux":
        if shutil.which("systemctl"):
            try:
                out = subprocess.run(
                    ["systemctl", "list-unit-files", "--type=service"],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                for svc in ["whoopsie", "apport", "popularity-contest"]:
                    if svc in out:
                        checks.append((f"{svc}.service present", "check if you want it running"))
            except Exception:
                pass

    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "link"], capture_output=True, text=True, timeout=5).stdout
            checks.append(("Network interfaces found", str(out.count(": <"))))
        except Exception:
            pass

    if not checks:
        print("No specific telemetry signals detected with the current checks "
              "(this is a lightweight heuristic audit, not exhaustive).")
    else:
        width = max(len(c[0]) for c in checks) + 2
        for name, status in checks:
            print(f"  {name:<{width}} {status}")

    print("\nThis audit only reads configuration — it changes nothing. "
          "Use clean-browser / mac-random to act on what you find here.")


# ---------------------------------------------------------------------
# 4. MAC randomization toggle (your own adapter only)
# ---------------------------------------------------------------------

def mac_random(interface: str, enable: bool) -> None:
    if platform.system() != "Linux":
        print("[!] mac-random currently supports Linux (NetworkManager) only.")
        return

    if not shutil.which("nmcli"):
        print("[!] nmcli not found. NetworkManager is required for this feature.\n"
              "    Install it, or set wifi.scan-rand-mac-address via your "
              "distro's network manager manually.")
        return

    value = "yes" if enable else "no"
    print(f"Setting wifi MAC randomization for scans to: {value}")
    try:
        subprocess.run(
            ["nmcli", "radio", "wifi"], capture_output=True, text=True, timeout=5
        )
        # Per-connection randomization setting (cloned-mac-address) is the
        # real per-connection toggle; wifi.scan-rand-mac-address covers scans.
        result = subprocess.run(
            ["nmcli", "connection", "modify", interface,
             "802-11-wireless.cloned-mac-address", "random" if enable else "permanent"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            print(f"Updated connection '{interface}': cloned-mac-address = "
                  f"{'random' if enable else 'permanent'}")
            print("Reconnect the interface for this to take effect:")
            print(f"  nmcli connection down {interface} && nmcli connection up {interface}")
        else:
            print(f"[!] nmcli error: {result.stderr.strip()}")
            print("    Check the connection name with: nmcli connection show")
    except Exception as e:
        print(f"[!] failed: {e}")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="nassau",
        description="Nassau — your safe harbour.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_clean = sub.add_parser("clean-browser", help="Clear your own browser cache/cookies/history")
    p_clean.add_argument("--browser", choices=["firefox", "chrome", "all"], default="all")
    p_clean.add_argument("--dry-run", action="store_true", help="Show what would happen, change nothing")

    p_strip = sub.add_parser("strip-metadata", help="Strip EXIF/metadata from a file or directory")
    p_strip.add_argument("target", help="File or directory path")
    p_strip.add_argument("--recursive", action="store_true")
    p_strip.add_argument("--dry-run", action="store_true")

    sub.add_parser("audit", help="Report on local telemetry/tracking settings (read-only)")

    p_mac = sub.add_parser("mac-random", help="Toggle MAC randomization for a Wi-Fi connection")
    p_mac.add_argument("interface", help="NetworkManager connection name (see: nmcli connection show)")
    group = p_mac.add_mutually_exclusive_group(required=True)
    group.add_argument("--on", action="store_true")
    group.add_argument("--off", action="store_true")

    args = parser.parse_args()

    banner.show("NASSAU", "your safe harbour")

    if args.command == "clean-browser":
        clean_browser(args.browser, args.dry_run)
    elif args.command == "strip-metadata":
        strip_metadata(args.target, args.recursive, args.dry_run)
    elif args.command == "audit":
        audit()
    elif args.command == "mac-random":
        mac_random(args.interface, enable=args.on)


if __name__ == "__main__":
    main()
