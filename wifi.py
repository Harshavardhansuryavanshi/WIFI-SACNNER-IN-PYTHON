#scans the wifi

import sys
import subprocess
import platform
import time
import threading
import re
from collections import namedtuple

Network = namedtuple("Network", ["ssid", "bssid", "signal", "channel", "security"])

def parse_netsh(output: str):
    """Parse Windows netsh wlan show networks mode=Bssid"""
    networks = []
    ssid = None
    bssid = None
    signal = None
    channel = None
    security = None

    # netsh output is in lines like "SSID 1 : MyNetwork" and "BSSID 1 : 00:11:22:..."
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID "):
            # SSID 1 : MyNetwork
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
        elif line.startswith("BSSID "):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                bssid = parts[1].strip()
        elif line.startswith("Signal"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                # "80%" -> parse to int
                signal = parts[1].strip().rstrip('%')
                try:
                    signal = int(signal)
                except:
                    pass
        elif line.startswith("Channel"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                channel = parts[1].strip()
        elif line.startswith("Authentication") or line.startswith("Encryption") or line.startswith("Network type"):
            # rough capture of security field
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                security = (security + " " + parts[1].strip()) if security else parts[1].strip()

        # If we have ssid & bssid, create entry (netsh lists multiple BSSIDs per SSID)
        if ssid and bssid:
            networks.append(Network(ssid=ssid, bssid=bssid, signal=signal, channel=channel, security=security))
            # reset bssid/signal/channel/security to allow multiple BSSIDs under same SSID
            bssid = None
            signal = None
            channel = None
            security = None

    return networks

def parse_nmcli(output: str):
    """
    nmcli -t -f SSID,BSSID,SIGNAL,CHAN,SECURITY dev wifi
    Terse format uses ':' separator by default.
    """
    networks = []
    for line in output.splitlines():
        if not line:
            continue
        parts = line.split(":")
        # parts: SSID:BSSID:SIGNAL:CHAN:SECURITY
        ssid = parts[0] if len(parts) > 0 else ""
        bssid = parts[1] if len(parts) > 1 else ""
        signal = None
        if len(parts) > 2 and parts[2].isdigit():
            signal = int(parts[2])
        channel = parts[3] if len(parts) > 3 else None
        security = parts[4] if len(parts) > 4 else None
        networks.append(Network(ssid=ssid, bssid=bssid, signal=signal, channel=channel, security=security))
    return networks

def parse_iwlist(output: str):
    """Simple iwlist parsing — best-effort only."""
    networks = []
    cells = re.split(r"Cell \d+ - ", output)
    for cell in cells[1:]:
        bssid_m = re.search(r"Address: ([0-9A-Fa-f:]{17})", cell)
        essid_m = re.search(r'ESSID:"(.*)"', cell)
        signal_m = re.search(r"Signal level[=|:]\s*([-0-9]+)", cell)
        channel_m = re.search(r"Channel:(\d+)", cell)
        # Encryption info
        enc_m = re.search(r"Encryption key:(on|off)", cell)
        security = None
        if enc_m:
            security = "on" if enc_m.group(1) == "on" else "off"
        networks.append(Network(
            ssid=essid_m.group(1) if essid_m else "",
            bssid=bssid_m.group(1) if bssid_m else "",
            signal=int(signal_m.group(1)) if signal_m else None,
            channel=channel_m.group(1) if channel_m else None,
            security=security
        ))
    return networks

def parse_airport(output: str):
    """macOS airport -s parsing"""
    networks = []
    lines = output.splitlines()
    if not lines:
        return networks
    header = lines[0]
    # Airport columns: SSID BSSID RSSI CHANNEL HT CC SECURITY (but spacing can vary)
    for line in lines[1:]:
        if not line.strip():
            continue
        # use regex: SSID may have spaces; BSSID is MAC -> find MAC then split
        mac_match = re.search(r"([0-9A-Fa-f:]{17})", line)
        if not mac_match:
            continue
        bssid = mac_match.group(1)
        before = line[:mac_match.start()].strip()
        after = line[mac_match.end():].strip()
        ssid = before
        parts_after = after.split()
        signal = None
        channel = None
        security = None
        if parts_after:
            try:
                signal = int(parts_after[0])  # RSSI
            except:
                pass
        if len(parts_after) > 1:
            channel = parts_after[1]
        if len(parts_after) > 4:
            security = " ".join(parts_after[4:])
        networks.append(Network(ssid=ssid, bssid=bssid, signal=signal, channel=channel, security=security))
    return networks

class WifiScanner:
    def __init__(self):
        self.system = platform.system()
        self.prev = {}  # bssid -> Network
        self.lock = threading.Lock()

    def scan_once(self):
        try:
            if self.system == "Windows":
                cmd = ["netsh", "wlan", "show", "networks", "mode=Bssid"]
                out = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
                nets = parse_netsh(out)
            elif self.system == "Darwin":
                # macOS
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                cmd = [airport_path, "-s"]
                out = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
                nets = parse_airport(out)
            else:
                # Assume Linux
                # Try nmcli first (more consistent)
                try:
                    cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"]
                    out = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
                    nets = parse_nmcli(out)
                except (FileNotFoundError, subprocess.CalledProcessError):
                    # fallback to iwlist (may require root)
                    try:
                        # try scanning interface wlan0 first; if user has other interface, they can change
                        cmd = ["iwlist", "scanning"]
                        out = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
                        nets = parse_iwlist(out)
                    except Exception as e:
                        print("Failed to scan (nmcli and iwlist not available or require privileges):", e)
                        nets = []
            # Normalize BSSID keys (lowercase)
            normalized = {}
            for n in nets:
                key = (n.bssid or n.ssid or "").lower()
                normalized[key] = n
            return normalized
        except Exception as e:
            print("Scan error:", e)
            return {}

    def diff_and_report(self, new):
        added = []
        removed = []
        changed = []

        with self.lock:
            old = self.prev
            # added or updated
            for k, v in new.items():
                if k not in old:
                    added.append(v)
                else:
                    # compare signal or channel or ssid change
                    o = old[k]
                    if (v.signal != o.signal) or (v.ssid != o.ssid) or (v.channel != o.channel) or (v.security != o.security):
                        changed.append((o, v))
            # removed
            for k, v in old.items():
                if k not in new:
                    removed.append(v)

            self.prev = new

        # Print summary
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        if added or removed or changed:
            print(f"\n[{t}] Scan results change:")
        if added:
            print(f"  + Added ({len(added)}):")
            for a in added:
                print(f"     SSID: {a.ssid!r}, BSSID: {a.bssid}, Signal: {a.signal}, Chan: {a.channel}, Sec: {a.security}")
        if removed:
            print(f"  - Removed ({len(removed)}):")
            for r in removed:
                print(f"     SSID: {r.ssid!r}, BSSID: {r.bssid}")
        if changed:
            print(f"  * Changed ({len(changed)}):")
            for o, v in changed:
                print(f"     BSSID: {v.bssid}, SSID: {o.ssid!r} -> {v.ssid!r}, Signal: {o.signal} -> {v.signal}")

        if not (added or removed or changed):
            print(f"[{t}] No changes (networks: {len(new)})")

    def start(self, interval=5, iterations=None):
        """
        Start continuous scanning every interval seconds.
        If iterations is None, runs forever (Ctrl+C to stop). Otherwise runs specified times.
        """
        try:
            count = 0
            while True:
                new = self.scan_once()
                self.diff_and_report(new)
                count += 1
                if iterations is not None and count >= iterations:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopping scanner (keyboard interrupt).")

if __name__ == "__main__":
    scanner = WifiScanner()
    print("Starting Wi-Fi scanner. Platform:", platform.system())
    print("Scanning every 5 seconds. Press Ctrl+C to stop.")
    scanner.start(interval=5)

    

    