# TODO — Raspberry Pi Cybersecurity Educational Tool

> Last updated: 2026-02-18
> Score: **6/100** (Proof-of-Concept / Educational Framework)

---

## P1 — Critical Fixes (2–4 hours)

- [x] Fix `from Crypto.*` → `from Cryptodome.*` import bug in `decrypt_data.py`, `src/tools/decrypt_data.py`, `src/tools/encrypt_data.py`
- [ ] Add `pip3 install -r requirements.txt` to `scripts/setup.sh` (`install_dependencies()` only installs `pycryptodomex` manually, ignores `requirements.txt`)
- [ ] Add USB gadget mode script using `libcomposite` (kernel configfs) — currently only `dtoverlay=dwc2` in setup.sh but no actual gadget code
- [ ] Write real unit tests in `tests/test_cybersec_tool.py` (all tests are `assert True` placeholders)

## P2 — Core Functionality (8–16 hours)

- [ ] **Browser credential decryption** — payloads only copy locked SQLite DB files; need DPAPI (Windows) / Keychain (macOS) decryption logic
- [ ] **WiFi password extraction** — `netsh wlan show profile` output needs XML parsing, macOS needs `security find-generic-password`
- [ ] **HID keyboard injection** — no keystroke simulation; need `/dev/hidg0` gadget + HID report descriptor
- [ ] **Auto-execution on plug-in** — no autorun; need mass-storage + HID composite gadget or `autorun.inf` alternative
- [ ] **Payload error handling** — both `windows_payload.ps1` and `macos_payload.sh` lack edge-case handling (locked files, missing dirs, permission denied)

## P3 — Advanced Features (16+ hours)

- [ ] Network exfiltration channel (HTTP/DNS/BLE)
- [ ] Anti-forensics (log wiping, timestomping, secure deletion)
- [ ] Payload obfuscation / encoding
- [ ] Composite USB device (HID + mass-storage simultaneously)
- [ ] Live progress indicator on Pi (LED / OLED)

## P4 — Code Quality & Maintenance

- [ ] Refactor `src/tools/advanced_security.py` (1924 lines — bloated, split into modules)
- [ ] Remove hardcoded paths (`/mnt/usb_share`, `/Volumes/TRUSTED_DRIVE`, `D:`) — use config file or env vars
- [ ] Add CI pipeline (GitHub Actions) with linting + tests
- [ ] Add `pre-commit` hooks (black, flake8, mypy)
- [ ] Add type hints to all public APIs
- [ ] Add `--dry-run` flag to payloads for safe classroom demos

## P5 — Documentation

- [ ] Add architecture diagram (Mermaid) to README.md
- [ ] Document config.txt / modules / fstab changes made by setup.sh
- [ ] Add "How to verify it works" section to hardware-setup.md
- [ ] Add troubleshooting FAQ

---

## What Works Today

| Component | Status |
|-----------|--------|
| Demo mode / sample scenarios | ✅ Working |
| Training / educational content | ✅ Working |
| AES-256-GCM encrypt/decrypt | ✅ Working (import fixed) |
| OS detection | ✅ Working |
| USB HID attack | ❌ Not implemented |
| Browser password extraction | ❌ Stub only (copies locked files) |
| WiFi credential harvesting | ❌ Stub only |
| Auto-execution on plug-in | ❌ Not implemented |
| Real test suite | ❌ Placeholders only |