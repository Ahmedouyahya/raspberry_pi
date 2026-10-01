# The Complete Guide — Raspberry Pi Cybersecurity Education Tool

> **Author:** Ahmedouyahya (Mr.D137)
> **Version:** 1.0.0
> **Last updated:** 2026-02-18
> **Skill level:** Beginner → Intermediate

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Who Is This For?](#2-who-is-this-for)
3. [What You Will Need (Shopping List)](#3-what-you-will-need-shopping-list)
4. [Setting Up Your Computer (Before You Touch the Pi)](#4-setting-up-your-computer-before-you-touch-the-pi)
5. [Setting Up the Raspberry Pi Hardware](#5-setting-up-the-raspberry-pi-hardware)
6. [Installing the Software on the Pi](#6-installing-the-software-on-the-pi)
7. [Running the Tool — Every Mode Explained](#7-running-the-tool--every-mode-explained)
8. [Running the Tests](#8-running-the-tests)
9. [Understanding the Project Structure](#9-understanding-the-project-structure)
10. [Use Cases — Real-World Scenarios](#10-use-cases--real-world-scenarios)
11. [What Works Today and What Does Not](#11-what-works-today-and-what-does-not)
12. [Future Improvements — Roadmap](#12-future-improvements--roadmap)
13. [Troubleshooting — Common Problems & Fixes](#13-troubleshooting--common-problems--fixes)
14. [Glossary — Cybersecurity Terms for Beginners](#14-glossary--cybersecurity-terms-for-beginners)
15. [Legal & Ethical Rules (Read This!)](#15-legal--ethical-rules-read-this)
16. [FAQ](#16-faq)

---

## 1. What Is This Project?

This project turns a tiny, $15 computer (the **Raspberry Pi Zero**) into a
**cybersecurity teaching tool**. It demonstrates how USB-based attacks work so
that students, teachers, and security professionals can understand — and defend
against — them.

### What does it actually do?

| Feature | What it demonstrates |
|---------|---------------------|
| **Demo mode** | Generates fake (safe) attack scenarios for classroom use |
| **Training mode** | Interactive lessons on USB attacks, encryption, ethics, etc. |
| **Encryption module** | Real AES-256-GCM encryption/decryption you can test |
| **OS detection** | Detects whether the connected machine is Windows, macOS, or Linux |
| **Payload scripts** | Example scripts showing *what* an attacker could try to collect |
| **Decryption utility** | Lets you decrypt and analyze collected (demo) data |

### What it is NOT

This is **not** a working attack tool you can plug in and hack someone.
It is an **educational framework** — like a textbook with runnable examples.
The payloads copy files but cannot decrypt browser passwords, simulate
keystrokes, or auto-run when plugged in. See
[Section 11](#11-what-works-today-and-what-does-not) for the full picture.

---

## 2. Who Is This For?

| Person | How to use this project |
|--------|------------------------|
| **Complete beginner** | Follow this guide start-to-finish. Read the glossary in Section 14. |
| **CS / cybersecurity student** | Focus on Sections 7, 8, 10. Run the demo and training modes. Read the source code. |
| **Teacher / instructor** | Use demo mode in class (Section 7). Fork the repo and assign improvements as homework. |
| **Penetration tester** | Use this as a proof-of-concept skeleton. Sections 11 & 12 list what needs work. |
| **CTF / HackTheBox player** | Study the encryption module and payload structure for ideas. |

---

## 3. What You Will Need (Shopping List)

### Required

| Item | Why you need it | Approx. cost | Where to buy |
|------|-----------------|--------------|--------------|
| **Raspberry Pi Zero WH** | The tiny computer that runs everything | ~$15 | [raspberrypi.com](https://www.raspberrypi.com/products/raspberry-pi-zero-w/) |
| **MicroSD card (16 GB+)** | Stores the operating system and our code | ~$8 | Any electronics store |
| **Micro-USB OTG cable** | Connects the Pi to a target computer | ~$5 | Amazon / AliExpress |
| **A regular computer** | Used to set up the Pi (any OS works) | You already have one | — |
| **Internet connection** | To download software | — | — |

### Optional (nice to have)

| Item | Why | Cost |
|------|-----|------|
| USB Wi-Fi dongle | Extra network interface for monitoring | ~$10 |
| 220 Ω resistor + LED | Status light on the Pi | ~$1 |
| Pi Zero case | Physical protection | ~$5 |
| Heat sink | Keeps the Pi cool under load | ~$2 |

**Total minimum cost: ~$28**

---

## 4. Setting Up Your Computer (Before You Touch the Pi)

You need a few tools installed on the computer you will use to *set up*
the Pi. This is not the target computer — this is **your** workstation.

### 4.1 Install Git

Git lets you download this project's code.

**Linux (Debian/Ubuntu/Parrot/Kali):**

```bash
sudo apt update && sudo apt install -y git
```

**macOS:**

```bash
xcode-select --install        # installs git automatically
```

**Windows:**

Download from <https://git-scm.com/downloads> and run the installer.
Accept all defaults.

Verify it works:

```bash
git --version
# Expected output: git version 2.x.x
```

### 4.2 Install Python 3.8+

Most Linux distros and macOS already have Python 3. Check:

```bash
python3 --version
# Expected: Python 3.8 or higher
```

If you do not have it:

- **Linux:** `sudo apt install -y python3 python3-pip python3-venv`
- **macOS:** `brew install python` (install [Homebrew](https://brew.sh) first)
- **Windows:** Download from <https://www.python.org/downloads/>. During
  install, check **"Add Python to PATH"**.

### 4.3 Install Raspberry Pi Imager

This program writes the operating system to the SD card.

Download: <https://www.raspberrypi.com/software/>

Available for Windows, macOS, and Linux.

### 4.4 Clone This Repository

```bash
cd ~/Desktop          # or wherever you keep projects
git clone https://github.com/Ahmedouyahya/raspberry_pi.git
cd raspberry_pi
```

You now have the project on your machine.

---

## 5. Setting Up the Raspberry Pi Hardware

### 5.1 Flash the SD Card

1. Insert the MicroSD card into your computer.
2. Open **Raspberry Pi Imager**.
3. Click **"Choose OS"** → Raspberry Pi OS (other) → **Raspberry Pi OS Lite (32-bit)**.
   - We use Lite because the Pi Zero has limited RAM and no screen.
4. Click **"Choose Storage"** → select your SD card.
5. Click the **gear icon** (⚙️) for advanced options:
   - **Enable SSH** — turn this ON.
   - **Set username and password** — for example `pi` / `raspberry` (change this later!).
   - **Configure Wi-Fi** — enter your network name and password.
   - **Set locale** — choose your timezone and keyboard layout.
6. Click **"Write"** and wait. This takes a few minutes.

> **Alternative (command line on Linux/macOS):**
> ```bash
> # Download the image
> wget https://downloads.raspberrypi.org/raspios_lite_armhf_latest
>
> # Find your SD card (BE CAREFUL — wrong device = data loss!)
> lsblk
>
> # Flash (replace /dev/sdX with your SD card)
> sudo dd if=raspios-lite.img of=/dev/sdX bs=4M status=progress
> sync
>
> # Enable SSH
> sudo mount /dev/sdX1 /mnt
> sudo touch /mnt/ssh
> sudo umount /mnt
> ```

### 5.2 First Boot

1. Remove the SD card from your computer.
2. Insert it into the Pi Zero.
3. Plug a micro-USB power cable into the **PWR** port (not the other one).
4. Wait **2–3 minutes** — the first boot is slow.

### 5.3 Find the Pi on Your Network

Try these methods in order:

```bash
# Method 1: mDNS (works on most networks)
ping raspberrypi.local

# Method 2: Network scan (install nmap first: sudo apt install nmap)
nmap -sn 192.168.1.0/24    # adjust to your subnet

# Method 3: Check your router's admin page for connected devices
```

### 5.4 Connect via SSH

```bash
ssh pi@raspberrypi.local
# Or use the IP address:
ssh pi@192.168.1.XXX
```

Type `yes` when asked about the fingerprint, then enter your password.

**You are now inside the Pi.** Everything from here runs on the Pi
unless stated otherwise.

### 5.5 Initial System Configuration

```bash
# Update everything (takes a few minutes)
sudo apt update && sudo apt full-upgrade -y

# Change the default password (important for security!)
passwd

# Optional: configure locale, timezone, etc.
sudo raspi-config
```

### 5.6 USB Gadget Mode (Making the Pi Pretend to Be a USB Device)

This is the key hardware trick. The Pi Zero can pretend to be a USB
keyboard, USB drive, or both — just like a "Rubber Ducky" attack device.

**Step 1 — Edit `/boot/config.txt`:**

```bash
# Backup first
sudo cp /boot/config.txt /boot/config.txt.backup

# Add gadget configuration
sudo tee -a /boot/config.txt << 'EOF'

# USB Gadget Configuration for Cybersecurity Tool
dtoverlay=dwc2,dr_mode=peripheral
gpu_mem=16
dtparam=act_led_trigger=none
dtparam=act_led_activelow=on
disable_splash=1
EOF
```

**Step 2 — Load kernel modules on boot:**

```bash
# These modules enable USB device emulation
echo "dwc2" | sudo tee -a /etc/modules
echo "g_hid" | sudo tee -a /etc/modules
echo "g_mass_storage" | sudo tee -a /etc/modules
```

**Step 3 — Create virtual USB storage:**

The Pi needs a file that acts like a USB drive when plugged into a target
computer. The target sees a drive called "TRUSTED_DRIVE".

```bash
# Create a 2 GB disk image
sudo dd if=/dev/zero of=/piusb.bin bs=1M count=2048

# Format it as exFAT (readable by Windows, macOS, and Linux)
sudo apt install -y exfat-fuse exfat-utils
sudo mkfs.exfat -n "TRUSTED_DRIVE" /piusb.bin

# Create a mount point
sudo mkdir -p /mnt/usb_share

# Auto-mount on boot
echo "/piusb.bin /mnt/usb_share exfat defaults,uid=pi,gid=pi 0 0" | sudo tee -a /etc/fstab
sudo mount -a
```

**Step 4 — Reboot to apply:**

```bash
sudo reboot
```

After reboot, SSH back in and verify:

```bash
# Check modules loaded
lsmod | grep dwc2
# Expected: dwc2 listed

# Check virtual drive mounted
df -h | grep usb_share
# Expected: /piusb.bin mounted on /mnt/usb_share
```

---

## 6. Installing the Software on the Pi

### 6.1 Clone the Project (on the Pi)

```bash
cd ~
git clone https://github.com/Ahmedouyahya/raspberry_pi.git
cd raspberry_pi
```

### 6.2 Option A: Automated Setup (recommended)

The setup script does everything at once: installs packages, configures
USB gadget mode, deploys payloads, and creates a system service.

```bash
sudo chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

The script will:
1. Show a disclaimer — type `yes` to continue.
2. Update system packages.
3. Install Python dependencies from `requirements.txt`.
4. Configure USB gadget (same steps as Section 5.6).
5. Create virtual USB storage.
6. Deploy payload scripts to the USB drive.
7. Create a systemd service so the tool runs at boot.
8. Optimize the system (disable Bluetooth, reduce GPU memory, etc.).

### 6.3 Option B: Manual Setup (if you want to learn each step)

```bash
# 1. Create a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) Install development tools for testing
pip install -r requirements-dev.txt
```

That is it for the software. The USB gadget mode from Section 5.6 covers
the hardware side.

### 6.4 Verify the Installation

```bash
# Activate the venv (if you used manual setup)
source .venv/bin/activate

# Check that imports work
python3 -c "from Cryptodome.Cipher import AES; print('Crypto OK')"
python3 -c "from src.tools.detect_os import detect_os; print('OS detect:', detect_os())"
python3 -c "from src.tools.encrypt_data import SecureDataHandler; print('Encrypt OK')"
```

All three commands should print without errors.

---

## 7. Running the Tool — Every Mode Explained

The main entry point is `src/main.py`. It has four modes:

```
python3 src/main.py <mode> [options]
```

### 7.1 Demo Mode — Safe for Classrooms

```bash
python3 src/main.py demo
```

**What it does:** Generates a fake attack scenario with made-up data.
No real data is collected. Completely safe.

**Example output:**

```
🎓 Starting Educational Demo Mode...

This mode provides safe demonstrations of:
• USB attack vector concepts
• Data extraction techniques
• Defense strategies
• Incident response procedures

📋 Demo Scenario Created:
{
  "scenario": "Classroom Demonstration",
  "educational_purpose": "Show USB attack concepts without real data collection",
  "simulated_findings": {
    "system_info": {
      "os": "Demo OS",
      "hostname": "EDUCATION-PC",
      "username": "student"
    },
    ...
  }
}
```

**When to use:**
- Classroom presentations
- Conference talks
- Showing friends what the project does
- Any time you just want to see it work

### 7.2 Training Mode — Interactive Lessons

```bash
python3 src/main.py train
```

**What it does:** Presents a menu of five cybersecurity training modules.
Pick a number (1–5) and read the lesson.

**Available modules:**

| # | Module | What you learn |
|---|--------|---------------|
| 1 | USB Attack Vectors | How USB devices become weapons, types of attacks |
| 2 | Data Encryption Best Practices | AES-256, PBKDF2, key management |
| 3 | Incident Response Procedures | 5-step process: Identify → Contain → Eradicate → Recover → Lessons |
| 4 | Legal and Ethical Considerations | Laws (CFAA, GDPR, etc.), authorization requirements |
| 5 | Defense Strategies | Technical, administrative, and physical controls |

**When to use:**
- Self-study
- Preparing for a cybersecurity exam
- Understanding what each topic means before diving into code

### 7.3 Assessment Mode — Authorized Testing

```bash
python3 src/main.py assess
```

**What it does:** Asks if you have written authorization. If you say
"yes", it prints a message saying hardware setup is needed. This mode is
a **placeholder** — it does not actually perform attacks.

**When to use:**
- Only after you have a fully set up Pi with USB gadget mode
- Only on systems you own or have **explicit written permission** to test

### 7.4 Analysis Mode — Decrypt & Study Collected Data

```bash
python3 src/main.py analyze --data-file path/to/file.enc
```

**What it does:** Decrypts an encrypted data file and shows the contents.
Requires the Pi's serial number as the encryption key.

### 7.5 Standalone Decryption Utility

There's also a top-level script for decryption:

```bash
# Decrypt a real file
python3 decrypt_data.py collected_data.enc PI_SERIAL_NUMBER --analyze

# Or generate demo data (no Pi needed)
python3 decrypt_data.py --demo --analyze
```

**The `--demo` flag** is the easiest way to see what decrypted data looks
like without needing any encrypted files.

### 7.6 Verbose Mode

Add `-v` to any command for detailed logging:

```bash
python3 src/main.py demo -v
```

---

## 8. Running the Tests

The project has **27 real tests** covering encryption, OS detection,
payload validation, security checks, and integration.

### 8.1 Quick Start

```bash
# From the project root:
cd ~/raspberry_pi

# Activate virtual environment
source .venv/bin/activate

# Run all tests
python3 -m pytest tests/ -v
```

### 8.2 What the Tests Cover

| Test class | # Tests | What it checks |
|------------|---------|---------------|
| `TestEncryption` | 9 | Encrypt/decrypt round-trip, wrong password rejection, tampered data detection, empty payloads, large payloads, file I/O, metadata |
| `TestOSDetection` | 7 | Detection on current platform, platform string mocking (Windows/macOS/Linux), system details, backward compatibility |
| `TestPayloads` | 5 | Payload files exist, educational disclaimers present, correct shebang line |
| `TestEducationalContent` | 3 | README.md exists, SECURITY.md exists, legal guide exists |
| `TestSecurity` | 2 | No hardcoded passwords in source, no `eval()`/`exec()` in source |
| `TestIntegration` | 1 | Full encrypt → save → load → decrypt workflow |

### 8.3 Expected Output

```
tests/test_cybersec_tool.py::TestEncryption::test_encrypt_returns_bytes PASSED
tests/test_cybersec_tool.py::TestEncryption::test_encrypt_decrypt_cycle PASSED
tests/test_cybersec_tool.py::TestEncryption::test_wrong_password_fails PASSED
tests/test_cybersec_tool.py::TestEncryption::test_tampered_blob_fails PASSED
tests/test_cybersec_tool.py::TestEncryption::test_data_integrity PASSED
tests/test_cybersec_tool.py::TestEncryption::test_empty_payload PASSED
tests/test_cybersec_tool.py::TestEncryption::test_large_payload PASSED
tests/test_cybersec_tool.py::TestEncryption::test_store_and_load_file PASSED
tests/test_cybersec_tool.py::TestEncryption::test_metadata_fields_present PASSED
tests/test_cybersec_tool.py::TestOSDetection::test_detect_returns_known_os PASSED
... (27 total)
========================= 27 passed in ~1s =========================
```

### 8.4 Running Specific Test Groups

```bash
# Only encryption tests
python3 -m pytest tests/test_cybersec_tool.py -k "TestEncryption" -v

# Only OS detection
python3 -m pytest tests/test_cybersec_tool.py -k "TestOSDetection" -v

# Only security checks
python3 -m pytest tests/test_cybersec_tool.py -k "TestSecurity" -v
```

### 8.5 Running with Coverage Report

```bash
pip install pytest-cov
python3 -m pytest tests/ --cov=src --cov-report=term-missing -v
```

This shows you which lines of code are tested and which are not.

### 8.6 If Tests Fail

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'Cryptodome'` | pycryptodomex not installed | `pip install pycryptodomex` |
| `ImportError: cannot import name 'detect_os'` | Wrong Python path | Run from project root with venv activated |
| `SKIPPED (pycryptodomex not installed)` | Crypto library missing | `pip install pycryptodomex` |
| All tests say `assert True` | You have the old test file | Pull latest code: `git pull` |

---

## 9. Understanding the Project Structure

```
raspberry_pi/
│
├── src/                          # All source code lives here
│   ├── main.py                   # Main entry point — run this
│   ├── __init__.py               # Package marker
│   ├── payloads/                 # Scripts that run on the target computer
│   │   ├── windows_payload.ps1   # PowerShell script for Windows targets
│   │   └── macos_payload.sh      # Bash script for macOS targets
│   ├── tools/                    # Python modules
│   │   ├── __init__.py
│   │   ├── encrypt_data.py       # AES-256-GCM encryption
│   │   ├── decrypt_data.py       # Decryption + data analysis
│   │   ├── detect_os.py          # OS fingerprinting
│   │   ├── demo_generator.py     # Fake data for demos
│   │   ├── security_education.py # Training module engine
│   │   └── advanced_security.py  # Extended security features (large file)
│   ├── logs/                     # Runtime logs go here
│   └── reports/                  # Generated reports go here
│
├── tests/
│   └── test_cybersec_tool.py     # 27 real tests
│
├── scripts/
│   └── setup.sh                  # Automated Pi setup script
│
├── docs/                         # Documentation (you are here!)
│   ├── FULL_GUIDE.md             # This file
│   ├── hardware-setup.md         # Detailed hardware wiring guide
│   ├── usb-attacks-guide.md      # Educational: how USB attacks work
│   └── legal-ethical-guidelines.md # Laws and ethics
│
├── decrypt_data.py               # Standalone decryption utility
├── requirements.txt              # Python packages needed
├── requirements-dev.txt          # Extra packages for developers
├── pyproject.toml                # Python project metadata
├── TODO.md                       # What's done, what's left
├── SECURITY.md                   # Security policy
├── LICENSE                       # MIT license
└── README.md                     # Project overview
```

### Key files explained

| File | What it does | Beginner importance |
|------|-------------|---------------------|
| `src/main.py` | Everything starts here. Run `python3 src/main.py demo` to try it. | ⭐⭐⭐ |
| `src/tools/encrypt_data.py` | The encryption engine. Uses AES-256-GCM — this is real, working crypto. | ⭐⭐⭐ |
| `src/tools/detect_os.py` | Detects whether the machine is Windows, macOS, Linux, etc. | ⭐⭐ |
| `decrypt_data.py` | The tool you use on your own machine to read encrypted data. | ⭐⭐ |
| `tests/test_cybersec_tool.py` | Automated tests — run regularly to make sure nothing is broken. | ⭐⭐⭐ |
| `scripts/setup.sh` | Sets up the Pi automatically. Read it to learn what it does. | ⭐⭐ |
| `src/payloads/windows_payload.ps1` | Shows what a Windows attack script looks like. Educational only. | ⭐ |
| `src/payloads/macos_payload.sh` | Shows what a macOS attack script looks like. Educational only. | ⭐ |

---

## 10. Use Cases — Real-World Scenarios

### Use Case 1: Classroom Demonstration

**Scenario:** You are a teacher giving a cybersecurity class. You want to
show students what a USB attack looks like — without actually attacking
anything.

**Steps:**
1. Run `python3 src/main.py demo` on the projector.
2. Walk through the fake data and explain each field.
3. Ask students: "How would you defend against this?"
4. Run `python3 src/main.py train` and go through Module 5 (Defense Strategies).

**Time needed:** 30 minutes.

---

### Use Case 2: Self-Study — Understanding Encryption

**Scenario:** You want to understand how AES-256 encryption works in practice.

**Steps:**
1. Open `src/tools/encrypt_data.py` and read the comments.
2. Run the encryption demo:
   ```bash
   source .venv/bin/activate
   python3 -c "
   from src.tools.encrypt_data import SecureDataHandler
   handler = SecureDataHandler(storage_path='/tmp/demo')
   data = {'secret': 'hello world', 'number': 42}
   blob = handler.encrypt_data(data, password='my-password')
   print(f'Encrypted: {len(blob)} bytes')
   result = handler.decrypt_data(blob, password='my-password')
   print(f'Decrypted payload: {result[\"payload\"]}')
   "
   ```
3. Try decrypting with the wrong password and see what happens.
4. Read the test `test_wrong_password_fails` to see how this is verified.

**Time needed:** 1 hour.

---

### Use Case 3: Conference / Security Meetup Talk

**Scenario:** You are giving a 15-minute lightning talk at a security meetup.

**Steps:**
1. Set up the Pi Zero with the full hardware setup (Sections 5–6).
2. Connect the Pi to a **test laptop you own** via OTG cable.
3. Show the audience the Pi and explain what it is.
4. Run `python3 src/main.py demo` on the Pi over SSH.
5. Show the demo output on screen.
6. Discuss what a real attack would do vs. what this does.

**Time needed:** 2 hours preparation, 15 minutes presentation.

---

### Use Case 4: Authorized Penetration Test Practice

**Scenario:** You are learning penetration testing and want to practice
on your own machine.

**Steps:**
1. Complete the full hardware setup.
2. Write yourself a "permission letter" (even for your own machine — practice the process).
3. Plug the Pi into your own Windows / macOS machine.
4. Look at what the payloads *would* collect.
5. Check if your machine's defenses (antivirus, USB policies) detected anything.
6. Write up a report of your findings.

**Time needed:** Half a day.

---

### Use Case 5: Testing the Encryption Module in a CTF

**Scenario:** You're studying for a CTF competition and want to practice
crypto challenges.

**Steps:**
1. Encrypt data with a known password.
2. Try to decrypt it with different passwords.
3. Look at the raw encrypted blob — understand the `salt + nonce + tag + ciphertext` structure.
4. Try tampering with bytes and observe the authentication failure.

```bash
python3 -c "
from src.tools.encrypt_data import SecureDataHandler
h = SecureDataHandler(storage_path='/tmp/ctf')
blob = h.encrypt_data({'flag': 'CTF{encryption_works}'}, password='secret')

# Look at the structure
print(f'Total blob: {len(blob)} bytes')
print(f'Salt (first 16):  {blob[:16].hex()}')
print(f'Nonce (next 16):  {blob[16:32].hex()}')
print(f'Tag (next 16):    {blob[32:48].hex()}')
print(f'Ciphertext (rest): {blob[48:64].hex()}...')
"
```

---

### Use Case 6: Developing Your Own Payloads (For Authorized Testing)

**Scenario:** You want to add a Linux payload or extend the Windows one.

**Steps:**
1. Read the existing payloads to understand the pattern.
2. Create your new payload file in `src/payloads/`.
3. Follow the existing structure: disclaimer → functions → main logic.
4. Add a test for it in `tests/test_cybersec_tool.py`.
5. Run the tests to verify.

---

## 11. What Works Today and What Does Not

### Working (you can run these right now)

| Feature | How to try it |
|---------|--------------|
| Demo mode | `python3 src/main.py demo` |
| Training modules (5 modules) | `python3 src/main.py train` |
| AES-256-GCM encryption/decryption | Section 10, Use Case 2 |
| OS detection | `python3 -c "from src.tools.detect_os import detect_os; print(detect_os())"` |
| Decryption utility with demo mode | `python3 decrypt_data.py --demo --analyze` |
| Test suite (27 tests) | `python3 -m pytest tests/ -v` |

### Not working / not implemented yet

| Feature | Status | What's missing |
|---------|--------|----------------|
| USB HID keyboard injection | Not implemented | No code writes to `/dev/hidg0`. Would need a `libcomposite` gadget script with HID report descriptors. |
| Real browser password extraction | Stub only | Payloads copy the encrypted SQLite files, but do not decrypt them. Windows needs DPAPI; macOS needs Keychain access. |
| WiFi password extraction | Stub only | Windows payload runs `netsh wlan export` but doesn't parse XML output. macOS doesn't use `security find-generic-password`. |
| Auto-execution on plug-in | Not implemented | No autorun mechanism. A composite HID+mass-storage gadget would be needed. |
| Network exfiltration | Not implemented | No HTTP/DNS/BLE channel to send data remotely. |
| Anti-forensics | Not implemented | No log wiping, timestomping, or secure deletion of traces. |
| LED status indicator in code | Only in setup.sh | The `payload_runner.sh` blinks the LED, but no Python code uses GPIO. |

---

## 12. Future Improvements — Roadmap

### Priority 1 — Critical fixes (easy, 2–4 hours)

- [x] ~~Fix `from Crypto.*` → `from Cryptodome.*` import bug~~ ✅ Done
- [x] ~~Fix `setup.sh` to install from `requirements.txt`~~ ✅ Done
- [x] ~~Write real tests (replace placeholder `assert True`)~~ ✅ Done
- [x] ~~Fix broken `__init__.py` exports~~ ✅ Done
- [ ] Add USB gadget configuration script using `libcomposite` kernel configfs

### Priority 2 — Core functionality (medium, 8–16 hours)

- [ ] Browser credential decryption (DPAPI on Windows, Keychain on macOS)
- [ ] WiFi password parsing (XML on Windows, `security` command on macOS)
- [ ] HID keyboard injection (write to `/dev/hidg0`)
- [ ] Auto-execution — composite USB device (HID + mass storage)
- [ ] Better error handling in payloads (locked files, missing directories)

### Priority 3 — Advanced features (hard, 16+ hours)

- [ ] Network exfiltration (HTTP POST, DNS tunneling, or BLE)
- [ ] Anti-forensics module (educational — show how attackers cover tracks)
- [ ] Payload obfuscation and encoding
- [ ] Composite USB device (HID + mass storage simultaneously)
- [ ] OLED display for Pi-side status indicator
- [ ] Web UI for configuration and monitoring

### Priority 4 — Code quality

- [ ] Refactor `advanced_security.py` (1924 lines — split into modules)
- [ ] Replace hardcoded paths with config file / environment variables
- [ ] Add GitHub Actions CI pipeline
- [ ] Add pre-commit hooks (black, flake8, mypy)
- [ ] Add type hints everywhere
- [ ] Add `--dry-run` flag to payloads

### Priority 5 — Documentation

- [ ] Architecture diagram (Mermaid)
- [ ] Video walkthrough
- [ ] Troubleshooting FAQ with screenshots
- [ ] Translated versions (French, Arabic, Spanish)

### Ideas from the community (open for contributions)

- [ ] Android payload via ADB
- [ ] iOS profile-based payload
- [ ] Rubber Ducky script compatibility layer
- [ ] Integration with Metasploit / Cobalt Strike for training
- [ ] Scoring system for CTF-style challenges

---

## 13. Troubleshooting — Common Problems & Fixes

### Setup Problems

| Problem | Cause | Solution |
|---------|-------|----------|
| `pip install` says "externally managed environment" | Python 3.11+ on Debian/Ubuntu | Use a virtual environment: `python3 -m venv .venv && source .venv/bin/activate` |
| `ssh: Connection refused` | SSH not enabled on the Pi | Re-flash the SD card and enable SSH in Raspberry Pi Imager settings, or create an empty file called `ssh` in the boot partition |
| `ping raspberrypi.local` — no response | mDNS not supported on your network | Find the IP via your router's admin page or `nmap -sn 192.168.1.0/24` |
| `setup.sh` fails at `apt install` | Pi has no internet | Check Wi-Fi config: `iwconfig`, `ping google.com` |
| `ModuleNotFoundError: No module named 'Cryptodome'` | Package not installed | `pip install pycryptodomex` (note the `x` at the end!) |

### Runtime Problems

| Problem | Cause | Solution |
|---------|-------|----------|
| `python3 src/main.py demo` crashes with ImportError | Not running from project root | `cd ~/raspberry_pi` first. Or activate venv: `source .venv/bin/activate` |
| Encryption works but decryption fails | Wrong password/serial | Double-check: `cat /proc/cpuinfo \| grep Serial` on the Pi |
| USB drive not showing on target computer | Gadget mode not configured | Follow Section 5.6 exactly. Check: `lsmod \| grep dwc2` |
| Tests say "27 passed" but you see warnings | `datetime.utcnow()` deprecation | Already fixed in the latest code. Pull updates: `git pull` |

### Hardware Problems

| Problem | Cause | Solution |
|---------|-------|----------|
| Pi won't boot (no green LED activity) | Bad SD card or image | Re-flash the SD card. Try a different SD card. |
| Pi boots but no Wi-Fi | Wrong credentials or channel | Check `wpa_supplicant.conf`. Make sure your router uses 2.4 GHz (Pi Zero doesn't support 5 GHz). |
| OTG cable doesn't work | Cable is charge-only (no data pins) | Try a different cable. OTG cables have all 4 pins connected. |
| LED circuit doesn't work | Wrong GPIO pin or resistor value | Pin 11 = GPIO17 (not pin 17!). Use a 220 Ω resistor. Check LED polarity. |

---

## 14. Glossary — Cybersecurity Terms for Beginners

| Term | Meaning |
|------|---------|
| **AES-256** | Advanced Encryption Standard with 256-bit keys. One of the strongest encryption algorithms. Used by governments and banks. |
| **GCM** | Galois/Counter Mode. A way to use AES that provides both encryption (secrecy) and authentication (tamper detection). |
| **PBKDF2** | Password-Based Key Derivation Function 2. Turns a human password into an encryption key by hashing it many times (100,000 times in our tool). Makes brute-force attacks very slow. |
| **Salt** | Random data mixed with a password before hashing. Prevents attackers from using pre-computed tables ("rainbow tables"). |
| **Nonce** | "Number used once." Random value used in encryption to ensure the same data encrypted twice gives different outputs. |
| **HID** | Human Interface Device. A USB device class for keyboards and mice. A "BadUSB" attack makes a device pretend to be a keyboard. |
| **BadUSB** | An attack where a USB device has malicious firmware that makes it act as a keyboard to type commands on the target computer. |
| **Rubber Ducky** | A well-known commercial BadUSB device made by Hak5. Looks like a USB drive but acts as a keyboard. Our Pi Zero does a similar thing (educationally). |
| **OTG** | USB "On-The-Go." A type of cable that lets devices like the Pi Zero act as USB peripherals (pretend to be a keyboard or flash drive). |
| **USB Gadget Mode** | A Linux kernel feature that lets a device present itself as a USB peripheral. The Pi Zero supports this via the `dwc2` driver. |
| **libcomposite** | A Linux kernel module for creating composite USB gadgets (devices that are multiple things at once, like a keyboard AND a drive). |
| **DPAPI** | Data Protection API. Windows' built-in system for encrypting user data like browser passwords. Needed to actually decrypt Chrome passwords on Windows. |
| **Keychain** | macOS's system for storing passwords and certificates. Chrome on macOS stores its encryption key here. |
| **Exfiltration** | The act of stealing and sending data out of a network. Our tool only copies files locally — it does not exfiltrate over the network. |
| **Payload** | The code that runs on the target computer. In our project, this is the PowerShell (Windows) or Bash (macOS) scripts. |
| **Penetration testing** | Authorized "ethical hacking" — testing a system's defenses by trying to break in, with permission. |
| **EDR** | Endpoint Detection and Response. Software on a computer that watches for suspicious activity (like a USB device typing commands). |
| **CFAA** | Computer Fraud and Abuse Act. The main US law against unauthorized hacking. Violations can lead to prison time. |
| **GDPR** | General Data Protection Regulation. EU law about data privacy. Fines up to €20 million for violations. |

---

## 15. Legal & Ethical Rules (Read This!)

### The Golden Rules

1. **NEVER** use this tool on a computer you do not own without **explicit
   written permission** from the owner.
2. **NEVER** use this tool to steal real data from real people.
3. **ALWAYS** comply with your country's laws (see `docs/legal-ethical-guidelines.md`).
4. **ALWAYS** use demo mode when showing the tool to others.
5. If you find a vulnerability in someone's system, **report it
   responsibly** — do not exploit it.

### What could happen if you misuse this

| Country | Law | Maximum penalty |
|---------|-----|-----------------|
| United States | Computer Fraud and Abuse Act | 10+ years in prison, $250,000 fine |
| European Union | GDPR + national laws | €20 million fine or 4% of revenue |
| United Kingdom | Computer Misuse Act | 10 years in prison |
| Canada | Criminal Code §342.1 | 10 years in prison |
| Australia | Cybercrime Act 2001 | 10 years in prison |

**This is not a joke.** People have gone to prison for running tools like
this without permission.

### How to Get Permission

Before testing on any system, get a **signed document** that includes:
- What systems you are allowed to test
- What time window the test is authorized for
- What data you may collect
- How you must handle and destroy collected data
- Who to contact if something goes wrong

Even if you're testing your own machine at work, get this in writing from
your employer.

---

## 16. FAQ

### Q: Is this a real hacking tool?
**A:** No. It is an educational framework. The payloads exist as examples
but do not decrypt browser passwords, inject keystrokes, or auto-execute.
See Section 11 for what works and what doesn't.

### Q: Can I use this for a school project?
**A:** Yes! Demo mode and training mode are completely safe. Mention that
this is educational software in your submission.

### Q: Do I need a Raspberry Pi to try the software?
**A:** No. You can run the Python code on any computer. The Pi is only
needed for the USB gadget mode (pretending to be a USB device). The demo
mode, training mode, encryption module, and tests all work on any machine.

### Q: Which Raspberry Pi models work?
**A:** Only the **Pi Zero W** and **Pi Zero WH** support USB gadget mode
through the OTG port. The regular Pi 3/4/5 does NOT have this capability
on its standard USB ports.

### Q: I'm getting an error about `from Crypto.Cipher import AES`. What's wrong?
**A:** The package is called `pycryptodomex` but its import path is
`Cryptodome`, not `Crypto`. The code has been fixed. If you still see
this error, pull the latest code with `git pull`.

### Q: How do I contribute?
**A:** See `CONTRIBUTING.md`. Fork the repo, make your changes, write
tests, and submit a pull request. All contributions must be educational
and ethical.

### Q: Can this tool actually extract browser passwords?
**A:** Not in its current state. The payloads copy the browser's
encrypted database files, but those files are locked by the browser and
encrypted with DPAPI (Windows) or Keychain (macOS). Actual decryption
is listed as a future improvement (Priority 2).

### Q: Is this tool detectable by antivirus?
**A:** The Python scripts might trigger some behavioral heuristics, but
because the payloads don't actually do anything malicious in their current
state, most antivirus software won't flag them. A real attack tool would
need obfuscation to bypass EDR — which is out of scope for this
educational project.

### Q: How long does it take to set up?
**A:** For a complete beginner: about 2–3 hours for the full hardware
setup, or 15 minutes for software-only (no Pi needed).

---

*This guide is part of the Raspberry Pi Cybersecurity Education Tool by Ahmedouyahya (Mr.D137). Licensed under MIT.*
