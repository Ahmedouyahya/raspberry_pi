# 🔐 Raspberry Pi Cybersecurity Tool - Real-World Feasibility Report

**Date:** 2026-02-18  
**Project:** raspberry_pi  
**Status:** Educational Proof-of-Concept (Not Production-Ready)

---

## 🎬 The Movie vs. Reality

| Movie Trope | Reality | This Project |
|-------------|---------|--------------|
| Plug in device → instant data exfiltration | Requires physical access + time | ❌ No working USB execution |
| Rubber ducky typing at 1000 WPM | Needs proper HID gadget setup | ❌ Stub code only |
| Decrypts passwords instantly | Browser DBs are encrypted | ❌ Just copies files |
| No trace left | Logs, artifacts, timestamps | ❌ No anti-forensics |
| Works on any OS | OS-specific protections | ⚠️ Partial Windows only |

---

## 🔴 What's Missing for Real-World Use

### 1. USB Gadget Mode (Critical)
**Current:** Just mentions `dtoverlay=dwc2` in docs  
**Needed:**
```
# /boot/config.txt - must add
dtoverlay=dwc2,dr_mode=peripheral

# /etc/modules - must add
dwc2
g_hid
g_mass_storage
libcomposite
```

**Real implementation requires:**
- Compiling USB kernel modules
- Configuring libcomposite
- Creating HID descriptor
- Setting up USB mass storage

### 2. Actual Data Exfiltration (Critical)
**Current:** Copies `.db` files (which are LOCKED by browsers)  
**Reality:**
- Chrome Login Data is encrypted with DPAPI → needs Windows DPAPI decryption
- Firefox logins.json needs master password or key4.db decryption
- Cookies are encrypted
- Files are locked while browser is running → needs to terminate browser or use backup copy

**What needs to be added:**
```python
# Example - what's missing:
def decrypt_chrome_passwords(login_db_path):
    # 1. Copy the locked file first
    # 2. Use DPAPI (Windows Data Protection API) 
    # 3. Decrypt with Chromium's key derivation
    # 4. Parse SQLite and extract
```

### 3. HID Keyboard Injection (Critical)
**Current:** No code  
**Needed:**
- USB HID gadget with keyboard descriptor
- Keystroke injection payload
- Timing/delays for different OS
- Escape sequences for UAC bypass

### 4. Auto-Execution (Major)
**Current:** None  
**Needed:**
- Autorun.inf (disabled by default since Windows 7)
- WMI event subscriptions
- Scheduled tasks
- Registry persistence

### 5. Network Exfiltration (Major)
**Current:** None  
**Needed:**
- C2 server connection
- DNS exfiltration
- HTTP/HTTPS tunneling
- Compression + encryption before sending

### 6. Anti-Forensics (Major)
**Current:** None  
**Needed:**
- Timestomp
- Log clearing
- Artifact removal
- Secure delete (not just rm)

### 7. Cross-Platform Support (Major)
**Current:** Windows partial, macOS stub  
**Needed:**
- macOS: Keychain access, System Preferences
- Linux: Chrome/Firefox keyring, PAM
- Root/elevated needed for most

---

## 📊 Component-by-Component Analysis

| Component | Status | Score | Notes |
|-----------|--------|-------|-------|
| USB Gadget Config | ⚠️ Incomplete | 3/10 | Docs exist, no working scripts |
| Windows Payload | ⚠️ Basic | 4/10 | Copies files, doesn't decrypt |
| macOS Payload | ⚠️ Stub | 2/10 | Shell script exists, minimal |
| Encryption Module | ✅ Good | 8/10 | AES-256-GCM correct implementation |
| Decryption Utility | ⚠️ Broken | 5/10 | Import bug + needs real data |
| Setup Script | ⚠️ Partial | 5/10 | Good for Pi, but missing USB gadget |
| Training/Demo | ✅ Complete | 9/10 | Educational content is excellent |
| Error Handling | ⚠️ Poor | 3/10 | Many edge cases not handled |
| Logging | ⚠️ Basic | 5/10 | No forensic logging |
| Tests | ❌ Missing | 0/10 | Empty test directory |

---

## 🛠️ Required Changes for Real-World

### Priority 1 - Must Fix (Non-Negotiable)

```
1. Fix decrypt_data.py imports
   FROM: from Crypto.Cipher import AES
   TO:   from Cryptodome.Cipher import AES

2. Add actual USB HID gadget scripts
   - src/scripts/usb_hid_setup.sh
   - src/scripts/gadget_config.sh

3. Add browser password decryption
   - src/tools/chrome_decrypt.py (DPAPI)
   - src/tools/firefox_decrypt.py (key4.db)
```

### Priority 2 - Essential Features

```
4. Auto-execution methods
   - WMI permanent event consumers
   - Registry run keys
   - Scheduled task creation

5. Data exfiltration
   - HTTP/HTTPS POST to C2
   - DNS TXT record exfil
   - Telegram/Discord webhooks

6. Cross-platform payloads
   - macOS Keychain dumper
   - Linux PAM credential harvester
```

### Priority 3 - Operational Security

```
7. Anti-forensics
   - Timestomp utility
   - Log clearing
   - Secure file deletion

8. Obfuscation
   - Base64 encoding
   - XOR/obfuscation
   - Common filename mimicry
```

---

## 💻 Code Issues Found

### 1. Import Bug (Breaks decryption)
```python
# decrypt_data.py line 31-33
try:
    from Crypto.Cipher import AES  # WRONG for pycryptodomex
except ImportError:
    from Cryptodome.Cipher import AES  # Should be this
```

### 2. File Lock Handling (Will fail)
```powershell
# windows_payload.ps1
# Problem: Can't copy Login Data while Chrome is running
# Fix needed: Use VSS (Volume Shadow Copy) or kill process first
Copy-Item "$ChromePath\Login Data" ...  # Will fail if Chrome open
```

### 3. No Error Recovery
- No fallback if Chrome not installed
- No handling if locked files
- No admin privilege checks

### 4. Hardcoded Paths
- Won't work on different Windows versions
- No roaming profile support
- No 32/64-bit path handling

---

## 🎯 Roadmap to Make It Work

### Phase 1: Fix Bugs (1-2 hours)
- [ ] Fix Crypto imports
- [ ] Add proper file locking handling
- [ ] Test on actual Windows system

### Phase 2: USB Gadget (4-8 hours)
- [ ] Create working dwc2 setup script
- [ ] Test on actual Pi Zero
- [ ] Add HID keyboard descriptor

### Phase 3: Real Exfiltration (8-16 hours)
- [ ] Add DPAPI decryption for Chrome
- [ ] Add Firefox key4.db parsing
- [ ] Implement WiFi password extraction
- [ ] Add network exfiltration

### Phase 4: Operational (8+ hours)
- [ ] Auto-execution persistence
- [ ] Anti-forensics
- [ ] Obfuscation
- [ ] Testing on multiple targets

---

## 📝 Conclusion

**Current State:** 6/100 (Not functional as attack tool)  
**Potential:** 75/100 (With fixes)  
**Educational Value:** 95/100 (Excellent teaching material)

### The Good
- Excellent educational documentation
- Correct cryptographic implementation
- Good training modules
- Clean code structure

### The Bad
- No working USB execution
- Browser data extraction is superficial
- No real-world testing
- Missing critical components

### The Verdict
This project is a **great starting point for learning** about cybersecurity concepts, but it is **NOT a functional tool** as-is. To make it work like in movies, you'd need to add approximately 2000+ lines of code and extensive testing.

**Recommendation:** This is perfect for:
- Learning cybersecurity concepts
- Teaching defense strategies
- Building a foundation for legitimate security research
- Conference demonstrations (with the demo mode)

**Not recommended for:**
- Actual penetration testing (use established tools like Metasploit, Cobalt Strike, Impacket)
- Real-world data exfiltration (illegal without authorization)
