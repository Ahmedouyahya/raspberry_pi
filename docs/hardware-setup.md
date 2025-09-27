# Hardware Setup Guide

## Overview

This guide provides detailed instructions for setting up the Raspberry Pi Zero WH hardware for the educational cybersecurity tool. This setup demonstrates how hardware can be configured for security testing and research purposes.

## Required Hardware

### Primary Components

| Component | Specification | Purpose | Required |
|-----------|---------------|---------|----------|
| Raspberry Pi Zero WH | Wi-Fi + Headers | Main processing unit | ✅ |
| MicroSD Card | 16GB+ Class 10 | Operating system storage | ✅ |
| Micro-USB OTG Cable | Data capable | Target device connection | ✅ |
| Setup Computer | Any OS | Initial configuration | ✅ |

### Optional Components

| Component | Specification | Purpose | Required |
|-----------|---------------|---------|----------|
| USB Wi-Fi Dongle | 2.4GHz/5GHz | Additional connectivity | ❌ |
| GPIO LED | 3.3V compatible | Visual status indicator | ❌ |
| Resistor | 220Ω | LED current limiting | ❌ |
| Case/Enclosure | Pi Zero compatible | Physical protection | ❌ |
| Heat Sink | Small form factor | Thermal management | ❌ |

## Hardware Assembly

### Step 1: Prepare the Raspberry Pi

1. **Inspect the board:**
   - Check for physical damage
   - Ensure GPIO pins are straight and intact
   - Verify microSD slot is clean

2. **Install heat sink (optional):**
   - Clean the CPU with isopropyl alcohol
   - Apply thermal adhesive pad
   - Press heat sink firmly

### Step 2: LED Status Indicator (Optional)

If adding a visual status indicator:

```
Pi Zero GPIO Layout (relevant pins):
┌─────────────────────────────┐
│  3V3  (1) (2)  5V           │
│  SDA  (3) (4)  5V           │
│  SCL  (5) (6)  GND          │
│ GPIO4 (7) (8)  TXD          │
│  GND  (9)(10)  RXD          │
│GPIO17(11)(12) GPIO18        │
│GPIO27(13)(14)  GND          │
│       ...                   │
└─────────────────────────────┘
```

**LED Connection:**
- GPIO17 (Pin 11) → 220Ω Resistor → LED Anode (+)
- LED Cathode (-) → GND (Pin 14)

**Circuit Diagram:**
```
GPIO17 ──┤ 220Ω ├──┤LED├── GND
         Resistor   Anode  Cathode
```

### Step 3: Case Installation (Optional)

1. **Choose appropriate case:**
   - Ensure GPIO access if using LED
   - Verify microSD card accessibility
   - Check USB port alignment

2. **Install Pi in case:**
   - Mount board on standoffs
   - Ensure proper fit without stress
   - Verify all ports are accessible

## SD Card Preparation

### Step 1: Download Raspberry Pi OS

```bash
# Download the official Raspberry Pi OS Lite image
wget https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2023-12-11/2023-12-11-raspios-bookworm-armhf-lite.img.xz

# Verify download integrity (recommended)
sha256sum 2023-12-11-raspios-bookworm-armhf-lite.img.xz
```

### Step 2: Flash the Image

**Using Raspberry Pi Imager (Recommended):**

1. Download and install [Raspberry Pi Imager](https://www.raspberrypi.org/software/)
2. Select the downloaded OS image
3. Choose your microSD card
4. Configure advanced options:
   - Enable SSH
   - Set username/password
   - Configure Wi-Fi
5. Flash the image

**Using Command Line (Linux/macOS):**

```bash
# Extract the image
unxz 2023-12-11-raspios-bookworm-armhf-lite.img.xz

# Identify SD card device (be very careful!)
lsblk  # or diskutil list on macOS

# Flash the image (replace /dev/sdX with your SD card)
sudo dd if=2023-12-11-raspios-bookworm-armhf-lite.img of=/dev/sdX bs=4M status=progress

# Sync to ensure all data is written
sync
```

### Step 3: Enable SSH and Wi-Fi

**Enable SSH:**
```bash
# Mount the boot partition
sudo mkdir -p /mnt/pi-boot
sudo mount /dev/sdX1 /mnt/pi-boot

# Enable SSH
sudo touch /mnt/pi-boot/ssh
```

**Configure Wi-Fi:**
```bash
# Create Wi-Fi configuration
sudo cat > /mnt/pi-boot/wpa_supplicant.conf << EOF
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="YOUR_NETWORK_NAME"
    psk="YOUR_NETWORK_PASSWORD"
    key_mgmt=WPA-PSK
}
EOF
```

**Unmount the card:**
```bash
sudo umount /mnt/pi-boot
```

## Initial System Configuration

### Step 1: First Boot and SSH Access

1. **Insert SD card** into Raspberry Pi Zero WH
2. **Connect power** using micro-USB port (not OTG port)
3. **Wait for boot** (2-3 minutes for first boot)
4. **Find IP address:**
   ```bash
   # Option 1: Check router's DHCP client list
   # Option 2: Network scan
   nmap -sn 192.168.1.0/24
   
   # Option 3: Use hostname (if mDNS works)
   ping raspberrypi.local
   ```

5. **SSH to the Pi:**
   ```bash
   ssh pi@192.168.1.XXX
   # or
   ssh pi@raspberrypi.local
   ```

### Step 2: Basic System Setup

```bash
# Update package lists
sudo apt update

# Upgrade system packages
sudo apt full-upgrade -y

# Configure locale and timezone
sudo raspi-config
# Navigate to: Localisation Options
# Set locale, timezone, keyboard layout

# Change default password
passwd

# Expand filesystem (if needed)
sudo raspi-config
# Navigate to: Advanced Options > Expand Filesystem
```

### Step 3: USB Gadget Configuration

**Configure `/boot/config.txt`:**
```bash
sudo cp /boot/config.txt /boot/config.txt.backup

# Add USB gadget configuration
sudo cat >> /boot/config.txt << EOF

# USB Gadget Configuration for Cybersecurity Tool
dtoverlay=dwc2,dr_mode=peripheral
gpu_mem=16
dtparam=act_led_trigger=none
dtparam=act_led_activelow=on
disable_splash=1
EOF
```

**Configure `/etc/modules`:**
```bash
# Add required kernel modules
sudo cat >> /etc/modules << EOF
dwc2
g_hid
g_mass_storage
EOF
```

## USB Gadget Setup

### Composite USB Gadget Configuration

```bash
# Create gadget configuration script
sudo cat > /usr/local/bin/setup-usb-gadget.sh << 'EOF'
#!/bin/bash

# USB Gadget Setup for Educational Cybersecurity Tool
cd /sys/kernel/config/usb_gadget/

# Create gadget directory
mkdir -p pi-zero-tool
cd pi-zero-tool

# Configure gadget
echo 0x1d6b > idVendor  # Linux Foundation
echo 0x0104 > idProduct # Multifunction Composite Gadget
echo 0x0100 > bcdDevice # v1.0.0
echo 0x0200 > bcdUSB    # USB 2.0

# Configure strings
mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "Educational Cybersecurity Tool" > strings/0x409/manufacturer
echo "Pi Zero Security Tester" > strings/0x409/product

# Create configuration
mkdir -p configs/c.1/strings/0x409
echo "Configuration 1" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower
echo 0x80 > configs/c.1/bmAttributes

# HID Function (Keyboard)
mkdir -p functions/hid.usb0
echo 1 > functions/hid.usb0/protocol
echo 1 > functions/hid.usb0/subclass
echo 8 > functions/hid.usb0/report_length

# HID Report Descriptor (Keyboard)
echo -ne \\x05\\x01\\x09\\x06\\xa1\\x01\\x05\\x07\\x19\\xe0\\x29\\xe7\\x15\\x00\\x25\\x01\\x75\\x01\\x95\\x08\\x81\\x02\\x95\\x01\\x75\\x08\\x81\\x03\\x95\\x05\\x75\\x01\\x05\\x08\\x19\\x01\\x29\\x05\\x91\\x02\\x95\\x01\\x75\\x03\\x91\\x03\\x95\\x06\\x75\\x08\\x15\\x00\\x25\\x65\\x05\\x07\\x19\\x00\\x29\\x65\\x81\\x00\\xc0 > functions/hid.usb0/report_desc

# Mass Storage Function
mkdir -p functions/mass_storage.usb0
echo 1 > functions/mass_storage.usb0/stall
echo 0 > functions/mass_storage.usb0/lun.0/cdrom
echo 0 > functions/mass_storage.usb0/lun.0/ro
echo 0 > functions/mass_storage.usb0/lun.0/nofua
echo /piusb.bin > functions/mass_storage.usb0/lun.0/file

# Link functions to configuration
ln -s functions/hid.usb0 configs/c.1/
ln -s functions/mass_storage.usb0 configs/c.1/

# Enable gadget
ls /sys/class/udc > UDC
EOF

# Make script executable
sudo chmod +x /usr/local/bin/setup-usb-gadget.sh
```

### Create Virtual USB Storage

```bash
# Create 2GB image file
sudo dd if=/dev/zero of=/piusb.bin bs=1M count=2048

# Format as exFAT (compatible with Windows/macOS/Linux)
sudo apt install -y exfat-fuse exfat-utils
sudo mkfs.exfat -n "TRUSTED_DRIVE" /piusb.bin

# Create mount point
sudo mkdir -p /mnt/usb_share

# Add to fstab for persistent mounting
echo "/piusb.bin /mnt/usb_share exfat defaults,uid=pi,gid=pi 0 0" | sudo tee -a /etc/fstab

# Mount the filesystem
sudo mount -a
```

## Hardware Testing

### Step 1: Basic Functionality Test

```bash
# Test GPIO LED (if installed)
echo 17 | sudo tee /sys/class/gpio/export
echo out | sudo tee /sys/class/gpio/gpio17/direction
echo 1 | sudo tee /sys/class/gpio/gpio17/value
sleep 1
echo 0 | sudo tee /sys/class/gpio/gpio17/value

# Test USB mount
df -h | grep usb_share

# Test kernel modules
lsmod | grep -E "dwc2|g_hid|g_mass_storage"
```

### Step 2: USB Gadget Test

```bash
# Run gadget setup script
sudo /usr/local/bin/setup-usb-gadget.sh

# Check gadget status
ls /sys/kernel/config/usb_gadget/pi-zero-tool/

# Verify UDC binding
cat /sys/kernel/config/usb_gadget/pi-zero-tool/UDC
```

### Step 3: Connection Test

1. **Connect to test computer** using OTG cable
2. **Verify device enumeration:**
   - Windows: Device Manager should show new USB devices
   - macOS: System Information > USB should list device
   - Linux: `lsusb` should show new entries

3. **Test mass storage access:**
   - Device should appear as "TRUSTED_DRIVE"
   - Should be readable/writable
   - Test file operations

## Troubleshooting

### Common Issues

#### USB Gadget Not Recognized

**Symptoms:**
- Device not appearing on host computer
- No USB enumeration

**Solutions:**
```bash
# Check if modules are loaded
lsmod | grep dwc2

# Manually load modules if needed
sudo modprobe dwc2
sudo modprobe g_hid
sudo modprobe g_mass_storage

# Check USB controller
dmesg | tail -20 | grep -i usb

# Verify cable is OTG-capable (data pins connected)
```

#### Mass Storage Mount Issues

**Symptoms:**
- USB storage not accessible
- File system errors

**Solutions:**
```bash
# Check image file integrity
sudo fsck.exfat /piusb.bin

# Recreate image if corrupted
sudo dd if=/dev/zero of=/piusb.bin bs=1M count=2048
sudo mkfs.exfat -n "TRUSTED_DRIVE" /piusb.bin

# Check mount status
mount | grep usb_share
```

#### LED Not Working

**Symptoms:**
- Status LED not blinking
- GPIO errors

**Solutions:**
```bash
# Check GPIO availability
ls /sys/class/gpio/

# Verify pin is not in use
cat /sys/kernel/debug/gpio

# Test pin manually
echo 17 | sudo tee /sys/class/gpio/export
echo out | sudo tee /sys/class/gpio/gpio17/direction
echo 1 | sudo tee /sys/class/gpio/gpio17/value
```

### Performance Optimization

#### Reduce Boot Time

```bash
# Disable unnecessary services
sudo systemctl disable bluetooth.service
sudo systemctl disable hciuart.service
sudo systemctl disable avahi-daemon.service

# Reduce GPU memory (already configured)
# gpu_mem=16 in /boot/config.txt

# Disable splash screen (already configured)
# disable_splash=1 in /boot/config.txt
```

#### Optimize for Low Power

```bash
# Disable HDMI output
echo 'hdmi_blanking=1' | sudo tee -a /boot/config.txt

# Disable camera LED
echo 'disable_camera_led=1' | sudo tee -a /boot/config.txt

# Set CPU governor
echo 'powersave' | sudo tee /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

## Security Considerations

### Hardware Security

1. **Physical Access Control:**
   - Secure SD card slot
   - Use tamper-evident seals
   - Consider encrypted storage

2. **Firmware Protection:**
   - Keep bootloader updated
   - Monitor for unauthorized modifications
   - Use signed firmware images

### Network Security

1. **Wi-Fi Configuration:**
   - Use WPA3 when available
   - Regularly rotate credentials
   - Monitor network traffic

2. **SSH Hardening:**
   - Use key-based authentication
   - Disable password authentication
   - Change default port

## Educational Applications

### Classroom Demonstrations

1. **USB Protocol Analysis:**
   - Show device enumeration process
   - Demonstrate different USB classes
   - Explain security implications

2. **Hardware Security:**
   - Physical access scenarios
   - Firmware modification risks
   - Trusted platform modules

### Research Projects

1. **Custom USB Devices:**
   - Develop new gadget configurations
   - Study protocol vulnerabilities
   - Create defensive tools

2. **IoT Security:**
   - Embedded system hardening
   - Secure boot processes
   - Hardware root of trust

---

**Safety Reminders:**
- Always obtain permission before testing
- Use only in controlled environments
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

This hardware setup enables hands-on learning about USB security, embedded systems, and cybersecurity testing methodologies in a controlled, educational environment.