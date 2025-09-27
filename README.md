# 🔐 Raspberry Pi Cybersecurity Education Tool

**Practical Cybersecurity Learning with Real Hardware**

> **🎓 EDUCATIONAL PURPOSE ONLY**  
> This project teaches cybersecurity concepts through hands-on experience with real hardware and practical scenarios. Always get proper authorization before testing.

## � What You'll Learn

This project turns a Raspberry Pi Zero into a practical cybersecurity learning tool that demonstrates:

- **USB Security**: How USB devices can be attack vectors
- **Data Encryption**: Protecting sensitive information with AES-256
- **Cross-Platform Security**: Different vulnerabilities across Windows, macOS, and mobile
- **Ethical Hacking**: Responsible penetration testing practices
- **Incident Response**: How to detect and respond to security events

## 🎯 Why This Project?

Instead of just reading about cybersecurity, you'll:
- ✅ **Build real hardware** - Set up your own testing device
- ✅ **See actual attacks** - Understand how vulnerabilities work
- ✅ **Practice defense** - Learn to detect and prevent attacks  
- ✅ **Handle real data** - Work with encryption and secure storage
- ✅ **Follow ethics** - Learn responsible disclosure and testing

## 🛠️ What You Need

| Item | Purpose | Cost |
|------|---------|------|
| Raspberry Pi Zero WH | Main computer | ~$15 |
| MicroSD Card (16GB+) | Storage | ~$10 |
| Micro-USB OTG Cable | Connect to devices | ~$5 |
| Computer for setup | Initial configuration | Existing |

**Total Cost: ~$30** (Much cheaper than commercial security tools!)

## 🚀 Quick Start

### 1. Set Up Your Pi Zero

```bash
# Download Raspberry Pi OS Lite
# Flash to SD card using Raspberry Pi Imager
# Enable SSH and configure WiFi

# Copy our project files
git clone https://github.com/Ahmedouyahya/raspberry_pi.git
cd raspberry_pi
```

### 2. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Set up the environment
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 3. Run Your First Test

```bash
# Start the educational demo
python src/main.py --demo

# Or try the interactive mode
python decrypt_data.py --demo
touch /boot/ssh

# Configure Wi-Fi
cat > /boot/wpa_supplicant.conf << EOF
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={
    ssid="YOUR_NETWORK_NAME"
    psk="YOUR_NETWORK_PASSWORD"
}
EOF
```

### 3. Configure USB Gadget Mode

Edit `/boot/config.txt` and add:
```
dtoverlay=dwc2,dr_mode=peripheral
gpu_mem=16
dtparam=act_led_trigger=none
dtparam=act_led_activelow=on
disable_splash=1
```

Edit `/etc/modules` and add:
```
dwc2
g_hid
g_mass_storage
```

### 4. Install and Configure

```bash
# Clone this repository
git clone https://github.com/yourusername/pi-zero-cybersec-tool.git
cd pi-zero-cybersec-tool

# Run the automated setup script
sudo ./scripts/setup.sh
```

## 📖 Educational Content

### Understanding USB Attacks

USB-based attacks exploit the trust relationship between users and USB devices. When you plug in a USB device, your computer typically:

1. **Auto-detects** the device type
2. **Automatically mounts** storage devices
3. **Executes** autorun files (in some configurations)
4. **Trusts** HID (keyboard/mouse) input

This project demonstrates these vulnerabilities in a controlled, ethical manner.

### Attack Vectors Demonstrated

| Vector | Description | Target OS | Educational Value |
|--------|-------------|-----------|-------------------|
| HID Injection | Simulates keyboard input | All | Shows why USB ports should be controlled |
| Data Extraction | Copies browser/system data | Windows/macOS | Demonstrates data at rest vulnerabilities |
| Wi-Fi Harvesting | Extracts saved network credentials | All | Shows importance of credential encryption |
| System Reconnaissance | Gathers system information | All | Illustrates information disclosure risks |

## 🔧 Advanced Configuration

### Custom Payloads

Create custom payloads in the `payloads/` directory:

```python
# Example: Custom Windows payload
def custom_windows_payload():
    """
    Educational payload for Windows demonstration
    """
    # Your custom educational code here
    pass
```

### Encryption Configuration

The tool uses AES-256-GCM encryption with PBKDF2 key derivation:

```python
# Key derivation parameters
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 16
KEY_LENGTH = 32
```

## 🛡️ Security Considerations

### Built-in Safeguards

1. **Visual Indicators**: LED blinks 3 times as ethical warning
2. **Embedded Disclaimers**: All data includes legal notices
3. **Encryption**: Data encrypted with device-specific keys
4. **No Persistence**: No permanent system modifications
5. **Secure Cleanup**: Temporary files are securely wiped

### Ethical Guidelines

- ✅ **Always obtain explicit written permission**
- ✅ **Use only on systems you own or are authorized to test**
- ✅ **Document all testing activities**
- ✅ **Securely handle any collected data**
- ❌ **Never use for malicious purposes**
- ❌ **Never test on systems without permission**

## 📚 Learning Resources

### Recommended Reading

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

### Online Courses

- Cybersecurity fundamentals
- Ethical hacking methodologies
- Digital forensics
- Incident response

### Practice Environments

- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)
- [VulnHub](https://www.vulnhub.com/)

## 🔍 Usage Examples

### Basic Security Assessment

```bash
# 1. Prepare the device
sudo ./scripts/prepare_device.sh

# 2. Deploy to target (with permission)
# Physical deployment on authorized system

# 3. Analyze results
python3 tools/decrypt_data.py --serial YOUR_PI_SERIAL --file collected_data.enc
```

### Educational Demonstration

```bash
# Generate sample data for classroom demonstration
python3 tools/generate_demo_data.py --scenario classroom

# Analyze the demo data
python3 tools/analyze_demo.py --input demo_data.json
```

## 🧪 Testing and Validation

### Unit Tests

```bash
# Run the test suite
python3 -m pytest tests/

# Run specific test categories
python3 -m pytest tests/test_encryption.py
python3 -m pytest tests/test_payloads.py
```

### Integration Tests

```bash
# Test on virtual machines (safe environment)
./scripts/test_on_vms.sh
```

## 🤝 Contributing

We welcome contributions that improve the educational value of this project!

### Guidelines

1. **Educational Focus**: All contributions must enhance learning
2. **Ethical Standards**: No malicious code or techniques
3. **Documentation**: Include comprehensive explanations
4. **Testing**: Provide tests for new features
5. **Legal Compliance**: Ensure all content is legal and ethical

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/pi-zero-cybersec-tool.git
cd pi-zero-cybersec-tool

# Install development dependencies
pip3 install -r requirements-dev.txt

# Run pre-commit hooks
pre-commit install
```

## 📄 Legal and Licensing

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Legal Disclaimer

**IMPORTANT**: This software is provided for educational and authorized testing purposes only. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with local, state, and federal laws
- Using the tool ethically and responsibly
- Securing any collected data appropriately

Unauthorized access to computer systems is illegal under laws including:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- General Data Protection Regulation (EU)
- Similar laws worldwide

### Responsible Disclosure

If you discover security vulnerabilities in this tool, please report them responsibly:

1. **Do not** publicly disclose the vulnerability
2. **Contact** the maintainers privately
3. **Provide** detailed information about the issue
4. **Allow** time for the issue to be addressed

## 🆘 Support and Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| USB not detected | Check OTG cable and USB gadget configuration |
| Payloads not executing | Verify HID gadget setup and target OS compatibility |
| Data not encrypted | Check Pi serial number and encryption key derivation |
| Service not starting | Review systemd service configuration and logs |

### Getting Help

1. **Check the [Wiki](wiki/)** for detailed guides
2. **Search [existing issues](issues/)** on GitHub
3. **Create a new issue** with detailed information:
   - Pi model and OS version
   - Target system details
   - Error logs and symptoms
   - Steps to reproduce

### Debug Commands

```bash
# Check service status
sudo systemctl status cyber_payload.service

# View service logs
journalctl -u cyber_payload.service -f

# Verify USB gadget setup
lsmod | grep -E "dwc2|g_hid|g_mass_storage"

# Check mounted filesystems
mount | grep usb_share
```

## 🌟 Acknowledgments

- **Raspberry Pi Foundation** for the amazing hardware platform
- **Cybersecurity community** for sharing knowledge and best practices
- **Educational institutions** for promoting ethical security research
- **Contributors** who help improve this educational resource

## 📈 Project Roadmap

### Version 2.0 (Planned)
- [ ] Web-based configuration interface
- [ ] Additional mobile OS support
- [ ] Enhanced encryption options
- [ ] Interactive learning modules

### Version 2.1 (Future)
- [ ] Cloud-based analysis tools
- [ ] Integration with security frameworks
- [ ] Advanced reporting features
- [ ] Multi-language support

---

**Remember**: This tool is designed to educate and improve cybersecurity awareness. Always use it responsibly and ethically! 🔐

---

<details>
<summary>📊 Project Statistics</summary>

- **Languages**: Python, Bash, PowerShell
- **Target Platforms**: Windows, macOS, Linux, Android, iOS
- **Security Features**: AES-256-GCM encryption, PBKDF2 key derivation
- **Educational Value**: High - comprehensive learning materials included

</details>

⭐ **Star this repository if it helps your cybersecurity education journey!**