#!/usr/bin/env python3
"""
Pi Zero Cybersecurity Educational Tool - Main Entry Point

This is the main interface for the educational cybersecurity demonstration tool.
It provides multiple modes for different educational scenarios and conference presentations.

Educational Modes:
1. Demo Mode - Safe classroom demonstrations
2. Assessment Mode - Authorized penetration testing
3. Analysis Mode - Data analysis and reporting
4. Training Mode - Interactive cybersecurity education

Author: Mr.D137
License: MIT (Educational Use)
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Educational disclaimer
EDUCATIONAL_BANNER = """
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█                    PI ZERO CYBERSECURITY EDUCATIONAL TOOL                   █
█                                                                              █
█                        🎓 EDUCATION • 🔒 SECURITY • ⚖️ ETHICS               █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████

⚠️  EDUCATIONAL PURPOSE ONLY ⚠️
This tool is designed exclusively for cybersecurity education and authorized testing.
Unauthorized use is illegal and unethical.

Educational Objectives:
• Demonstrate USB-based attack vectors
• Teach data-at-rest vulnerabilities
• Show importance of endpoint security
• Practice ethical penetration testing
• Learn cryptographic best practices

Legal Requirements:
✅ Only use on systems you own or have explicit written permission to test
✅ Comply with all applicable laws and regulations
✅ Use responsibly for educational purposes only
❌ NEVER use for malicious purposes or unauthorized access

"""

class CybersecTool:
    """Main educational cybersecurity tool class"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.config_dir = self.project_root / "config"
        self.logs_dir = self.project_root / "logs"
        self.reports_dir = self.project_root / "reports"
        
        # Ensure directories exist
        for directory in [self.logs_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)
    
    def demo_mode(self):
        """Run safe demonstration mode for classrooms and conferences"""
        print("🎓 Starting Educational Demo Mode...")
        print("\nThis mode provides safe demonstrations of:")
        print("• USB attack vector concepts")
        print("• Data extraction techniques")
        print("• Defense strategies")
        print("• Incident response procedures")
        
        # Import demo functionality
        try:
            from .tools.demo_generator import create_demo_scenario
            create_demo_scenario()
        except ImportError:
            print("Demo module not available. Creating basic demo...")
            self._create_basic_demo()
    
    def assessment_mode(self):
        """Run authorized penetration testing mode"""
        print("🔍 Starting Assessment Mode...")
        
        # Verify authorization
        consent = input("\nDo you have explicit written authorization to test this system? (yes/no): ")
        if consent.lower() != "yes":
            print("❌ Assessment cancelled. Authorization required.")
            return
        
        print("✅ Starting authorized assessment...")
        # Assessment implementation would go here
        print("Assessment mode requires hardware setup. Please refer to documentation.")
    
    def analysis_mode(self, data_file: Optional[str] = None):
        """Analyze collected data for educational purposes"""
        print("📊 Starting Analysis Mode...")
        
        if not data_file:
            print("Please provide a data file to analyze")
            return
        
        # Use the decrypt_data functionality
        from decrypt_data import main as decrypt_main
        decrypt_main()
    
    def training_mode(self):
        """Interactive cybersecurity training mode"""
        print("🎯 Starting Interactive Training Mode...")
        
        training_modules = [
            "USB Attack Vectors",
            "Data Encryption Best Practices",
            "Incident Response Procedures",
            "Legal and Ethical Considerations",
            "Defense Strategies"
        ]
        
        print("\nAvailable Training Modules:")
        for i, module in enumerate(training_modules, 1):
            print(f"{i}. {module}")
        
        try:
            choice = int(input("\nSelect a module (1-5): ")) - 1
            if 0 <= choice < len(training_modules):
                self._run_training_module(training_modules[choice])
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")
    
    def _create_basic_demo(self):
        """Create a basic demonstration scenario"""
        demo_data = {
            "scenario": "Classroom Demonstration",
            "educational_purpose": "Show USB attack concepts without real data collection",
            "simulated_findings": {
                "system_info": {
                    "os": "Demo OS",
                    "hostname": "EDUCATION-PC",
                    "username": "student"
                },
                "educational_notes": [
                    "This is simulated data for educational purposes",
                    "Real attacks would target actual system files",
                    "Defense: Disable USB autorun and use endpoint protection"
                ]
            }
        }
        
        print("\n📋 Demo Scenario Created:")
        import json
        print(json.dumps(demo_data, indent=2))
    
    def _run_training_module(self, module_name: str):
        """Run a specific training module"""
        print(f"\n🎓 Training Module: {module_name}")
        
        modules = {
            "USB Attack Vectors": self._usb_training,
            "Data Encryption Best Practices": self._encryption_training,
            "Incident Response Procedures": self._incident_response_training,
            "Legal and Ethical Considerations": self._ethics_training,
            "Defense Strategies": self._defense_training
        }
        
        if module_name in modules:
            modules[module_name]()
        else:
            print("Module not implemented yet")
    
    def _usb_training(self):
        """USB attack vectors training module"""
        print("""
USB Attack Vectors Training Module
==================================

Key Concepts:
1. USB devices are automatically trusted by most systems
2. HID (Human Interface Device) attacks simulate keyboard/mouse input
3. Mass storage attacks can trigger autorun functionality
4. BadUSB attacks can reprogram USB device firmware

Common Attack Types:
• Keystroke injection (simulating user input)
• Data exfiltration via hidden storage
• Network credential harvesting
• System reconnaissance and information gathering

Defense Strategies:
• Disable USB autorun functionality
• Implement USB device whitelisting
• Use endpoint detection and response (EDR) tools
• Regular security awareness training
• Physical security controls for USB ports
        """)
    
    def _encryption_training(self):
        """Data encryption training module"""
        print("""
Data Encryption Best Practices
===============================

This tool demonstrates:
• AES-256-GCM for authenticated encryption
• PBKDF2 key derivation with high iteration counts
• Proper salt and nonce generation
• Secure key management practices

Key Principles:
1. Never store encryption keys with encrypted data
2. Use hardware-specific identifiers for key derivation
3. Implement proper authentication (GCM mode)
4. Regular key rotation and secure deletion

Real-World Applications:
• Full-disk encryption (BitLocker, FileVault)
• Database encryption at rest
• Application-level encryption
• Backup and archive encryption
        """)
    
    def _incident_response_training(self):
        """Incident response training module"""
        print("""
Incident Response Procedures
============================

If you suspect a USB-based attack:

1. IDENTIFICATION
   • Unusual system behavior
   • Unexpected network connections
   • New files or processes
   • Modified system settings

2. CONTAINMENT
   • Disconnect from network
   • Preserve evidence
   • Document timeline
   • Notify security team

3. ERADICATION
   • Remove malicious software
   • Patch vulnerabilities
   • Update security controls
   • Reset compromised credentials

4. RECOVERY
   • Restore from clean backups
   • Monitor for residual activity
   • Gradual system restoration
   • User access validation

5. LESSONS LEARNED
   • Post-incident review
   • Update security policies
   • Improve detection capabilities
   • Staff training updates
        """)
    
    def _ethics_training(self):
        """Ethics and legal training module"""
        print("""
Legal and Ethical Considerations
================================

Legal Framework:
• Computer Fraud and Abuse Act (US)
• General Data Protection Regulation (EU)
• Local cybersecurity laws and regulations
• Professional codes of conduct

Ethical Principles:
1. Authorized Use Only
   • Explicit written permission required
   • Scope clearly defined and limited
   • Regular authorization review

2. Responsible Disclosure
   • Report vulnerabilities to system owners
   • Allow time for remediation
   • Coordinate public disclosure

3. Data Protection
   • Minimize data collection
   • Secure handling and storage
   • Proper data destruction
   • Privacy considerations

4. Educational Focus
   • Enhance security awareness
   • Improve defensive capabilities
   • Promote best practices
   • Never cause harm

Remember: With great power comes great responsibility!
        """)
    
    def _defense_training(self):
        """Defense strategies training module"""
        print("""
Defense Strategies Against USB Attacks
======================================

Technical Controls:
• USB port controls and whitelisting
• Endpoint Detection and Response (EDR)
• Application whitelisting
• Network segmentation
• Full-disk encryption

Administrative Controls:
• Security policies and procedures
• Regular security awareness training
• Incident response planning
• Vendor risk management
• Access control reviews

Physical Controls:
• USB port blocking/disabling
• Secure workstation configuration
• Clean desk policies
• Visitor access controls
• Device inventory management

Detection Indicators:
• Unusual process execution
• Unexpected network connections
• File system modifications
• Registry changes (Windows)
• System log anomalies

Monitoring and Response:
• Real-time security monitoring
• Automated threat detection
• Incident response procedures
• Forensic analysis capabilities
• Threat intelligence integration
        """)

def main():
    """Main entry point for the cybersecurity tool"""
    parser = argparse.ArgumentParser(
        description="Pi Zero Cybersecurity Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For detailed documentation, visit: https://github.com/yourusername/pi-zero-cybersec-tool"
    )
    
    parser.add_argument(
        "mode",
        choices=["demo", "assess", "analyze", "train"],
        help="Tool operation mode"
    )
    
    parser.add_argument(
        "--data-file",
        help="Data file for analysis mode"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Display educational banner
    print(EDUCATIONAL_BANNER)
    
    # Initialize tool
    tool = CybersecTool()
    
    # Run selected mode
    try:
        if args.mode == "demo":
            tool.demo_mode()
        elif args.mode == "assess":
            tool.assessment_mode()
        elif args.mode == "analyze":
            tool.analysis_mode(args.data_file)
        elif args.mode == "train":
            tool.training_mode()
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\n⚠️ Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()