#!/usr/bin/env python3
"""
Live Demo Script for Conference Presentations

This script provides a structured, safe demonstration of USB attack concepts
for educational conferences and presentations.

Features:
- Real-time visual feedback
- Safe, controlled demonstrations
- Audience interaction capabilities
- Professional presentation flow

Author: Mr.D137
License: MIT (Educational Use)
"""

import time
import json
import random
from datetime import datetime
from typing import Dict, Any
import logging

# Configure logging for live demo
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - DEMO - %(message)s'
)
logger = logging.getLogger(__name__)

class LiveDemoPresentation:
    """
    Live demonstration controller for conference presentations
    """
    
    def __init__(self, demo_type: str = "conference"):
        self.demo_type = demo_type
        self.start_time = datetime.now()
        self.demo_phase = "setup"
        self.audience_size = 0
        
        # Demo configuration
        self.config = {
            "show_terminal_output": True,
            "simulate_delays": True,
            "audience_interaction": True,
            "safety_warnings": True
        }
        
        print(self._get_demo_banner())
    
    def _get_demo_banner(self) -> str:
        """Get presentation banner"""
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    🎓 LIVE CYBERSECURITY DEMONSTRATION 🎓                    ║
║                                                                              ║
║                          USB Attack Vector Education                         ║
║                                                                              ║
║  ⚠️  EDUCATIONAL PURPOSE ONLY - ALL DEMONSTRATIONS ARE SAFE AND CONTROLLED  ⚠️   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
    
    def audience_poll(self, question: str, options: list) -> Dict[str, int]:
        """
        Conduct live audience poll
        
        Args:
            question: Poll question
            options: List of options
            
        Returns:
            dict: Poll results (simulated for demo)
        """
        print(f"\n🗳️  AUDIENCE POLL: {question}")
        print("Options:")
        for i, option in enumerate(options, 1):
            print(f"   {i}. {option}")
        
        # Simulate poll results for demo
        results = {}
        for option in options:
            results[option] = random.randint(5, 25)
        
        print(f"\n📊 Poll Results:")
        total_votes = sum(results.values())
        for option, votes in results.items():
            percentage = (votes / total_votes) * 100
            print(f"   {option}: {votes} votes ({percentage:.1f}%)")
        
        return results
    
    def demo_phase_1_introduction(self):
        """Phase 1: Introduction and setup"""
        print("\n" + "="*80)
        print("PHASE 1: INTRODUCTION AND THREAT LANDSCAPE")
        print("="*80)
        
        self.demo_phase = "introduction"
        
        # Audience engagement
        poll_results = self.audience_poll(
            "Have you ever plugged in a found USB device?",
            ["Never", "Once or twice", "Yes, multiple times", "I prefer not to say"]
        )
        
        # Statistics display
        print(f"\n📈 USB Threat Statistics (2024-2025):")
        print(f"   • 68% of organizations experienced USB-based attacks")
        print(f"   • Average time to detection: 197 days")
        print(f"   • 94% of successful attacks started with email or USB")
        print(f"   • $4.45M average cost of a data breach")
        
        time.sleep(2)
    
    def demo_phase_2_usb_hid_attack(self):
        """Phase 2: USB HID attack demonstration"""
        print("\n" + "="*80)
        print("PHASE 2: USB HID ATTACK DEMONSTRATION")
        print("="*80)
        
        self.demo_phase = "hid_attack"
        
        print("🔌 Simulating USB device insertion...")
        time.sleep(1)
        
        print("📱 Device recognized as HID (Human Interface Device)")
        print("⌨️  Beginning keystroke injection simulation...")
        
        # Simulate keystroke injection
        keystrokes = [
            "Windows+R",
            "powershell",
            "Enter",
            "$demo='This is educational only'",
            "Write-Host $demo -ForegroundColor Green"
        ]
        
        for keystroke in keystrokes:
            print(f"   Injecting: {keystroke}")
            time.sleep(0.5)
        
        print("\n✅ HID injection complete - No actual commands executed")
        print("🛡️  Defense: USB device controls and EDR monitoring")
    
    def demo_phase_3_data_extraction(self):
        """Phase 3: Data extraction concepts"""
        print("\n" + "="*80)
        print("PHASE 3: DATA EXTRACTION CONCEPTS")
        print("="*80)
        
        self.demo_phase = "data_extraction"
        
        print("🗃️  Demonstrating data collection concepts...")
        
        # Generate demo data
        demo_data = {
            "timestamp": datetime.now().isoformat(),
            "educational_disclaimer": "THIS IS SIMULATED DATA FOR EDUCATION ONLY",
            "simulated_findings": {
                "system_info": {
                    "hostname": "DEMO-CONFERENCE-PC",
                    "username": "presenter",
                    "os": "Educational Demo OS"
                },
                "browser_simulation": {
                    "note": "No real browser data accessed",
                    "concept_demonstrated": "How attackers target stored credentials"
                },
                "network_info": {
                    "note": "Network discovery simulation only",
                    "educational_purpose": "Show reconnaissance techniques"
                }
            }
        }
        
        print("📊 Simulated data collection complete:")
        print(json.dumps(demo_data, indent=2))
        
        print("\n🔐 Encrypting collected data...")
        time.sleep(1)
        print("✅ Data encrypted with AES-256-GCM")
        print("🛡️  Defense: Full-disk encryption and data loss prevention")
    
    def demo_phase_4_network_recon(self):
        """Phase 4: Network reconnaissance simulation"""
        print("\n" + "="*80)
        print("PHASE 4: NETWORK RECONNAISSANCE SIMULATION")
        print("="*80)
        
        self.demo_phase = "network_recon"
        
        print("🌐 Simulating network discovery...")
        
        # Simulate network discovery
        demo_networks = [
            {"ssid": "ConferenceWiFi", "security": "WPA2-Enterprise", "signal": "Strong"},
            {"ssid": "GuestNetwork", "security": "Open", "signal": "Medium"},
            {"ssid": "EducationNet", "security": "WPA3", "signal": "Weak"}
        ]
        
        print("📡 Discovered networks:")
        for network in demo_networks:
            print(f"   SSID: {network['ssid']}")
            print(f"   Security: {network['security']}")
            print(f"   Signal: {network['signal']}")
            print("   ---")
        
        print("🛡️  Defense: Network segmentation and monitoring")
    
    def demo_phase_5_defense_strategies(self):
        """Phase 5: Defense strategies demonstration"""
        print("\n" + "="*80)
        print("PHASE 5: DEFENSE STRATEGIES DEMONSTRATION")
        print("="*80)
        
        self.demo_phase = "defense"
        
        defenses = [
            {
                "category": "Technical Controls",
                "examples": [
                    "USB device whitelisting",
                    "Endpoint Detection and Response (EDR)",
                    "Application whitelisting",
                    "Network segmentation"
                ]
            },
            {
                "category": "Administrative Controls", 
                "examples": [
                    "Security awareness training",
                    "Incident response procedures",
                    "Regular security assessments",
                    "Vendor risk management"
                ]
            },
            {
                "category": "Physical Controls",
                "examples": [
                    "USB port locks",
                    "Device inventory management",
                    "Secure workstation configuration",
                    "Visitor access controls"
                ]
            }
        ]
        
        for defense in defenses:
            print(f"\n🛡️  {defense['category']}:")
            for example in defense['examples']:
                print(f"   • {example}")
        
        print(f"\n💡 Key Takeaway: Defense in depth is essential!")
    
    def interactive_qa_session(self):
        """Interactive Q&A session"""
        print("\n" + "="*80)
        print("INTERACTIVE Q&A SESSION")
        print("="*80)
        
        common_questions = [
            {
                "question": "Can this attack work on modern systems?",
                "answer": "Yes, but proper EDR and USB controls significantly reduce risk."
            },
            {
                "question": "How can we detect these attacks?",
                "answer": "Monitor USB device insertions, process execution, and network activity."
            },
            {
                "question": "What's the best defense strategy?",
                "answer": "Layered security: technical controls + user training + policies."
            }
        ]
        
        print("❓ Common Questions and Answers:")
        for qa in common_questions:
            print(f"\nQ: {qa['question']}")
            print(f"A: {qa['answer']}")
        
        print(f"\n🎤 Now taking live questions from the audience...")
    
    def demo_wrap_up(self):
        """Wrap up the demonstration"""
        print("\n" + "="*80)
        print("DEMONSTRATION WRAP-UP")
        print("="*80)
        
        duration = datetime.now() - self.start_time
        
        print(f"📊 Demo Summary:")
        print(f"   • Duration: {duration.total_seconds():.0f} seconds")
        print(f"   • Phases completed: 5")
        print(f"   • Safety level: 100% (no actual attacks performed)")
        print(f"   • Educational value: Maximum")
        
        print(f"\n🎯 Key Learning Outcomes:")
        print(f"   ✅ Understanding of USB attack vectors")
        print(f"   ✅ Awareness of data-at-rest vulnerabilities")
        print(f"   ✅ Knowledge of defense strategies")
        print(f"   ✅ Importance of layered security")
        
        print(f"\n📚 Resources:")
        print(f"   • GitHub: github.com/yourusername/pi-zero-cybersec-tool")
        print(f"   • Documentation: Full setup and usage guides")
        print(f"   • Contact: presenter@cybersec-education.org")
        
        print(f"\n🙏 Thank you for your attention!")
        print(f"   Questions? Let's continue the conversation!")

def run_live_demo():
    """Run the complete live demonstration"""
    demo = LiveDemoPresentation()
    
    try:
        demo.demo_phase_1_introduction()
        
        input("\nPress Enter to continue to Phase 2...")
        demo.demo_phase_2_usb_hid_attack()
        
        input("\nPress Enter to continue to Phase 3...")
        demo.demo_phase_3_data_extraction()
        
        input("\nPress Enter to continue to Phase 4...")
        demo.demo_phase_4_network_recon()
        
        input("\nPress Enter to continue to Phase 5...")
        demo.demo_phase_5_defense_strategies()
        
        input("\nPress Enter for Q&A session...")
        demo.interactive_qa_session()
        
        input("\nPress Enter to wrap up...")
        demo.demo_wrap_up()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by presenter")
        print("This concludes our demonstration. Thank you!")

if __name__ == "__main__":
    print("Starting live conference demonstration...")
    run_live_demo()