#!/usr/bin/env python3
"""
Practical Cybersecurity Education Module

This module provides hands-on cybersecurity learning experiences focused on:
- USB security and device management
- Data encryption and protection
- Basic threat detection and response
- Ethical hacking practices

Author: Ahmedouyahya (Mr.D137)
License: MIT (Educational Use)
Version: 1.0 Educational Edition
"""

import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import random

# Configure logging for educational purposes
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Simple threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Simple security event for educational purposes"""
    event_id: str
    event_type: str
    severity: ThreatLevel
    description: str
    timestamp: str
    detected: bool = True
    mitigated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for easy display"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "description": self.description,
            "timestamp": self.timestamp,
            "detected": self.detected,
            "mitigated": self.mitigated
        }

class PracticalThreatSimulator:
    """Simulates common cybersecurity threats for educational purposes"""
    
    def __init__(self):
        self.events_generated = []
        logger.info("Practical Threat Simulator initialized for education")
    
    def simulate_usb_insertion(self) -> SecurityEvent:
        """Simulate USB device insertion threat"""
        event = SecurityEvent(
            event_id=f"USB_{int(time.time())}",
            event_type="usb_insertion",
            severity=ThreatLevel.MEDIUM,
            description="Suspicious USB device detected - Educational simulation",
            timestamp=datetime.now().isoformat()
        )
        
        self.events_generated.append(event)
        logger.info(f"🔌 USB threat simulated: {event.event_id}")
        return event
    
    def simulate_powershell_execution(self) -> SecurityEvent:
        """Simulate PowerShell execution threat"""
        event = SecurityEvent(
            event_id=f"PS_{int(time.time())}",
            event_type="powershell_execution",
            severity=ThreatLevel.HIGH,
            description="Suspicious PowerShell execution detected - Educational simulation",
            timestamp=datetime.now().isoformat()
        )
        
        self.events_generated.append(event)
        logger.info(f"💻 PowerShell threat simulated: {event.event_id}")
        return event
    
    def simulate_data_access(self) -> SecurityEvent:
        """Simulate unauthorized data access"""
        event = SecurityEvent(
            event_id=f"DATA_{int(time.time())}",
            event_type="data_access",
            severity=ThreatLevel.CRITICAL,
            description="Unauthorized data access attempt - Educational simulation",
            timestamp=datetime.now().isoformat()
        )
        
        self.events_generated.append(event)
        logger.info(f"📁 Data access threat simulated: {event.event_id}")
        return event

class BasicDefenseSimulator:
    """Simulates basic cybersecurity defense mechanisms"""
    
    def __init__(self):
        self.defense_systems = {
            "usb_controls": {"name": "USB Device Controls", "active": True, "effectiveness": 0.85},
            "antivirus": {"name": "Antivirus Protection", "active": True, "effectiveness": 0.80},
            "firewall": {"name": "Network Firewall", "active": True, "effectiveness": 0.75},
            "monitoring": {"name": "Security Monitoring", "active": False, "effectiveness": 0.90}
        }
        logger.info("Basic Defense Simulator initialized")
    
    def attempt_mitigation(self, threat: SecurityEvent) -> Dict[str, Any]:
        """Attempt to mitigate a security threat"""
        
        # Simple mitigation logic for education
        mitigation_map = {
            "usb_insertion": "usb_controls",
            "powershell_execution": "antivirus",
            "data_access": "monitoring"
        }
        
        required_defense = mitigation_map.get(threat.event_type)
        
        if not required_defense:
            return {
                "success": False,
                "reason": "No defense system available for this threat type",
                "learning_point": "This shows the importance of comprehensive security coverage"
            }
        
        defense_system = self.defense_systems.get(required_defense)
        
        if not defense_system["active"]:
            return {
                "success": False,
                "reason": f"{defense_system['name']} is not active",
                "learning_point": f"Enable {defense_system['name']} to improve security",
                "recommendation": f"Activate {defense_system['name']} system"
            }
        
        # Simulate defense effectiveness
        if random.random() <= defense_system["effectiveness"]:
            threat.mitigated = True
            return {
                "success": True,
                "method": defense_system["name"],
                "learning_point": "Successful mitigation demonstrates effective security controls",
                "time_to_mitigation": f"{random.randint(1, 30)} seconds"
            }
        else:
            return {
                "success": False,
                "reason": "Defense system failed to stop the threat",
                "learning_point": "No security system is 100% effective - layered defense is important",
                "recommendation": "Consider additional security layers"
            }
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security system status"""
        active_systems = [sys for sys in self.defense_systems.values() if sys["active"]]
        total_effectiveness = sum(sys["effectiveness"] for sys in active_systems) / len(self.defense_systems)
        
        return {
            "systems": self.defense_systems,
            "overall_effectiveness": total_effectiveness,
            "active_systems": len(active_systems),
            "total_systems": len(self.defense_systems),
            "security_grade": self._calculate_grade(total_effectiveness),
            "recommendations": self._get_recommendations()
        }
    
    def _calculate_grade(self, effectiveness: float) -> str:
        """Calculate security grade"""
        if effectiveness >= 0.9:
            return "A (Excellent)"
        elif effectiveness >= 0.8:
            return "B (Good)"
        elif effectiveness >= 0.7:
            return "C (Fair)"
        elif effectiveness >= 0.6:
            return "D (Poor)"
        else:
            return "F (Critical Issues)"
    
    def _get_recommendations(self) -> List[str]:
        """Get security improvement recommendations"""
        recommendations = []
        
        for key, system in self.defense_systems.items():
            if not system["active"]:
                recommendations.append(f"Activate {system['name']} for better protection")
        
        active_count = len([s for s in self.defense_systems.values() if s["active"]])
        if active_count < len(self.defense_systems):
            recommendations.append("Enable all security systems for maximum protection")
        
        return recommendations

class CybersecurityEducator:
    """Main educational orchestrator for practical cybersecurity learning"""
    
    def __init__(self):
        self.threat_sim = PracticalThreatSimulator()
        self.defense_sim = BasicDefenseSimulator()
        self.learning_scenarios = self._load_scenarios()
        logger.info("Cybersecurity Educator initialized - Ready for learning!")
    
    def _load_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Load educational scenarios"""
        return {
            "usb_security_basics": {
                "name": "USB Security Fundamentals",
                "description": "Learn how USB devices can be security risks",
                "duration": "10 minutes",
                "difficulty": "Beginner",
                "learning_goals": [
                    "Understand USB attack vectors",
                    "Learn USB security controls",
                    "Practice threat detection"
                ]
            },
            "data_protection": {
                "name": "Data Protection Essentials",
                "description": "Learn to protect sensitive data",
                "duration": "15 minutes",
                "difficulty": "Beginner",
                "learning_goals": [
                    "Understand data encryption",
                    "Learn access controls",
                    "Practice secure data handling"
                ]
            },
            "incident_response": {
                "name": "Basic Incident Response",
                "description": "Learn to respond to security incidents",
                "duration": "20 minutes",
                "difficulty": "Intermediate",
                "learning_goals": [
                    "Recognize security incidents",
                    "Follow response procedures",
                    "Document lessons learned"
                ]
            }
        }
    
    def run_practical_demo(self) -> Dict[str, Any]:
        """Run a practical cybersecurity demonstration"""
        print("\n🎓 PRACTICAL CYBERSECURITY LEARNING DEMO")
        print("=" * 50)
        print("This demo shows real cybersecurity concepts in action!")
        
        demo_results = {
            "start_time": datetime.now().isoformat(),
            "scenarios": [],
            "learning_outcomes": []
        }
        
        # Scenario 1: USB Security
        print("\n📱 Scenario 1: USB Device Security")
        print("Simulating a suspicious USB device insertion...")
        
        usb_threat = self.threat_sim.simulate_usb_insertion()
        usb_response = self.defense_sim.attempt_mitigation(usb_threat)
        
        scenario_1 = {
            "name": "USB Security Test",
            "threat": usb_threat.to_dict(),
            "response": usb_response,
            "learning_outcome": "USB devices can carry malware - always scan unknown devices"
        }
        demo_results["scenarios"].append(scenario_1)
        
        self._display_scenario_results(scenario_1)
        time.sleep(2)
        
        # Scenario 2: PowerShell Execution
        print("\n💻 Scenario 2: Suspicious PowerShell Activity")
        print("Detecting potentially malicious script execution...")
        
        ps_threat = self.threat_sim.simulate_powershell_execution()
        ps_response = self.defense_sim.attempt_mitigation(ps_threat)
        
        scenario_2 = {
            "name": "PowerShell Security",
            "threat": ps_threat.to_dict(),
            "response": ps_response,
            "learning_outcome": "Monitor PowerShell execution - attackers often use it"
        }
        demo_results["scenarios"].append(scenario_2)
        
        self._display_scenario_results(scenario_2)
        time.sleep(2)
        
        # Security Assessment
        print("\n🛡️ Security System Assessment")
        security_status = self.defense_sim.get_security_status()
        demo_results["security_assessment"] = security_status
        
        self._display_security_assessment(security_status)
        
        # Learning Summary
        print("\n📚 What Did You Learn?")
        self._display_learning_summary(demo_results)
        
        demo_results["end_time"] = datetime.now().isoformat()
        return demo_results
    
    def _display_scenario_results(self, scenario: Dict[str, Any]):
        """Display scenario results in an educational way"""
        threat = scenario["threat"]
        response = scenario["response"]
        
        print(f"   🔍 Threat Detected: {threat['description']}")
        print(f"   📊 Severity Level: {threat['severity'].upper()}")
        
        if response["success"]:
            print(f"   ✅ Mitigation: SUCCESS using {response['method']}")
            if "time_to_mitigation" in response:
                print(f"   ⏱️  Response Time: {response['time_to_mitigation']}")
        else:
            print(f"   ❌ Mitigation: FAILED - {response['reason']}")
            if "recommendation" in response:
                print(f"   💡 Recommendation: {response['recommendation']}")
        
        print(f"   🎓 Learning Point: {response['learning_point']}")
    
    def _display_security_assessment(self, status: Dict[str, Any]):
        """Display security assessment in an educational format"""
        print(f"   📊 Overall Security Grade: {status['security_grade']}")
        print(f"   🛡️  Active Systems: {status['active_systems']}/{status['total_systems']}")
        
        print("   💼 Security Systems Status:")
        for system in status["systems"].values():
            status_icon = "🟢" if system["active"] else "🔴"
            print(f"      {status_icon} {system['name']}: {'ACTIVE' if system['active'] else 'INACTIVE'}")
        
        if status["recommendations"]:
            print("   💡 Recommendations:")
            for rec in status["recommendations"]:
                print(f"      • {rec}")
    
    def _display_learning_summary(self, results: Dict[str, Any]):
        """Display educational summary"""
        print("   🎯 Key Takeaways:")
        for scenario in results["scenarios"]:
            print(f"      • {scenario['learning_outcome']}")
        
        print("\n   📖 Remember These Security Principles:")
        print("      • Defense in depth - use multiple security layers")
        print("      • Monitor everything - visibility is key to security")
        print("      • Respond quickly - fast response limits damage")
        print("      • Keep learning - threats evolve constantly")
        
        print("\n   🚀 Next Steps:")
        print("      • Practice with your own Pi Zero setup")
        print("      • Try different scenarios and configurations")
        print("      • Learn about real security tools and techniques")
        print("      • Always test ethically and with permission")

    def get_available_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Get available learning scenarios"""
        return self.learning_scenarios
    
    def run_interactive_learning(self, scenario_name: str):
        """Run interactive learning scenario"""
        scenario = self.learning_scenarios.get(scenario_name)
        
        if not scenario:
            print(f"❌ Scenario '{scenario_name}' not found")
            print("Available scenarios:")
            for name, info in self.learning_scenarios.items():
                print(f"   • {name}: {info['name']}")
            return
        
        print(f"\n🎓 Starting: {scenario['name']}")
        print(f"📖 Description: {scenario['description']}")
        print(f"⏱️  Duration: {scenario['duration']}")
        print(f"📊 Difficulty: {scenario['difficulty']}")
        
        print("\n🎯 Learning Goals:")
        for goal in scenario["learning_goals"]:
            print(f"   • {goal}")
        
        input("\nPress Enter to begin the scenario...")
        
        # Run scenario-specific content
        if scenario_name == "usb_security_basics":
            self._run_usb_scenario()
        elif scenario_name == "data_protection":
            self._run_data_protection_scenario()
        elif scenario_name == "incident_response":
            self._run_incident_response_scenario()
    
    def _run_usb_scenario(self):
        """Run USB security learning scenario"""
        print("\n🔌 USB Security Learning Scenario")
        print("=" * 40)
        
        print("\n1. Understanding USB Threats")
        print("   USB devices can contain malware, steal data, or impersonate keyboards")
        
        print("\n2. Simulating USB Insertion")
        threat = self.threat_sim.simulate_usb_insertion()
        print(f"   Created threat: {threat.event_id}")
        
        print("\n3. Testing Defense Response")
        response = self.defense_sim.attempt_mitigation(threat)
        if response["success"]:
            print("   ✅ Defense system successfully blocked the threat!")
        else:
            print("   ❌ Defense system failed - this is a learning opportunity")
        
        print(f"\n💡 Key Learning: {response['learning_point']}")
    
    def _run_data_protection_scenario(self):
        """Run data protection learning scenario"""
        print("\n🔒 Data Protection Learning Scenario")
        print("=" * 40)
        
        print("\n1. Understanding Data Threats")
        print("   Sensitive data needs protection from unauthorized access")
        
        print("\n2. Simulating Data Access Attempt")
        threat = self.threat_sim.simulate_data_access()
        print(f"   Created threat: {threat.event_id}")
        
        print("\n3. Testing Access Controls")
        response = self.defense_sim.attempt_mitigation(threat)
        if response["success"]:
            print("   ✅ Access controls protected the data!")
        else:
            print("   ❌ Data access was not properly controlled")
        
        print(f"\n💡 Key Learning: {response['learning_point']}")
    
    def _run_incident_response_scenario(self):
        """Run incident response learning scenario"""
        print("\n🚨 Incident Response Learning Scenario")
        print("=" * 40)
        
        print("\n1. Detecting Multiple Threats")
        threats = [
            self.threat_sim.simulate_usb_insertion(),
            self.threat_sim.simulate_powershell_execution()
        ]
        
        print("\n2. Coordinated Response")
        for threat in threats:
            response = self.defense_sim.attempt_mitigation(threat)
            print(f"   Threat {threat.event_id}: {'✅ Mitigated' if response['success'] else '❌ Failed'}")
        
        print("\n3. Lessons Learned")
        print("   • Quick detection is crucial")
        print("   • Coordinated response improves effectiveness")
        print("   • Document everything for future improvement")

def main():
    """Main function for practical cybersecurity education"""
    educator = CybersecurityEducator()
    
    print("🔐 PRACTICAL CYBERSECURITY EDUCATION TOOL")
    print("Learn cybersecurity by doing!")
    print("=" * 50)
    
    try:
        # Run practical demonstration
        results = educator.run_practical_demo()
        
        # Save results for review
        with open(f"learning_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n✅ Learning session completed!")
        print("📄 Results saved for your review and study.")
        
        # Show available scenarios
        print(f"\n📚 Want to learn more? Try these scenarios:")
        scenarios = educator.get_available_scenarios()
        for name, info in scenarios.items():
            print(f"   • {info['name']} ({info['difficulty']}) - {info['duration']}")
        
        print(f"\nTo run a specific scenario: python -c \"from advanced_security import *; educator = CybersecurityEducator(); educator.run_interactive_learning('scenario_name')\"")
        
    except KeyboardInterrupt:
        print(f"\n⚠️ Learning session interrupted")
    except Exception as e:
        print(f"\n❌ Error during learning session: {e}")
        logger.error(f"Educational demo error: {e}")

if __name__ == "__main__":
    main()