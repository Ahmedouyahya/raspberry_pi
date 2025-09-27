#!/usr/bin/env python3
"""
Demo Generator for Educational Cybersecurity Tool

This module creates safe, simulated demonstrations for classroom and conference presentations.
It generates realistic but non-harmful examples of what attackers might collect.

Educational Purpose:
- Safe classroom demonstrations
- Conference presentation scenarios
- Training environment setup
- Security awareness building

Author: Mr.D137
License: MIT (Educational Use)
"""

import json
import random
import string
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class DemoScenarioGenerator:
    """Generate realistic but safe demonstration scenarios"""
    
    def __init__(self):
        self.demo_users = [
            "alex.student", "jordan.researcher", "taylor.admin", 
            "casey.developer", "morgan.analyst"
        ]
        
        self.demo_hostnames = [
            "EDUCATION-PC", "TRAINING-LAB", "DEMO-WORKSTATION",
            "CONFERENCE-LAPTOP", "WORKSHOP-PC"
        ]
        
        self.demo_browsers = ["Chrome", "Firefox", "Edge", "Safari"]
        
        self.educational_websites = [
            "cybersecurity-course.edu", "security-training.org",
            "ethical-hacking-lab.edu", "infosec-academy.edu"
        ]
    
    def create_demo_scenario(self, scenario_type: str = "classroom") -> Dict[str, Any]:
        """
        Create a complete demo scenario
        
        Args:
            scenario_type: Type of scenario ("classroom", "conference", "workshop")
            
        Returns:
            dict: Complete demo scenario data
        """
        scenarios = {
            "classroom": self._create_classroom_scenario,
            "conference": self._create_conference_scenario,
            "workshop": self._create_workshop_scenario
        }
        
        generator = scenarios.get(scenario_type, self._create_classroom_scenario)
        return generator()
    
    def _create_classroom_scenario(self) -> Dict[str, Any]:
        """Create classroom demonstration scenario"""
        return {
            "scenario_info": {
                "type": "Classroom Demonstration",
                "purpose": "Educational cybersecurity awareness",
                "safety_level": "COMPLETELY SAFE - NO REAL DATA",
                "audience": "Students and educators"
            },
            "educational_disclaimer": {
                "notice": "THIS IS SIMULATED DATA FOR EDUCATIONAL PURPOSES ONLY",
                "warning": "No real user data was collected or harmed",
                "purpose": "Demonstrate attack concepts and defense strategies"
            },
            "simulated_collection": {
                "timestamp": datetime.now().isoformat(),
                "device_info": {
                    "hostname": random.choice(self.demo_hostnames),
                    "username": random.choice(self.demo_users),
                    "os": "Demo OS 10.0",
                    "ip_address": "192.168.1.100"
                },
                "browser_simulation": {
                    "browsers_found": random.sample(self.demo_browsers, 2),
                    "simulated_passwords": 8,
                    "simulated_cookies": 150,
                    "simulated_history_entries": 500,
                    "note": "All values are simulated for educational purposes"
                },
                "network_simulation": {
                    "wifi_networks": [
                        {"ssid": "EducationWiFi", "security": "WPA2"},
                        {"ssid": "StudentNetwork", "security": "WPA3"},
                        {"ssid": "LibraryAccess", "security": "Open"}
                    ],
                    "note": "These are fictional network examples"
                }
            },
            "educational_content": self._generate_educational_content(),
            "defense_recommendations": self._generate_defense_recommendations()
        }
    
    def _create_conference_scenario(self) -> Dict[str, Any]:
        """Create conference presentation scenario"""
        return {
            "scenario_info": {
                "type": "Conference Presentation",
                "purpose": "Professional cybersecurity education",
                "safety_level": "DEMONSTRATION ONLY - NO REAL ATTACKS",
                "audience": "Security professionals and researchers"
            },
            "attack_simulation": {
                "vector": "USB HID Injection",
                "target_os": "Windows 10 Enterprise",
                "execution_time": "15 seconds",
                "detection_probability": "Low (without proper EDR)",
                "mitigation_effectiveness": "High (with proper controls)"
            },
            "technical_details": {
                "payload_type": "PowerShell",
                "evasion_techniques": [
                    "AMSI bypass simulation",
                    "UAC bypass demonstration",
                    "Process injection concepts"
                ],
                "note": "All techniques shown for defensive education only"
            },
            "impact_assessment": {
                "data_types": [
                    "Browser stored credentials",
                    "System configuration",
                    "Network information",
                    "Application data"
                ],
                "business_impact": "High - Complete system compromise possible",
                "compliance_implications": [
                    "GDPR data breach notification",
                    "SOX audit findings",
                    "HIPAA security incidents"
                ]
            },
            "educational_content": self._generate_advanced_educational_content(),
            "defense_recommendations": self._generate_enterprise_defense_recommendations()
        }
    
    def _create_workshop_scenario(self) -> Dict[str, Any]:
        """Create hands-on workshop scenario"""
        return {
            "scenario_info": {
                "type": "Hands-on Workshop",
                "purpose": "Practical cybersecurity training",
                "safety_level": "CONTROLLED ENVIRONMENT - SAFE LEARNING",
                "audience": "Security practitioners and students"
            },
            "lab_environment": {
                "setup": "Isolated virtual machines",
                "target_systems": ["Windows 10", "macOS Big Sur", "Ubuntu 20.04"],
                "safety_measures": [
                    "Network isolation",
                    "Snapshot restoration",
                    "No real user data",
                    "Instructor supervision"
                ]
            },
            "learning_objectives": [
                "Understand USB attack vectors",
                "Practice incident detection",
                "Implement defense controls",
                "Develop response procedures"
            ],
            "practical_exercises": [
                {
                    "exercise": "Attack Detection",
                    "description": "Identify signs of USB-based compromise",
                    "tools": ["Windows Event Viewer", "Sysmon", "Process Monitor"]
                },
                {
                    "exercise": "Defense Implementation",
                    "description": "Configure USB device controls",
                    "tools": ["Group Policy", "PowerShell", "Registry Editor"]
                },
                {
                    "exercise": "Incident Response",
                    "description": "Practice response procedures",
                    "tools": ["Forensic toolkit", "Network analyzer", "SIEM"]
                }
            ],
            "educational_content": self._generate_hands_on_educational_content()
        }
    
    def _generate_educational_content(self) -> Dict[str, Any]:
        """Generate educational content for basic scenarios"""
        return {
            "key_concepts": [
                "USB devices are automatically trusted by most systems",
                "HID attacks can simulate keyboard input without detection",
                "Data at rest is vulnerable without proper encryption",
                "Physical access often bypasses network security controls"
            ],
            "real_world_examples": [
                "Stuxnet used USB propagation",
                "BadUSB demonstrates firmware attacks",
                "Corporate espionage via USB drops",
                "Social engineering with malicious USB devices"
            ],
            "learning_outcomes": [
                "Understand USB attack vectors",
                "Recognize signs of compromise",
                "Implement basic defense controls",
                "Develop security awareness"
            ]
        }
    
    def _generate_advanced_educational_content(self) -> Dict[str, Any]:
        """Generate advanced educational content for professional audiences"""
        return {
            "threat_landscape": {
                "attack_frequency": "USB attacks increased 50% in 2024",
                "target_sectors": ["Healthcare", "Financial", "Government", "Education"],
                "attacker_profiles": ["Nation-state", "Cybercriminals", "Insider threats"]
            },
            "technical_analysis": {
                "attack_chain": [
                    "Initial access via USB device",
                    "Privilege escalation",
                    "Persistence establishment",
                    "Data exfiltration",
                    "Command and control"
                ],
                "detection_points": [
                    "USB device insertion events",
                    "Unusual process execution",
                    "Network communications",
                    "File system changes"
                ]
            },
            "compliance_considerations": {
                "frameworks": ["NIST", "ISO 27001", "CIS Controls"],
                "requirements": ["Asset inventory", "Access controls", "Monitoring"],
                "audit_evidence": ["Logs", "Configurations", "Procedures"]
            }
        }
    
    def _generate_hands_on_educational_content(self) -> Dict[str, Any]:
        """Generate hands-on educational content for workshops"""
        return {
            "lab_scenarios": [
                {
                    "name": "USB Drop Attack",
                    "description": "Simulate finding USB device in parking lot",
                    "learning_objective": "Understand social engineering aspects"
                },
                {
                    "name": "HID Injection",
                    "description": "Demonstrate keystroke injection attack",
                    "learning_objective": "See how HID attacks bypass security"
                },
                {
                    "name": "Data Exfiltration",
                    "description": "Show how data can be stolen via USB",
                    "learning_objective": "Understand data protection needs"
                }
            ],
            "tools_introduced": [
                "Rubber Ducky (educational use)",
                "USB Killer (awareness only)",
                "Flipper Zero (demonstration)",
                "Custom Pi Zero setup"
            ],
            "skills_developed": [
                "Threat modeling",
                "Risk assessment",
                "Control implementation",
                "Incident response"
            ]
        }
    
    def _generate_defense_recommendations(self) -> List[Dict[str, str]]:
        """Generate basic defense recommendations"""
        return [
            {
                "category": "Technical",
                "control": "USB Device Whitelisting",
                "description": "Only allow approved USB devices to connect",
                "implementation": "Group Policy or endpoint management tools"
            },
            {
                "category": "Technical",
                "control": "Endpoint Detection and Response",
                "description": "Deploy EDR solutions to detect unusual activity",
                "implementation": "CrowdStrike, SentinelOne, or similar platforms"
            },
            {
                "category": "Administrative",
                "control": "Security Awareness Training",
                "description": "Train users about USB security risks",
                "implementation": "Regular training sessions and phishing simulations"
            },
            {
                "category": "Physical",
                "control": "USB Port Controls",
                "description": "Physically disable unused USB ports",
                "implementation": "Port locks or BIOS-level disabling"
            }
        ]
    
    def _generate_enterprise_defense_recommendations(self) -> List[Dict[str, str]]:
        """Generate enterprise-level defense recommendations"""
        return [
            {
                "category": "Architecture",
                "control": "Zero Trust Network",
                "description": "Implement zero trust principles for all devices",
                "implementation": "Micro-segmentation and continuous verification"
            },
            {
                "category": "Detection",
                "control": "SIEM Integration",
                "description": "Integrate USB events into SIEM platform",
                "implementation": "Splunk, QRadar, or Azure Sentinel"
            },
            {
                "category": "Response",
                "control": "Automated Containment",
                "description": "Automatically isolate compromised systems",
                "implementation": "SOAR platforms and network access control"
            },
            {
                "category": "Governance",
                "control": "Risk Management",
                "description": "Regular risk assessments and policy updates",
                "implementation": "GRC platforms and audit procedures"
            }
        ]

def create_demo_scenario(scenario_type: str = "classroom") -> Dict[str, Any]:
    """
    Create a demonstration scenario for educational purposes
    
    Args:
        scenario_type: Type of scenario to create
        
    Returns:
        dict: Complete demo scenario
    """
    generator = DemoScenarioGenerator()
    scenario = generator.create_demo_scenario(scenario_type)
    
    logger.info(f"Generated {scenario_type} demo scenario")
    return scenario

def save_demo_scenario(scenario: Dict[str, Any], output_file: str) -> None:
    """
    Save demo scenario to file
    
    Args:
        scenario: Demo scenario data
        output_file: Output file path
    """
    with open(output_file, 'w') as f:
        json.dump(scenario, f, indent=2)
    
    logger.info(f"Demo scenario saved to {output_file}")

def main():
    """Command-line interface for demo generator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate educational demo scenarios")
    parser.add_argument("--type", choices=["classroom", "conference", "workshop"],
                       default="classroom", help="Type of demo scenario")
    parser.add_argument("--output", "-o", help="Output file for demo scenario")
    
    args = parser.parse_args()
    
    # Generate scenario
    scenario = create_demo_scenario(args.type)
    
    if args.output:
        save_demo_scenario(scenario, args.output)
    else:
        print(json.dumps(scenario, indent=2))

if __name__ == "__main__":
    main()