#!/usr/bin/env python3
"""
Quick test of the enterprise cybersecurity platform
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src', 'tools'))

from advanced_security import AdvancedSecurityEducationOrchestrator
import asyncio

async def quick_demo():
    print('🏢 TESTING ENTERPRISE CYBERSECURITY PLATFORM')
    print('=' * 50)
    
    orchestrator = AdvancedSecurityEducationOrchestrator()
    
    # Test scenario availability
    scenarios = orchestrator.get_available_enterprise_scenarios()
    print(f'✅ Available scenarios: {len(scenarios)}')
    for name, info in scenarios.items():
        print(f'   • {info["name"]} ({info["difficulty"]})')
    
    # Test security posture assessment
    metrics = orchestrator.get_session_metrics()
    posture = metrics["security_posture"]
    print(f'✅ Security posture grade: {posture["security_grade"]}')
    print(f'✅ Monthly security cost: ${posture["monthly_cost"]:,}')
    print(f'✅ Active security systems: {posture["active_systems"]}/{posture["total_systems"]}')
    
    print('\n🎉 Enterprise platform ready for professional use!')
    print('🎓 Ready for conference presentations and educational deployment!')

if __name__ == "__main__":
    asyncio.run(quick_demo())