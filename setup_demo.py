#!/usr/bin/env python3
"""
Quick Setup Script for Pi Zero Cybersecurity Educational Tool

This script automates the setup process for conference presentations
and educational demonstrations.

Usage:
    python3 setup_demo.py --mode conference
    python3 setup_demo.py --mode classroom
    python3 setup_demo.py --mode workshop

Author: Mr.D137
License: MIT (Educational Use)
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
import json

def install_dependencies():
    """Install required Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    
    return True

def setup_demo_environment(mode: str):
    """Set up demo environment based on mode"""
    print(f"🔧 Setting up {mode} demo environment...")
    
    # Create necessary directories
    directories = ["logs", "reports", "config", "collected_data"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Create demo configuration
    config = {
        "demo_mode": mode,
        "safety_level": "maximum",
        "educational_purpose": True,
        "real_data_collection": False,
        "audience_type": mode
    }
    
    with open("config/demo_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ {mode.title()} environment configured")

def run_system_check():
    """Run system compatibility check"""
    print("🔍 Running system compatibility check...")
    
    checks = {
        "Python version": sys.version_info >= (3, 8),
        "pip available": subprocess.run([sys.executable, "-m", "pip", "--version"], 
                                       capture_output=True).returncode == 0,
        "Git available": subprocess.run(["git", "--version"], 
                                       capture_output=True).returncode == 0,
    }
    
    all_passed = True
    for check, passed in checks.items():
        status = "✅" if passed else "❌"
        print(f"   {status} {check}")
        if not passed:
            all_passed = False
    
    return all_passed

def create_demo_shortcuts():
    """Create convenient demo shortcuts"""
    print("🔗 Creating demo shortcuts...")
    
    shortcuts = {
        "demo.py": "python3 src/main.py demo",
        "live_demo.py": "python3 presentations/live-demo-script.py",
        "decrypt_demo.py": "python3 decrypt_data.py --demo",
        "advanced_demo.py": "python3 src/tools/advanced_security.py"
    }
    
    for shortcut, command in shortcuts.items():
        with open(shortcut, "w") as f:
            f.write(f"#!/usr/bin/env python3\n")
            f.write(f"import subprocess\n")
            f.write(f"subprocess.run('{command}'.split())\n")
        
        os.chmod(shortcut, 0o755)
    
    print("✅ Demo shortcuts created")

def main():
    """Main setup function"""
    parser = argparse.ArgumentParser(description="Setup Pi Zero Cybersec Educational Tool")
    parser.add_argument("--mode", choices=["conference", "classroom", "workshop"],
                       default="conference", help="Demo mode to setup")
    parser.add_argument("--skip-deps", action="store_true", 
                       help="Skip dependency installation")
    
    args = parser.parse_args()
    
    print("🎓 Pi Zero Cybersecurity Educational Tool Setup")
    print("=" * 50)
    
    # System check
    if not run_system_check():
        print("❌ System check failed. Please resolve issues and try again.")
        return 1
    
    # Install dependencies
    if not args.skip_deps:
        if not install_dependencies():
            return 1
    
    # Setup demo environment
    setup_demo_environment(args.mode)
    
    # Create shortcuts
    create_demo_shortcuts()
    
    print("\n🎉 Setup completed successfully!")
    print(f"Ready for {args.mode} demonstration.")
    print("\nQuick start commands:")
    print("  python3 demo.py                    # Basic demo mode")
    print("  python3 live_demo.py               # Live presentation")
    print("  python3 decrypt_demo.py            # Decryption demo")
    print("  python3 advanced_demo.py           # Advanced features")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())