#!/usr/bin/env python3
"""
Data Decryption Utility for Educational Cybersecurity Tool

This standalone utility decrypts data collected by the Pi Zero cybersecurity tool.
It demonstrates proper cryptographic decryption practices and secure data handling.

Educational Purpose:
- Shows secure decryption implementation
- Demonstrates proper key derivation
- Teaches cryptographic security principles
- Provides data analysis capabilities for educational scenarios

Usage:
    python3 decrypt_data.py <encrypted_file> <pi_serial>
    python3 decrypt_data.py --demo  # For educational demonstration

Author: Mr.D137
License: MIT (Educational Use)
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("Error: pycryptodomex library required. Install with: pip3 install pycryptodomex")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Educational constants
EDUCATIONAL_DISCLAIMER = """
================================================================================
                    EDUCATIONAL CYBERSECURITY TOOL
================================================================================
This tool is designed for educational purposes and authorized security testing.
Unauthorized use is illegal and unethical.

Educational Value:
- Demonstrates data-at-rest vulnerabilities
- Shows importance of encryption
- Teaches secure decryption practices
- Illustrates defense strategies
================================================================================
"""

def decrypt_data(encrypted_blob: bytes, password: str) -> Dict[str, Any]:
    """
    Decrypt data encrypted with the companion encryption tool
    
    Educational Notes:
    - Uses AES-256-GCM for authenticated encryption
    - PBKDF2 with high iteration count prevents brute force
    - Proper error handling prevents information leakage
    
    Args:
        encrypted_blob: Encrypted data blob with embedded salt, nonce, and tag
        password: Password for decryption (typically Pi serial number)
        
    Returns:
        dict: Decrypted data structure
        
    Raises:
        ValueError: If decryption fails or data is corrupted
    """
    try:
        logger.info("Starting decryption process...")
        
        # Validate input
        if len(encrypted_blob) < 48:  # Minimum: 16+16+16 bytes for salt+nonce+tag
            raise ValueError("Invalid encrypted data format")
        
        # Extract components from blob
        salt = encrypted_blob[:16]      # 128-bit salt
        nonce = encrypted_blob[16:32]   # 128-bit nonce
        tag = encrypted_blob[32:48]     # 128-bit authentication tag
        ciphertext = encrypted_blob[48:] # Variable length ciphertext
        
        logger.info(f"Extracted components: salt={len(salt)}B, nonce={len(nonce)}B, "
                   f"tag={len(tag)}B, ciphertext={len(ciphertext)}B")
        
        # Derive decryption key using PBKDF2
        key = PBKDF2(
            password=password,
            salt=salt,
            dkLen=32,  # 256-bit key
            count=100000,  # High iteration count for security
            hmac_hash_module=SHA256
        )
        
        # Create AES-GCM cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Parse JSON data
        decrypted_data = json.loads(plaintext.decode('utf-8'))
        
        logger.info("Decryption successful")
        return decrypted_data
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError(f"Decryption failed: {e}")

def generate_demo_data() -> Dict[str, Any]:
    """
    Generate demonstration data for educational purposes
    
    Returns:
        dict: Sample data structure showing typical collected information
    """
    return {
        "notice": "EDUCATIONAL DEMONSTRATION DATA - NOT REAL COLLECTION",
        "purpose": "Cybersecurity awareness and defense training",
        "demo_data": {
            "system_info": {
                "os": "Windows 10",
                "hostname": "DEMO-PC",
                "username": "demo_user"
            },
            "browser_data": {
                "browsers_found": ["Chrome", "Firefox", "Edge"],
                "total_passwords": 5,
                "total_cookies": 150,
                "note": "Real tool would show encrypted/hashed data"
            },
            "educational_notes": [
                "This demonstrates what data could be extracted",
                "Real attacks would target encrypted browser stores",
                "Defense: Use master passwords and full-disk encryption",
                "Always keep browsers updated",
                "Enable two-factor authentication"
            ]
        }
    }

def analyze_data(data: Dict[str, Any]) -> None:
    """
    Analyze and display decrypted data for educational purposes
    
    Args:
        data: Decrypted data dictionary
    """
    print("\n" + "="*80)
    print("                    DATA ANALYSIS REPORT")
    print("="*80)
    
    # Display metadata
    if "timestamp" in data:
        print(f"Collection Time: {data['timestamp']}")
    if "device_id" in data:
        print(f"Device ID: {data['device_id'][:8]}...")
    
    # Educational information
    if "notice" in data:
        print(f"\nNotice: {data['notice']}")
    
    # Analyze payload if present
    if "payload" in data:
        payload = data["payload"]
        print(f"\nPayload Analysis:")
        print(f"- Data type: {type(payload).__name__}")
        
        if isinstance(payload, dict):
            print(f"- Keys found: {list(payload.keys())}")
            
            # Analyze system information
            if "system_info" in payload:
                sys_info = payload["system_info"]
                print(f"- Target OS: {sys_info.get('os', 'Unknown')}")
                print(f"- Hostname: {sys_info.get('hostname', 'Unknown')}")
            
            # Analyze browser data
            if "browser_data" in payload:
                browser_data = payload["browser_data"]
                print(f"- Browsers found: {browser_data.get('browsers_found', [])}")
    
    # Educational recommendations
    print(f"\n" + "="*80)
    print("                    EDUCATIONAL RECOMMENDATIONS")
    print("="*80)
    print("Defense Strategies:")
    print("1. Enable full-disk encryption")
    print("2. Use browser master passwords")
    print("3. Keep software updated")
    print("4. Implement USB port controls")
    print("5. Enable endpoint detection and response (EDR)")
    print("6. Regular security awareness training")

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(
        description="Decrypt data from Pi Zero Cybersecurity Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EDUCATIONAL_DISCLAIMER
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "encrypted_file",
        nargs="?",
        help="Path to encrypted data file"
    )
    group.add_argument(
        "--demo",
        action="store_true",
        help="Generate and display demonstration data"
    )
    
    parser.add_argument(
        "pi_serial",
        nargs="?",
        help="Raspberry Pi serial number (password)"
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for decrypted data (JSON format)"
    )
    
    parser.add_argument(
        "--analyze",
        "-a",
        action="store_true",
        help="Perform educational analysis of the data"
    )
    
    args = parser.parse_args()
    
    print(EDUCATIONAL_DISCLAIMER)
    
    try:
        if args.demo:
            # Generate demo data
            logger.info("Generating demonstration data...")
            data = generate_demo_data()
        else:
            # Validate arguments
            if not args.pi_serial:
                parser.error("Pi serial number required when decrypting real data")
            
            if not os.path.exists(args.encrypted_file):
                print(f"Error: File '{args.encrypted_file}' not found", file=sys.stderr)
                sys.exit(1)
            
            # Read and decrypt file
            logger.info(f"Reading encrypted file: {args.encrypted_file}")
            with open(args.encrypted_file, "rb") as f:
                encrypted_data = f.read()
            
            data = decrypt_data(encrypted_data, args.pi_serial)
        
        # Output results
        if args.output:
            logger.info(f"Saving decrypted data to: {args.output}")
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2)
        else:
            print("\nDecrypted Data:")
            print(json.dumps(data, indent=2))
        
        # Perform analysis if requested
        if args.analyze:
            analyze_data(data)
        
        logger.info("Operation completed successfully")
        
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()