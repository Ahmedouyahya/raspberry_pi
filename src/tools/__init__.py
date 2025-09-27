"""
Cybersecurity Tools Package

Contains encryption, decryption, OS detection, and other educational utilities.
"""

from .encrypt_data import SecureDataHandler
from .decrypt_data import decrypt_data
from .detect_os import detect_target_os

__all__ = ["SecureDataHandler", "decrypt_data", "detect_target_os"]