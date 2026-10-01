#!/usr/bin/env python3
"""
Test Suite for Pi Zero Cybersecurity Tool

Real tests for encryption/decryption, OS detection, payload validation,
educational content, CLI entry points, and the auto-attack orchestrator.
"""

import pytest
import json
import os
import sys
import tempfile
import re
import subprocess
from pathlib import Path
from typing import Dict, Any
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Add project root to sys.path so we can import src modules
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ---------------------------------------------------------------------------
# Try to import crypto modules — skip tests gracefully if missing
# ---------------------------------------------------------------------------
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Hash import SHA256
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Import project modules
from tools.detect_os import OSDetector, detect_os
from tools.encrypt_data import SecureDataHandler
from tools.demo_generator import DemoScenarioGenerator, create_demo_scenario

# Constants (must match encrypt_data.py)
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 16
KEY_LENGTH = 32
NONCE_LENGTH = 16
TAG_LENGTH = 16

# ===== Fixtures =====

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_data():
    """Sample data for testing"""
    return {
        "test_key": "test_value",
        "number": 42,
        "list": [1, 2, 3],
        "nested": {
            "inner": "value"
        },
    }


@pytest.fixture
def handler(temp_dir):
    """SecureDataHandler writing to a temp directory."""
    return SecureDataHandler(storage_path=str(temp_dir))


# ===== Encryption / Decryption =====

@pytest.mark.skipif(not HAS_CRYPTO, reason="pycryptodomex not installed")
class TestEncryption:
    """Test encryption and decryption functionality"""

    def test_encrypt_returns_bytes(self, handler, sample_data):
        blob = handler.encrypt_data(sample_data)
        assert isinstance(blob, bytes)
        # Blob must contain at least salt + nonce + tag
        assert len(blob) > SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH

    def test_encrypt_decrypt_cycle(self, handler, sample_data):
        """Encrypt then decrypt — payload must match original data."""
        blob = handler.encrypt_data(sample_data, password="test-pw")
        result = handler.decrypt_data(blob, password="test-pw")
        assert result["payload"] == sample_data

    def test_wrong_password_fails(self, handler, sample_data):
        """Decryption with wrong password must raise."""
        blob = handler.encrypt_data(sample_data, password="correct")
        with pytest.raises(Exception):
            handler.decrypt_data(blob, password="wrong")

    def test_tampered_blob_fails(self, handler, sample_data):
        """Flipping a byte in ciphertext must fail authentication."""
        blob = handler.encrypt_data(sample_data, password="pw")
        corrupted = bytearray(blob)
        corrupted[-1] ^= 0xFF  # flip last byte
        with pytest.raises(Exception):
            handler.decrypt_data(bytes(corrupted), password="pw")

    def test_data_integrity(self, handler):
        """Various data types survive the round-trip."""
        data = {"a": 1, "b": "hello", "c": [True, None, 3.14]}
        blob = handler.encrypt_data(data, password="pw")
        result = handler.decrypt_data(blob, password="pw")
        assert result["payload"] == data

    def test_empty_payload(self, handler):
        blob = handler.encrypt_data({}, password="pw")
        result = handler.decrypt_data(blob, password="pw")
        assert result["payload"] == {}

    def test_large_payload(self, handler):
        """Encrypt/decrypt a larger payload (~100 KB JSON)."""
        data = {"key_" + str(i): "x" * 100 for i in range(1000)}
        blob = handler.encrypt_data(data, password="pw")
        result = handler.decrypt_data(blob, password="pw")
        assert result["payload"] == data

    def test_store_and_load_file(self, handler, sample_data, temp_dir):
        """Round-trip through file I/O."""
        handler.store_encrypted_data(sample_data, "test.enc")
        loaded = handler.load_encrypted_data("test.enc")
        assert loaded["payload"] == sample_data
        assert (temp_dir / "test.enc").exists()

    def test_metadata_fields_present(self, handler, sample_data):
        blob = handler.encrypt_data(sample_data, password="pw")
        result = handler.decrypt_data(blob, password="pw")
        assert "device_id" in result
        assert "timestamp" in result
        assert "encryption_info" in result
        assert result["encryption_info"]["algorithm"] == "AES-256-GCM"


# ===== OS Detection =====

class TestOSDetection:
    """Test OS detection functionality"""

    def test_detect_returns_known_os(self):
        detector = OSDetector()
        detected = detector.detect_os()
        assert detected in ("windows", "macos", "linux", "android", "ios", "unknown")

    def test_detect_on_current_platform(self):
        """On Linux CI / dev machine the result must be 'linux'."""
        detector = OSDetector()
        detected = detector.detect_os()
        if sys.platform.startswith("linux"):
            assert detected == "linux"
        elif sys.platform.startswith("darwin"):
            assert detected == "macos"
        elif sys.platform.startswith("win"):
            assert detected == "windows"

    def test_system_details_populated(self):
        detector = OSDetector()
        detector.detect_os()
        assert detector.details.get("system") is not None
        assert detector.details.get("python_version") is not None

    def test_backward_compat_function(self):
        result = detect_os()
        assert isinstance(result, str)
        assert len(result) > 0

    @patch("sys.platform", "win32")
    def test_windows_platform_string(self):
        detector = OSDetector()
        assert detector._detect_by_platform() == "windows"

    @patch("sys.platform", "darwin")
    def test_macos_platform_string(self):
        detector = OSDetector()
        assert detector._detect_by_platform() == "macos"

    @patch("sys.platform", "linux")
    def test_linux_platform_string(self):
        detector = OSDetector()
        assert detector._detect_by_platform() == "linux"


# ===== Payload Structure =====

class TestPayloads:
    """Validate payload files exist and contain safety disclaimers."""

    PAYLOAD_DIR = PROJECT_ROOT / "src" / "payloads"

    def test_windows_payload_exists(self):
        assert (self.PAYLOAD_DIR / "windows_payload.ps1").is_file()

    def test_macos_payload_exists(self):
        assert (self.PAYLOAD_DIR / "macos_payload.sh").is_file()

    def test_windows_payload_has_disclaimer(self):
        text = (self.PAYLOAD_DIR / "windows_payload.ps1").read_text()
        assert "EDUCATIONAL" in text.upper()
        assert "authorized" in text.lower()

    def test_macos_payload_has_disclaimer(self):
        text = (self.PAYLOAD_DIR / "macos_payload.sh").read_text()
        assert "EDUCATIONAL" in text.upper()
        assert "authorized" in text.lower()

    def test_macos_payload_is_executable_syntax(self):
        text = (self.PAYLOAD_DIR / "macos_payload.sh").read_text()
        assert text.startswith("#!/bin/bash")


# ===== Educational Content =====

class TestEducationalContent:
    """Verify educational and ethical content is present."""

    def test_readme_exists(self):
        assert (PROJECT_ROOT / "README.md").is_file()

    def test_security_md_exists(self):
        assert (PROJECT_ROOT / "SECURITY.md").is_file()

    def test_legal_ethical_guide_exists(self):
        assert (PROJECT_ROOT / "docs" / "legal-ethical-guidelines.md").is_file()


# ===== Security Safeguards =====

class TestSecurity:
    """Basic static-analysis-style checks on the source tree."""

    SOURCE_FILES = list((PROJECT_ROOT / "src").rglob("*.py"))

    def test_no_hardcoded_passwords(self):
        """Ensure no obvious password literals in Python source."""
        pattern = re.compile(r'password\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE)
        violations = []
        for f in self.SOURCE_FILES:
            for i, line in enumerate(f.read_text().splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue
                if pattern.search(line):
                    violations.append(f"{f.name}:{i}")
        assert len(violations) == 0, f"Possible hardcoded passwords: {violations}"

    def test_no_eval_or_exec(self):
        """No eval() or exec() in production code."""
        for f in self.SOURCE_FILES:
            text = f.read_text()
            for func in ("eval(", "exec("):
                assert func not in text, f"{func} found in {f.name}"


# ===== Integration =====

@pytest.mark.skipif(not HAS_CRYPTO, reason="pycryptodomex not installed")
class TestIntegration:
    """End-to-end workflow tests."""

    def test_encrypt_save_load_decrypt(self, temp_dir, sample_data):
        handler = SecureDataHandler(storage_path=str(temp_dir))
        handler.store_encrypted_data(sample_data, "integration.enc")

        # Simulate loading on same device (same device_id)
        loaded = handler.load_encrypted_data("integration.enc")
        assert loaded["payload"] == sample_data


# ===== Demo Generator =====

class TestDemoGenerator:
    """Test the demo scenario engine."""

    def test_classroom_scenario_structure(self):
        scenario = create_demo_scenario("classroom")
        assert "scenario_info" in scenario
        assert scenario["scenario_info"]["type"] == "Classroom Demonstration"

    def test_conference_scenario_structure(self):
        scenario = create_demo_scenario("conference")
        assert scenario["scenario_info"]["type"] == "Conference Presentation"

    def test_workshop_scenario_structure(self):
        scenario = create_demo_scenario("workshop")
        assert scenario["scenario_info"]["type"] == "Hands-on Workshop"

    def test_unknown_type_defaults_to_classroom(self):
        scenario = create_demo_scenario("nonexistent")
        assert scenario["scenario_info"]["type"] == "Classroom Demonstration"

    def test_generator_class_creates_all_types(self):
        gen = DemoScenarioGenerator()
        for stype in ("classroom", "conference", "workshop"):
            s = gen.create_demo_scenario(stype)
            assert isinstance(s, dict)
            assert "scenario_info" in s


# ===== OS Detection Detail =====

class TestOSDetectionDetailed:
    """Additional detection tests."""

    def test_get_detailed_info_has_timestamp(self):
        detector = OSDetector()
        detector.detect_os()
        info = detector.get_detailed_info()
        # After the fix, detection_timestamp should be a float
        assert isinstance(info["detection_timestamp"], float)

    def test_supported_os_mapping(self):
        d = OSDetector()
        assert "windows" in d.SUPPORTED_OS
        assert "macos" in d.SUPPORTED_OS
        assert "linux" in d.SUPPORTED_OS


# ===== Auto Attack Orchestrator =====

class TestAutoAttackModule:
    """Test the auto_attack module can be imported and configured."""

    def test_import_auto_attack(self):
        from auto_attack import AutoAttack, AttackConfig, HIDKeyboard, StatusLED  # noqa: F401

    def test_attack_config_defaults(self):
        from auto_attack import AttackConfig
        cfg = AttackConfig()
        assert cfg.mount_point == "/mnt/usb_share"
        assert cfg.auto_encrypt is True

    def test_hid_keyboard_char_map_completeness(self):
        from auto_attack import _CHAR_MAP
        # All printable ASCII from space to tilde (32-126)
        missing = []
        for code in range(32, 127):
            ch = chr(code)
            if ch not in _CHAR_MAP:
                missing.append(ch)
        # We expect only a handful of very obscure chars to be missing
        assert len(missing) == 0, f"Missing HID mappings: {missing}"

    def test_detect_host_os_defaults_to_windows(self):
        from auto_attack import detect_host_os
        with tempfile.TemporaryDirectory() as td:
            assert detect_host_os(td) == "windows"

    def test_detect_host_os_macos(self):
        from auto_attack import detect_host_os
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".DS_Store").touch()
            assert detect_host_os(td) == "macos"

    def test_detect_host_os_windows(self):
        from auto_attack import detect_host_os
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "desktop.ini").touch()
            assert detect_host_os(td) == "windows"

    def test_attack_result_dataclass(self):
        from auto_attack import AttackResult
        r = AttackResult()
        assert r.host_os == "unknown"
        assert r.errors == []


# ===== CLI Entry Points =====

class TestCLI:
    """Test command-line entry points run without crashing."""

    def test_main_demo_mode(self):
        """python src/main.py demo should exit 0."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "src" / "main.py"), "demo"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "Demo" in result.stdout or "demo" in result.stdout.lower()

    def test_main_default_mode_is_demo(self):
        """python src/main.py (no args) should default to demo."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "src" / "main.py")],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_decrypt_data_demo_mode(self):
        """python decrypt_data.py --demo should exit 0."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "decrypt_data.py"), "--demo"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_decrypt_data_no_args_defaults_to_demo(self):
        """python decrypt_data.py (no args) should now default to demo."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "decrypt_data.py")],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_main_train_with_module(self):
        """python src/main.py train --module 1 should work non-interactively."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "src" / "main.py"), "train", "-m", "1"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "USB" in result.stdout or "Training" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
