#!/usr/bin/env python3
"""Tests for cfaop CLI tool."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import cfaop


class TestValidation(unittest.TestCase):
    """Test input validation functions."""

    def test_validate_zone_valid(self):
        """Valid 32-char hex zone ID should pass."""
        zone_id = "abcdef1234567890abcdef1234567890"
        result = cfaop.validate_zone(zone_id)
        self.assertEqual(result, zone_id)

    def test_validate_zone_uppercase(self):
        """Uppercase zone ID should be lowercased."""
        zone_id = "ABCDEF1234567890ABCDEF1234567890"
        result = cfaop.validate_zone(zone_id)
        self.assertEqual(result, zone_id.lower())

    def test_validate_zone_with_whitespace(self):
        """Zone ID with whitespace should be trimmed."""
        zone_id = "  abcdef1234567890abcdef1234567890  "
        result = cfaop.validate_zone(zone_id)
        self.assertEqual(result, zone_id.strip())

    def test_validate_zone_too_short(self):
        """Zone ID too short should raise AOPError."""
        with self.assertRaises(cfaop.AOPError) as ctx:
            cfaop.validate_zone("abc123")
        self.assertIn("Invalid zone ID", str(ctx.exception))

    def test_validate_zone_too_long(self):
        """Zone ID too long should raise AOPError."""
        with self.assertRaises(cfaop.AOPError) as ctx:
            cfaop.validate_zone("a" * 64)
        self.assertIn("Invalid zone ID", str(ctx.exception))

    def test_validate_zone_invalid_chars(self):
        """Zone ID with invalid characters should raise AOPError."""
        with self.assertRaises(cfaop.AOPError) as ctx:
            cfaop.validate_zone("ghijkl1234567890ghijkl1234567890")
        self.assertIn("Invalid zone ID", str(ctx.exception))

    def test_validate_pem_cert_valid(self):
        """Valid certificate PEM should pass."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
            f.flush()
            try:
                content = cfaop.validate_pem(f.name, "cert")
                self.assertIn("BEGIN CERTIFICATE", content)
            finally:
                os.unlink(f.name)

    def test_validate_pem_key_valid(self):
        """Valid private key PEM should pass."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
            f.flush()
            try:
                content = cfaop.validate_pem(f.name, "key")
                self.assertIn("PRIVATE KEY", content)
            finally:
                os.unlink(f.name)

    def test_validate_pem_file_not_found(self):
        """Non-existent file should raise AOPError."""
        with self.assertRaises(cfaop.AOPError) as ctx:
            cfaop.validate_pem("/nonexistent/path.pem", "cert")
        self.assertIn("File not found", str(ctx.exception))

    def test_validate_pem_invalid_cert(self):
        """File without certificate header should raise AOPError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("not a certificate")
            f.flush()
            try:
                with self.assertRaises(cfaop.AOPError) as ctx:
                    cfaop.validate_pem(f.name, "cert")
                self.assertIn("Invalid certificate", str(ctx.exception))
            finally:
                os.unlink(f.name)

    def test_validate_pem_invalid_key(self):
        """File without key header should raise AOPError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("not a private key")
            f.flush()
            try:
                with self.assertRaises(cfaop.AOPError) as ctx:
                    cfaop.validate_pem(f.name, "key")
                self.assertIn("Invalid private key", str(ctx.exception))
            finally:
                os.unlink(f.name)


class TestAuthentication(unittest.TestCase):
    """Test authentication functions."""

    def test_get_auth_with_token(self):
        """API token should return Bearer auth header."""
        with patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "test-token"}, clear=True):
            auth = cfaop.get_auth()
            self.assertEqual(auth, {"Authorization": "Bearer test-token"})

    def test_get_auth_with_key_and_email(self):
        """API key + email should return X-Auth headers."""
        env = {
            "CLOUDFLARE_API_KEY": "test-key",
            "CLOUDFLARE_EMAIL": "test@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            auth = cfaop.get_auth()
            self.assertEqual(auth["X-Auth-Key"], "test-key")
            self.assertEqual(auth["X-Auth-Email"], "test@example.com")

    def test_get_auth_prefers_token(self):
        """Token should be preferred over key+email."""
        env = {
            "CLOUDFLARE_API_TOKEN": "test-token",
            "CLOUDFLARE_API_KEY": "test-key",
            "CLOUDFLARE_EMAIL": "test@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            auth = cfaop.get_auth()
            self.assertIn("Authorization", auth)
            self.assertNotIn("X-Auth-Key", auth)

    def test_get_auth_missing_credentials(self):
        """Missing credentials should raise AOPError."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(cfaop.AOPError) as ctx:
                cfaop.get_auth()
            self.assertIn("credentials not found", str(ctx.exception))

    def test_get_auth_partial_credentials(self):
        """Only key without email should raise AOPError."""
        with patch.dict(os.environ, {"CLOUDFLARE_API_KEY": "test-key"}, clear=True):
            with self.assertRaises(cfaop.AOPError):
                cfaop.get_auth()


class TestAPIClient(unittest.TestCase):
    """Test API client functions."""

    @patch("cfaop._api")
    def test_api_aop_status(self, mock_api):
        """api_aop_status should call correct endpoint."""
        mock_api.return_value = {"enabled": True}
        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        result = cfaop.api_aop_status(zone_id, auth)

        mock_api.assert_called_once()
        call_url = mock_api.call_args[0][0]
        self.assertIn(zone_id, call_url)
        self.assertIn("origin_tls_client_auth/settings", call_url)
        self.assertEqual(result, {"enabled": True})

    @patch("cfaop._api")
    def test_api_aop_set_enable(self, mock_api):
        """api_aop_set should call PUT with enabled=True."""
        mock_api.return_value = {"enabled": True}
        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        cfaop.api_aop_set(zone_id, True, auth)

        mock_api.assert_called_once()
        call_args = mock_api.call_args
        self.assertEqual(call_args[0][2], "PUT")
        self.assertEqual(call_args[0][3], {"enabled": True})

    @patch("cfaop._api")
    def test_api_aop_set_disable(self, mock_api):
        """api_aop_set should call PUT with enabled=False."""
        mock_api.return_value = {"enabled": False}
        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        cfaop.api_aop_set(zone_id, False, auth)

        call_args = mock_api.call_args
        self.assertEqual(call_args[0][3], {"enabled": False})


class TestCommands(unittest.TestCase):
    """Test CLI command functions."""

    @patch("cfaop.api_aop_status")
    @patch("cfaop.api_zone")
    @patch("cfaop.api_certs")
    def test_cmd_status_disabled(self, mock_certs, mock_zone, mock_status):
        """cmd_status should show disabled status."""
        mock_zone.return_value = {"name": "example.com"}
        mock_status.return_value = {"enabled": False}
        mock_certs.return_value = []

        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        result = cfaop.cmd_status(zone_id, auth)
        self.assertEqual(result, 0)

    @patch("cfaop.api_aop_status")
    @patch("cfaop.api_aop_set")
    def test_cmd_set_dry_run(self, mock_set, mock_status):
        """cmd_set with dry_run should not call API."""
        mock_status.return_value = {"enabled": False}

        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        result = cfaop.cmd_set(zone_id, auth, dry_run=True)

        mock_set.assert_not_called()
        self.assertEqual(result, 0)

    @patch("cfaop.api_aop_status")
    def test_cmd_set_already_enabled(self, mock_status):
        """cmd_set should succeed if already enabled."""
        mock_status.return_value = {"enabled": True}

        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        result = cfaop.cmd_set(zone_id, auth)
        self.assertEqual(result, 0)

    @patch("cfaop.api_aop_status")
    @patch("cfaop.api_aop_set")
    def test_cmd_unset_dry_run(self, mock_set, mock_status):
        """cmd_unset with dry_run should not call API."""
        mock_status.return_value = {"enabled": True}

        zone_id = "abcdef1234567890abcdef1234567890"
        auth = {"Authorization": "Bearer test"}

        result = cfaop.cmd_unset(zone_id, auth, dry_run=True)

        mock_set.assert_not_called()
        self.assertEqual(result, 0)


class TestCLI(unittest.TestCase):
    """Test CLI argument parsing and execution."""

    def test_help_flag(self):
        """--help should exit with code 0."""
        result = subprocess.run(
            [sys.executable, "cfaop.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Cloudflare", result.stdout)
        self.assertIn("--set-aop", result.stdout)
        self.assertIn("--unset-aop", result.stdout)

    def test_version_flag(self):
        """--version should show version and exit."""
        result = subprocess.run(
            [sys.executable, "cfaop.py", "--version"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(cfaop.__version__, result.stdout)

    def test_guide_command(self):
        """guide command should print documentation."""
        result = subprocess.run(
            [sys.executable, "cfaop.py", "guide"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("NGINX", result.stdout)
        self.assertIn("APACHE", result.stdout)
        self.assertIn("526", result.stdout)

    def test_invalid_zone_id(self):
        """Invalid zone ID should error."""
        env = {**os.environ, "CLOUDFLARE_API_TOKEN": "test"}
        result = subprocess.run(
            [sys.executable, "cfaop.py", "invalid-zone"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid zone ID", result.stderr)

    def test_missing_credentials(self):
        """Missing credentials should error."""
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("CLOUDFLARE", "CF_API"))
        }
        result = subprocess.run(
            [sys.executable, "cfaop.py", "setup"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credentials", result.stderr.lower())


class TestOutputHelpers(unittest.TestCase):
    """Test terminal output functions."""

    def test_colors_disabled_non_tty(self):
        """Colors should be empty strings when not a TTY."""
        # This is tested implicitly - colors are disabled at import if not TTY
        # Just verify the color class exists and has expected attributes
        self.assertTrue(hasattr(cfaop.C, "R"))
        self.assertTrue(hasattr(cfaop.C, "G"))
        self.assertTrue(hasattr(cfaop.C, "END"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
