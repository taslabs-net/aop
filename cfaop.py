#!/usr/bin/env python3
"""
cfaop - Cloudflare Authenticated Origin Pulls (AOP) Management Tool

A self-contained CLI tool for configuring AOP on Cloudflare zones.
AOP ensures only Cloudflare can connect to your origin by presenting
a TLS client certificate that your origin server verifies.

Setup:
    export CLOUDFLARE_API_TOKEN="your-token"

Usage:
    cfaop setup                         # Interactive wizard (recommended)
    cfaop ZONE_ID                       # Show AOP status
    cfaop ZONE_ID --set-aop             # Enable AOP
    cfaop ZONE_ID --unset-aop           # Disable AOP
    cfaop ZONE_ID --set-aop --dry-run   # Preview changes
    cfaop ZONE_ID --troubleshoot        # Diagnose issues
    cfaop guide                         # Full documentation

Requirements:
    Python 3.8+ with 'requests' library (pip install requests)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# =============================================================================
# Configuration
# =============================================================================

API_BASE = "https://api.cloudflare.com/client/v4"
TIMEOUT = 30
CF_CA_URL = (
    "https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem"
)
CF_DOCS_URL = "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/"

# =============================================================================
# Terminal Colors
# =============================================================================


class C:
    """ANSI color codes for terminal output."""

    R = "\033[91m"  # Red
    G = "\033[92m"  # Green
    Y = "\033[93m"  # Yellow
    B = "\033[94m"  # Blue
    C = "\033[96m"  # Cyan
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


# Disable colors if not a TTY
if not sys.stdout.isatty():
    C.R = C.G = C.Y = C.B = C.C = C.BOLD = C.DIM = C.END = ""


def ok(msg: str) -> None:
    """Print success message."""
    print(f"{C.G}✓ SUCCESS:{C.END} {msg}")


def err(msg: str) -> None:
    """Print error message to stderr."""
    print(f"{C.R}✗ ERROR:{C.END} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    """Print warning message."""
    print(f"{C.Y}⚠ WARNING:{C.END} {msg}")


def info(msg: str) -> None:
    """Print info message."""
    print(f"{C.C}ℹ INFO:{C.END} {msg}")


def step(msg: str) -> None:
    """Print step indicator."""
    print(f"{C.BOLD}→ {msg}{C.END}")


def dry(msg: str) -> None:
    """Print dry-run message."""
    print(f"{C.Y}[DRY-RUN]{C.END} {msg}")


def header(msg: str) -> None:
    """Print section header."""
    print(f"\n{C.BOLD}{'=' * 60}\n  {msg}\n{'=' * 60}{C.END}\n")


def subheader(msg: str) -> None:
    """Print subsection header."""
    print(f"\n{C.BOLD}{C.B}── {msg} ──{C.END}\n")


# =============================================================================
# Exceptions
# =============================================================================


class AOPError(Exception):
    """User-facing error with helpful message."""


class APIError(Exception):
    """Cloudflare API error."""

    def __init__(self, msg: str, code: int | None = None, errors: list | None = None):
        super().__init__(msg)
        self.code = code
        self.errors = errors or []


# =============================================================================
# HTTP Client
# =============================================================================


def _api(url: str, auth: dict, method: str = "GET", body: dict | None = None) -> Any:
    """Make Cloudflare API request. Returns result or raises APIError."""
    headers = {"Content-Type": "application/json", **auth}

    # Try requests library (better error handling)
    try:
        import requests

        r = requests.request(method, url, headers=headers, json=body, timeout=TIMEOUT)
        data = r.json()
    except ImportError:
        # Fallback to urllib (no dependencies)
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            data = json.loads(e.read().decode())

    if data.get("success"):
        return data.get("result", {})

    errors = data.get("errors", [])
    msgs = [f"[{e.get('code', '?')}] {e.get('message', '?')}" for e in errors]
    raise APIError(" | ".join(msgs) or "Unknown API error", errors=errors)


def _paginate(url: str, auth: dict) -> list[dict]:
    """Fetch all pages from a paginated endpoint."""
    results: list[dict] = []
    page = 1
    while True:
        data = _api(f"{url}?page={page}&per_page=50", auth)
        if not isinstance(data, list) or not data:
            return results or ([data] if data else [])
        results.extend(data)
        if len(data) < 50:
            break
        page += 1
    return results


# =============================================================================
# Authentication
# =============================================================================


def get_auth() -> dict[str, str]:
    """Get auth headers from environment variables."""
    # API Token (preferred)
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}

    # Global API Key + Email (legacy)
    key = os.environ.get("CLOUDFLARE_API_KEY") or os.environ.get("CF_API_KEY")
    email = os.environ.get("CLOUDFLARE_EMAIL") or os.environ.get("CF_API_EMAIL")
    if key and email:
        return {"X-Auth-Key": key, "X-Auth-Email": email}

    raise AOPError(
        "Cloudflare credentials not found!\n\n"
        "Set one of these:\n"
        "  export CLOUDFLARE_API_TOKEN='your-api-token'\n"
        "OR\n"
        "  export CLOUDFLARE_API_KEY='your-global-api-key'\n"
        "  export CLOUDFLARE_EMAIL='your-email@example.com'\n\n"
        "Get credentials: https://dash.cloudflare.com/profile/api-tokens",
    )


def verify_auth(auth: dict) -> bool:
    """Check if credentials are valid."""
    try:
        endpoint = "/user/tokens/verify" if "Authorization" in auth else "/user"
        _api(f"{API_BASE}{endpoint}", auth)
        return True
    except APIError:
        return False


# =============================================================================
# Validation
# =============================================================================


def validate_zone(zone_id: str) -> str:
    """Validate zone ID format (32 hex characters)."""
    zone_id = zone_id.strip().lower()
    if not re.match(r"^[a-f0-9]{32}$", zone_id):
        raise AOPError(
            f"Invalid zone ID: '{zone_id}'\n"
            "Must be exactly 32 hexadecimal characters.\n"
            "Find it: Cloudflare Dashboard → Domain → Overview → right sidebar",
        )
    return zone_id


def validate_pem(path: str, kind: str) -> str:
    """Read and validate a PEM file (cert or key)."""
    p = Path(path)
    if not p.exists():
        raise AOPError(f"File not found: {path}")
    if not p.is_file():
        raise AOPError(f"Not a file: {path}")

    content = p.read_text()
    if kind == "cert" and "-----BEGIN CERTIFICATE-----" not in content:
        raise AOPError(f"Invalid certificate: {path}\nMissing BEGIN CERTIFICATE header")
    if kind == "key" and "PRIVATE KEY-----" not in content:
        raise AOPError(f"Invalid private key: {path}\nMissing PRIVATE KEY header")

    return content


# =============================================================================
# Cloudflare AOP API
# =============================================================================


def api_zones(auth: dict) -> list[dict]:
    """List all zones."""
    return _paginate(f"{API_BASE}/zones", auth)


def api_zone(zone_id: str, auth: dict) -> dict | None:
    """Get zone by ID."""
    try:
        return _api(f"{API_BASE}/zones/{zone_id}", auth)
    except APIError:
        return None


def api_aop_status(zone_id: str, auth: dict) -> dict:
    """Get AOP settings."""
    return _api(f"{API_BASE}/zones/{zone_id}/origin_tls_client_auth/settings", auth)


def api_aop_set(zone_id: str, enabled: bool, auth: dict) -> dict:
    """Enable or disable AOP."""
    return _api(
        f"{API_BASE}/zones/{zone_id}/origin_tls_client_auth/settings",
        auth,
        "PUT",
        {"enabled": enabled},
    )


def api_certs(zone_id: str, auth: dict) -> list[dict]:
    """List AOP certificates."""
    return _paginate(f"{API_BASE}/zones/{zone_id}/origin_tls_client_auth", auth)


def api_cert_upload(zone_id: str, cert: str, key: str, auth: dict) -> dict:
    """Upload AOP certificate."""
    return _api(
        f"{API_BASE}/zones/{zone_id}/origin_tls_client_auth",
        auth,
        "POST",
        {"certificate": cert, "private_key": key},
    )


def api_cert_delete(zone_id: str, cert_id: str, auth: dict) -> dict:
    """Delete AOP certificate."""
    return _api(
        f"{API_BASE}/zones/{zone_id}/origin_tls_client_auth/{cert_id}",
        auth,
        "DELETE",
    )


# =============================================================================
# Commands
# =============================================================================


def cmd_status(zone_id: str, auth: dict) -> int:
    """Show AOP status for a zone."""
    zone_id = validate_zone(zone_id)
    subheader(f"AOP Status for {zone_id[:8]}...")

    # Zone info
    zone = api_zone(zone_id, auth)
    if zone:
        print(f"Zone: {C.BOLD}{zone.get('name', 'Unknown')}{C.END}")

    # AOP status
    status = api_aop_status(zone_id, auth)
    enabled = status.get("enabled", False)
    status_str = (
        f"{C.G}{C.BOLD}ENABLED ✓{C.END}"
        if enabled
        else f"{C.R}{C.BOLD}DISABLED ✗{C.END}"
    )
    print(f"AOP:  {status_str}")

    # Certificates
    certs = api_certs(zone_id, auth)
    print(f"\nCertificates: {len(certs)}")
    if certs:
        for cert in certs:
            cid = cert.get("id", "?")[:16]
            exp = cert.get("expires_on", "?")
            st = cert.get("status", "?")
            color = C.G if st == "active" else C.Y
            print(f"  • {cid}... | Status: {color}{st}{C.END} | Expires: {exp}")
    else:
        print(f"  {C.DIM}(using Cloudflare's managed certificate){C.END}")

    # Summary
    print()
    if enabled:
        ok("AOP is active. Cloudflare presents client certs to your origin.")
        info("Ensure your origin is configured to verify client certificates!")
    else:
        warn("AOP is not enabled. Run with --set-aop to enable.")

    return 0


def cmd_set(zone_id: str, auth: dict, dry_run: bool = False) -> int:
    """Enable AOP."""
    zone_id = validate_zone(zone_id)

    # Already enabled?
    if api_aop_status(zone_id, auth).get("enabled"):
        ok("AOP is already enabled for this zone!")
        return 0

    if dry_run:
        dry(f"Would ENABLE AOP for zone {zone_id[:8]}...")
        dry("Cloudflare would present client certificates to your origin.")
        dry("Your origin must be configured to require and verify client certs.")
        info("Run without --dry-run to apply changes.")
        return 0

    step(f"Enabling AOP for zone {zone_id[:8]}...")
    api_aop_set(zone_id, True, auth)

    # Verify
    if api_aop_status(zone_id, auth).get("enabled"):
        ok("AOP has been ENABLED!")
        print(f"""
{C.BOLD}IMPORTANT - Configure your origin server:{C.END}

1. Download Cloudflare's CA certificate:
   {C.C}curl -o cloudflare-ca.pem {CF_CA_URL}{C.END}

2. Configure your web server:

   {C.BOLD}NGINX:{C.END}
   ssl_client_certificate /path/to/cloudflare-ca.pem;
   ssl_verify_client on;

   {C.BOLD}Apache:{C.END}
   SSLCACertificateFile /path/to/cloudflare-ca.pem
   SSLVerifyClient require

   {C.BOLD}Caddy:{C.END}
   tls {{
     client_auth {{
       mode require_and_verify
       trusted_ca_cert_file /path/to/cloudflare-ca.pem
     }}
   }}

3. Restart your web server
""")
        return 0

    err("Enable succeeded but verification failed. Please retry.")
    return 1


def cmd_unset(zone_id: str, auth: dict, dry_run: bool = False) -> int:
    """Disable AOP."""
    zone_id = validate_zone(zone_id)

    # Already disabled?
    if not api_aop_status(zone_id, auth).get("enabled"):
        ok("AOP is already disabled for this zone.")
        return 0

    if dry_run:
        dry(f"Would DISABLE AOP for zone {zone_id[:8]}...")
        dry("Cloudflare would stop presenting client certificates.")
        warn("Your origin may reject requests if it still requires client certs!")
        info("Run without --dry-run to apply changes.")
        return 0

    step(f"Disabling AOP for zone {zone_id[:8]}...")
    api_aop_set(zone_id, False, auth)

    # Verify
    if not api_aop_status(zone_id, auth).get("enabled"):
        ok("AOP has been DISABLED!")
        warn("If your origin requires client certs, it will now reject requests!")
        info("Update your origin config to remove the client cert requirement.")
        return 0

    err("Disable succeeded but verification failed. Please retry.")
    return 1


def cmd_upload(
    zone_id: str,
    cert_path: str,
    key_path: str,
    auth: dict,
    dry_run: bool = False,
    enable: bool = False,
) -> int:
    """Upload certificate and optionally enable AOP."""
    zone_id = validate_zone(zone_id)

    step("Validating certificate and key files...")
    cert = validate_pem(cert_path, "cert")
    ok(f"Certificate: {cert_path}")
    key = validate_pem(key_path, "key")
    ok(f"Private key: {key_path}")

    if dry_run:
        dry(f"Would upload certificate to zone {zone_id[:8]}...")
        if enable:
            dry("Would also ENABLE AOP after upload.")
        info("Run without --dry-run to apply changes.")
        return 0

    step(f"Uploading certificate to zone {zone_id[:8]}...")
    result = api_cert_upload(zone_id, cert, key, auth)
    ok("Certificate uploaded!")
    print(f"  ID: {C.C}{result.get('id', '?')}{C.END}")
    print(f"  Status: {result.get('status', '?')}")
    print(f"  Expires: {result.get('expires_on', '?')}")

    if enable:
        print()
        return cmd_set(zone_id, auth)

    print()
    info("Certificate uploaded. Run with --set-aop to enable AOP.")
    return 0


def cmd_troubleshoot(zone_id: str, auth: dict) -> int:
    """Diagnose AOP configuration issues."""
    zone_id = validate_zone(zone_id)
    header("AOP Troubleshooter")
    issues = []

    # Check zone
    step("Checking zone access...")
    zone = api_zone(zone_id, auth)
    if zone:
        ok(f"Zone: {zone.get('name', '?')}")
    else:
        err(f"Zone {zone_id} not found")
        issues.append("Zone not found - check zone ID")

    # Check AOP
    step("Checking AOP status...")
    try:
        status = api_aop_status(zone_id, auth)
        if status.get("enabled"):
            ok("AOP is ENABLED")
        else:
            warn("AOP is DISABLED")
            issues.append("AOP not enabled - use --set-aop")
    except APIError as e:
        err(f"Cannot get status: {e}")
        issues.append("Cannot retrieve AOP status")

    # Check certs
    step("Checking certificates...")
    try:
        certs = api_certs(zone_id, auth)
        if certs:
            ok(f"Found {len(certs)} certificate(s)")
            for cert in certs:
                st = cert.get("status", "?")
                if st != "active":
                    warn(f"Cert {cert.get('id', '?')[:8]}... status: {st}")
                    issues.append(f"Certificate status '{st}' (not active)")
        else:
            info("No custom certs - using Cloudflare's managed certificate")
    except APIError as e:
        err(f"Cannot list certs: {e}")

    # Check DNS
    if zone:
        step("Checking DNS...")
        domain = zone.get("name", "")
        if domain:
            try:
                ip = socket.gethostbyname(domain)
                ok(f"{domain} → {ip}")
            except socket.gaierror:
                warn(f"Cannot resolve {domain}")
                issues.append("Domain does not resolve")

    # Summary
    subheader("Summary")
    if issues:
        err(f"Found {len(issues)} issue(s):")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        print(f"""
{C.BOLD}Common Fixes:{C.END}
  {C.C}AOP not enabled?{C.END}  →  cfaop {zone_id} --set-aop
  {C.C}526 error?{C.END}        →  Origin not verifying client certs
  {C.C}525 error?{C.END}        →  Origin SSL broken (openssl s_client -connect ...)
""")
        return 1

    ok("No issues found with Cloudflare AOP configuration!")
    print(f"\nIf still having issues, check your {C.BOLD}origin server{C.END}:")
    print("  1. Is it requiring client certificates?")
    print("  2. Does it trust Cloudflare's CA?")
    print(f"  3. Download CA: {CF_CA_URL}")
    return 0


def cmd_wizard(auth: dict) -> int:
    """Interactive setup wizard."""
    header("Cloudflare AOP Setup Wizard")

    # Verify auth
    step("Step 1: Verifying credentials...")
    if not verify_auth(auth):
        err("Invalid credentials. Check your API token or key/email.")
        return 1
    ok("Credentials verified!")

    # List zones
    step("Step 2: Finding your zones...")
    zones = api_zones(auth)
    if not zones:
        err("No zones found!")
        return 1

    print(f"\nFound {len(zones)} zone(s):\n")
    for i, z in enumerate(zones, 1):
        print(f"  {i}. {z['name']} ({z['id'][:8]}...)")

    # Select zone
    step("\nStep 3: Select a zone")
    while True:
        try:
            choice = input(f"\nEnter number (1-{len(zones)}) or zone ID: ").strip()
            if re.match(r"^[a-f0-9]{32}$", choice.lower()):
                zone_id = choice.lower()
                zone_name = next(
                    (z["name"] for z in zones if z["id"] == zone_id),
                    zone_id[:8],
                )
                break
            idx = int(choice) - 1
            if 0 <= idx < len(zones):
                zone_id, zone_name = zones[idx]["id"], zones[idx]["name"]
                break
            print("Invalid selection.")
        except ValueError:
            print("Enter a number or zone ID.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130

    ok(f"Selected: {zone_name}")

    # Check status
    step("\nStep 4: Checking current status...")
    status = api_aop_status(zone_id, auth)
    enabled = status.get("enabled", False)
    print(f"  AOP: {C.G if enabled else C.R}{enabled}{C.END}")

    if enabled:
        ok("AOP is already enabled!")
        info(f"Run: cfaop {zone_id} --troubleshoot")
        return 0

    # Enable
    step("\nStep 5: Ready to enable AOP")
    print("""
This will:
  • Enable AOP on your zone
  • Cloudflare will present client certificates to your origin

You must then configure your origin to require client certs.
""")
    try:
        if input("Enable AOP now? [y/N]: ").strip().lower() != "y":
            info("Cancelled.")
            return 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130

    return cmd_set(zone_id, auth)


def cmd_guide() -> int:
    """Print full documentation."""
    print(f"""
{"=" * 72}
   CLOUDFLARE AUTHENTICATED ORIGIN PULLS (AOP) - COMPLETE GUIDE
{"=" * 72}

WHAT IS AOP?

  AOP ensures requests to your origin come from Cloudflare, not attackers.
  Cloudflare presents a TLS client certificate; your origin verifies it.
  This blocks direct attacks even if your origin IP is discovered.

CREDENTIALS

  export CLOUDFLARE_API_TOKEN="your-token"    # Recommended
  OR
  export CLOUDFLARE_API_KEY="your-key"        # Legacy
  export CLOUDFLARE_EMAIL="your-email"

  Get credentials: https://dash.cloudflare.com/profile/api-tokens

COMMANDS

  cfaop setup                      Interactive wizard (start here!)
  cfaop ZONE_ID                    Show AOP status
  cfaop ZONE_ID --set-aop          Enable AOP
  cfaop ZONE_ID --unset-aop        Disable AOP
  cfaop ZONE_ID --dry-run          Preview changes (with --set/--unset)
  cfaop ZONE_ID --upload C K       Upload certificate C and key K
  cfaop ZONE_ID --troubleshoot     Diagnose issues
  cfaop guide                      Show this guide

ORIGIN SERVER CONFIGURATION

  After enabling AOP, configure your origin:

  1. Download Cloudflare's CA:
     curl -o cloudflare-ca.pem {CF_CA_URL}

  2. Configure your server:

     NGINX:
       ssl_client_certificate /path/to/cloudflare-ca.pem;
       ssl_verify_client on;

     APACHE:
       SSLCACertificateFile /path/to/cloudflare-ca.pem
       SSLVerifyClient require
       SSLVerifyDepth 1

     CADDY:
       tls {{
         client_auth {{
           mode require_and_verify
           trusted_ca_cert_file /path/to/cloudflare-ca.pem
         }}
       }}

TROUBLESHOOTING

  526 - Invalid SSL Certificate
    → Origin not requiring/verifying client certs
    → Add: ssl_verify_client on; (nginx)
    → Add: SSLVerifyClient require (apache)

  525 - SSL Handshake Failed
    → Origin SSL/TLS broken (not AOP)
    → Test: openssl s_client -connect ORIGIN:443

  403/400 when hitting origin directly
    → CORRECT! AOP is blocking non-Cloudflare traffic

MORE INFO

  Documentation: {CF_DOCS_URL}
  CA Certificate: {CF_CA_URL}

SUPPORT

  Need help? Contact: rc-commerce@cloudflare.com

{"=" * 72}
""")
    return 0


# =============================================================================
# Main
# =============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cfaop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"""
{"=" * 72}
   CLOUDFLARE AUTHENTICATED ORIGIN PULLS (AOP) - MANAGEMENT TOOL
{"=" * 72}

   AOP ensures only Cloudflare can reach your origin by presenting a TLS
   client certificate that your origin verifies. This blocks attackers
   from bypassing Cloudflare even if they discover your origin IP.
""",
        epilog=f"""
{"=" * 72}
   SETUP
{"=" * 72}

   Set credentials (choose one):

   API Token (Recommended):
     export CLOUDFLARE_API_TOKEN="your-token"

   Global API Key (Legacy):
     export CLOUDFLARE_API_KEY="your-key"
     export CLOUDFLARE_EMAIL="your-email"

   Get credentials: https://dash.cloudflare.com/profile/api-tokens

{"=" * 72}
   EXAMPLES
{"=" * 72}

   Interactive setup (recommended for first-time users):
     %(prog)s setup

   Check current AOP status:
     %(prog)s abc123def456...

   Enable AOP:
     %(prog)s abc123def456... --set-aop
     %(prog)s abc123def456... --set-aop --dry-run    (preview first)

   Disable AOP:
     %(prog)s abc123def456... --unset-aop
     %(prog)s abc123def456... --unset-aop --dry-run  (preview first)

   Upload custom certificate:
     %(prog)s abc123def456... --upload cert.pem key.pem
     %(prog)s abc123def456... --upload cert.pem key.pem --enable

   Troubleshoot issues:
     %(prog)s abc123def456... --troubleshoot

   Full documentation:
     %(prog)s guide

{"=" * 72}
   FIND YOUR ZONE ID
{"=" * 72}

   1. Go to https://dash.cloudflare.com
   2. Click your domain
   3. Look in the RIGHT sidebar under "API"
   4. Copy "Zone ID" (32 hex characters)

{"=" * 72}
   AFTER ENABLING AOP
{"=" * 72}

   Configure your origin to require client certificates:

   1. Download Cloudflare's CA:
      curl -o cloudflare-ca.pem \\
        {CF_CA_URL}

   2. Add to your web server config:

      NGINX:  ssl_verify_client on;
              ssl_client_certificate /path/to/cloudflare-ca.pem;

      APACHE: SSLVerifyClient require
              SSLCACertificateFile /path/to/cloudflare-ca.pem

   3. Restart your web server

{"=" * 72}
   COMMON ERRORS
{"=" * 72}

   526 - Origin not verifying client certs (add ssl_verify_client on)
   525 - Origin SSL broken (test with openssl s_client)
   403 when hitting origin directly - CORRECT! AOP is working

{"=" * 72}
   SUPPORT
{"=" * 72}

   Need help? Contact: rc-commerce@cloudflare.com

{"=" * 72}
""",
    )

    parser.add_argument(
        "zone_id",
        nargs="?",
        metavar="ZONE_ID",
        help='Zone ID (32 hex chars), "setup", or "guide"',
    )
    parser.add_argument("--set-aop", action="store_true", help="Enable AOP")
    parser.add_argument("--unset-aop", action="store_true", help="Disable AOP")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying",
    )
    parser.add_argument(
        "--upload",
        nargs=2,
        metavar=("CERT", "KEY"),
        help="Upload certificate and private key (PEM files)",
    )
    parser.add_argument(
        "--enable",
        action="store_true",
        help="With --upload: also enable AOP",
    )
    parser.add_argument(
        "--troubleshoot",
        action="store_true",
        help="Diagnose AOP issues",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Special commands
    if args.zone_id == "guide":
        return cmd_guide()

    if args.zone_id in (None, "setup"):
        try:
            return cmd_wizard(get_auth())
        except AOPError as e:
            err(str(e))
            return 1

    # Zone-based commands
    try:
        zone_id = validate_zone(args.zone_id)
        auth = get_auth()
    except AOPError as e:
        err(str(e))
        return 1

    if not verify_auth(auth):
        err("Invalid credentials. Check your API token or key/email.")
        return 1

    try:
        if args.set_aop and args.unset_aop:
            err("Cannot use --set-aop and --unset-aop together")
            return 1

        if args.troubleshoot:
            return cmd_troubleshoot(zone_id, auth)
        if args.upload:
            return cmd_upload(
                zone_id,
                args.upload[0],
                args.upload[1],
                auth,
                args.dry_run,
                args.enable,
            )
        if args.set_aop:
            return cmd_set(zone_id, auth, args.dry_run)
        if args.unset_aop:
            return cmd_unset(zone_id, auth, args.dry_run)

        return cmd_status(zone_id, auth)

    except APIError as e:
        err(f"API error: {e}")
        return 1
    except KeyboardInterrupt:
        warn("Cancelled")
        return 130
    except Exception as e:
        err(f"Unexpected error: {e}")
        if os.environ.get("DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
