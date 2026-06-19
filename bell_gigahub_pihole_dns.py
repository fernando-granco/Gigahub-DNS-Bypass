#!/usr/bin/env python3
"""
Bell Gigahub - Force Pi-hole as DNS Server
==========================================
This script modifies the Bell Gigahub's DNS relay settings
to force all LAN devices to use your Pi-hole as the DNS server.

The Gigahub GUI does NOT allow you to change the DNS server for LAN devices.
This script skips the GUI and talks directly to the router's API.

Requirements:
  - Python 3.6+ (no extra packages needed)
  - Your Bell Gigahub admin password (on the modem sticker)
  - Pi-hole must be running and accessible on your LAN

Usage:
  python bell_gigahub_pihole_dns.py

You'll be prompted for:
  1. Router IP (default: 192.168.2.1)
  2. Admin password (from modem sticker)
  3. Primary DNS / DNS 1 (default: 192.168.2.10)
  4. Secondary DNS / DNS 2 (default: same as DNS 1)

https://github.com/fernando-granco/Bell-Gigahub-Local-DNS
"""

import hashlib
import json
import urllib.request
import urllib.parse
import random
import sys


# ─── Configuration ───────────────────────────────────────────────

def get_config():
    """Prompt user for configuration values."""
    print("Bell Gigahub + Pi-hole DNS Setup")
    print("-" * 50)

    router_ip = input("Router IP [default 192.168.2.1]: ").strip()
    if not router_ip:
        router_ip = "192.168.2.1"

    password = input("Admin password: ").strip()
    if not password:
        print("ERROR: Password is required.", file=sys.stderr)
        sys.exit(1)

    dns1 = input("Primary DNS (DNS 1): ").strip()
    if not dns1:
        dns1 = "192.168.2.10"

    dns2 = input("Secondary DNS (DNS 2): ").strip()
    if not dns2:
        dns2 = dns1

    return router_ip, password, dns1, dns2


# ─── Gigahub API Client ─────────────────────────────────────────

class GigahubAPI:
    """Client for the Bell Gigahub JSON-RPC API."""

    def __init__(self, router_ip, password):
        self.base_url = f"http://{router_ip}"
        self.user = "admin"
        self.hash_encoder_pass = hashlib.sha512(
            password.encode()
        ).hexdigest()
        self.session_id = None
        self.nonce = None
        self.ha1 = None
        self.req_index = 0

        self.headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json, text/javascript, */*; q=0.01"),
            ("X-Requested-With", "XMLHttpRequest"),
            ("User-Agent", "Mozilla/5.0"),
        ]

    def _compute_auth_key(self, req_id, cnonce):
        """Compute the auth-key for request authentication."""
        auth_str = f"{self.ha1}:{req_id}:{cnonce}:JSON:/cgi/json-req"
        return hashlib.sha512(auth_str.encode()).hexdigest()

    def _send(self, actions):
        """Send a request to the Gigahub JSON-RPC endpoint."""
        cnonce = str(random.randint(0, 4294967295))
        req_id = self.req_index
        self.req_index += 1
        auth_key = self._compute_auth_key(req_id, cnonce)

        body = {
            "request": {
                "id": req_id,
                "session-id": self.session_id or "0",
                "priority": False,
                "cnonce": cnonce,
                "auth-key": auth_key,
                "actions": actions,
            }
        }

        json_str = json.dumps(body, separators=(",", ":"))
        data = urllib.parse.urlencode({"req": json_str}).encode()

        req = urllib.request.Request(
            f"{self.base_url}/cgi/json-req",
            data=data,
            method="POST",
        )
        for name, value in self.headers:
            req.add_header(name, value)

        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    def login(self):
        """Authenticate with the router."""
        ha1_initial = hashlib.sha512(
            f"{self.user}::{self.hash_encoder_pass}".encode()
        ).hexdigest()

        cnonce = str(random.randint(0, 4294967295))
        auth_key = hashlib.sha512(
            f"{ha1_initial}:0:{cnonce}:JSON:/cgi/json-req".encode()
        ).hexdigest()

        body = {
            "request": {
                "id": 0,
                "session-id": "0",
                "priority": False,
                "cnonce": cnonce,
                "auth-key": auth_key,
                "actions": [
                    {
                        "id": 0,
                        "method": "logIn",
                        "parameters": {
                            "user": self.user,
                            "persistent": "true",
                            "session-options": {
                                "nss": [
                                    {
                                        "name": "gtw",
                                        "uri": "http://sagemcom.com/gateway-data",
                                    }
                                ],
                                "context-flags": {
                                    "get-content-name": True,
                                    "local-time": True,
                                },
                                "capability-depth": 2,
                                "capability-flags": {
                                    "name": True,
                                    "default-value": False,
                                    "restriction": True,
                                    "description": False,
                                },
                                "time-format": "ISO_8601",
                            },
                        },
                    }
                ],
            }
        }

        json_str = json.dumps(body, separators=(",", ":"))
        data = urllib.parse.urlencode({"req": json_str}).encode()

        req = urllib.request.Request(
            f"{self.base_url}/cgi/json-req",
            data=data,
            method="POST",
        )
        for name, value in self.headers:
            req.add_header(name, value)

        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        action = result["reply"]["actions"][0]
        if action["error"]["code"] != 16777239:  # XMO_NO_ERR
            raise RuntimeError(
                f"Login failed: {action['error']['description']} "
                f"(code {action['error']['code']})"
            )

        self.session_id = str(
            action["callbacks"][0]["parameters"]["id"]
        )
        self.nonce = action["callbacks"][0]["parameters"]["nonce"]
        self.ha1 = hashlib.sha512(
            f"{self.user}:{self.nonce}:{self.hash_encoder_pass}".encode()
        ).hexdigest()
        self.req_index = 1

    def get_value(self, xpath):
        """Get a value from the router configuration."""
        opts = {
            "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
            "context-flags": {"get-content-name": True, "local-time": True},
            "capability-depth": 3,
            "capability-flags": {
                "name": True,
                "default-value": True,
                "restriction": True,
                "description": True,
            },
            "time-format": "ISO_8601",
        }

        result = self._send(
            [
                {
                    "id": 0,
                    "method": "getValue",
                    "xpath": xpath,
                    "options": opts,
                }
            ]
        )

        action = result["reply"]["actions"][0]
        if action["error"]["code"] != 16777239:
            raise RuntimeError(
                f"getValue failed: {action['error']['description']}"
            )

        return action["callbacks"][0]["parameters"]["value"]

    def set_value(self, xpath, value):
        """Set a value in the router configuration."""
        opts = {
            "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
            "context-flags": {"get-content-name": True, "local-time": True},
            "capability-depth": 3,
            "capability-flags": {
                "name": True,
                "default-value": True,
                "restriction": True,
                "description": True,
            },
            "time-format": "ISO_8601",
        }

        result = self._send(
            [
                {
                    "id": 0,
                    "method": "setValue",
                    "xpath": xpath,
                    "parameters": {"value": value},
                    "options": opts,
                }
            ]
        )

        action = result["reply"]["actions"][0]
        if action["error"]["code"] != 16777239:
            raise RuntimeError(
                f"setValue failed: {action['error']['description']}"
            )


# ─── Main ───────────────────────────────────────────────────────

def main():
    router_ip, password, dns1, dns2 = get_config()
    dns_servers = f"{dns1},{dns2}" if dns2 else dns1
    api = GigahubAPI(router_ip, password)

    print()
    print("Connecting to router...")
    try:
        api.login()
        print("  Login successful.")
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        print("  Check that the router IP and admin password are correct.", file=sys.stderr)
        sys.exit(1)

    # 1. Read current settings
    print()
    print("Reading current settings...")

    try:
        fwd1 = api.get_value(
            "Device/DNS/Relay/Forwardings/Forwarding[1]/DNSServer"
        )
        print(f"  Current DNS relay #1: {fwd1}")
    except Exception:
        pass

    try:
        fwd2 = api.get_value(
            "Device/DNS/Relay/Forwardings/Forwarding[2]/DNSServer"
        )
        print(f"  Current DNS relay #2: {fwd2}")
    except Exception:
        pass

    # 2. Apply changes
    print()
    print("Applying changes...")

    # Set DNS relay forwardings (what the router uses when devices query it for DNS)
    api.set_value(
        "Device/DNS/Relay/Forwardings/Forwarding[1]/DNSServer",
        dns1,
    )
    print(f"  DNS relay #1 -> {dns1}")

    api.set_value(
        "Device/DNS/Relay/Forwardings/Forwarding[2]/DNSServer",
        dns2,
    )
    print(f"  DNS relay #2 -> {dns2}")

    # 3. Verify
    print()
    print("Verifying changes...")

    new_fwd1 = api.get_value(
        "Device/DNS/Relay/Forwardings/Forwarding[1]/DNSServer"
    )
    print(f"  DNS relay #1: {new_fwd1}")

    new_fwd2 = api.get_value(
        "Device/DNS/Relay/Forwardings/Forwarding[2]/DNSServer"
    )
    print(f"  DNS relay #2: {new_fwd2}")

    # 4. Summary
    print()
    print("=" * 50)
    print("CONFIGURATION COMPLETE!")
    print()
    print("What was changed:")
    print(f"  Relay #1  -> {dns1}  (router forwards DNS here)")
    print(f"  Relay #2  -> {dns2}  (backup forwarding)")
    print()
    print("To apply on your devices:")
    print("  Windows:  ipconfig /renew")
    print("  Mac/Linux: Renew DHCP lease or toggle Wi-Fi off/on")
    print("  Or simply reboot client devices")
    print()
    print("NOTE: If you change DHCP settings through the router's")
    print("web interface, the DNS might be reset. Re-run this script.")
    print("=" * 50)


if __name__ == "__main__":
    main()
