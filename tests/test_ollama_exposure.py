"""
Tests for checks/check_ollama_exposure.py - binding classification and
OLLAMA_HOST parsing. No real netstat or registry access.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "check_ollama_exposure", ROOT / "checks" / "check_ollama_exposure.py")
oe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oe)

CONFIG = {"checks": {"ollama_exposure": {"enabled": True, "severity": "HIGH"}}}

HEADER = ("\nActive Connections\n\n  Proto  Local Address          "
          "Foreign Address        State           PID\n")


def netstat(*lines):
    return HEADER + "\n".join(lines) + "\n"


def run_with(monkeypatch, netstat_text, host_values=None):
    monkeypatch.setattr(oe, "run_netstat", lambda: netstat_text)
    monkeypatch.setattr(oe, "read_ollama_host_values", lambda: dict(host_values or {}))
    return oe.run(CONFIG)


# --- Listener bindings -------------------------------------------------------

class TestBindings:
    def test_ipv4_loopback_passes(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       20860"))
        assert r.status == "PASS"
        assert "loopback" in r.message

    def test_ipv6_loopback_passes(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    [::1]:11434            [::]:0                 LISTENING       20860"))
        assert r.status == "PASS"

    def test_ipv4_wildcard_fails(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    0.0.0.0:11434          0.0.0.0:0              LISTENING       20860"))
        assert r.status == "FAIL"
        assert "IPv4 wildcard" in r.message

    def test_ipv6_wildcard_fails(self, monkeypatch):
        """v1 missed this: [::] exposes the API on every IPv6 interface."""
        r = run_with(monkeypatch, netstat(
            "  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       20860",
            "  TCP    [::]:11434             [::]:0                 LISTENING       20860"))
        assert r.status == "FAIL"
        assert "IPv6 wildcard" in r.message

    def test_lan_ip_fails(self, monkeypatch):
        """v1 missed this: binding to a LAN IP is reachable from the network."""
        r = run_with(monkeypatch, netstat(
            "  TCP    192.168.1.50:11434     0.0.0.0:0              LISTENING       20860"))
        assert r.status == "FAIL"
        assert "non-loopback" in r.message

    def test_not_listening_passes(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       100"))
        assert r.status == "PASS"
        assert "not listening" in r.message

    def test_established_connection_ignored(self, monkeypatch):
        """A client connection to 11434 is not a listener."""
        r = run_with(monkeypatch, netstat(
            "  TCP    192.168.1.50:50123     192.168.1.9:11434      ESTABLISHED     100"))
        assert r.status == "PASS"

    def test_other_port_with_11434_suffix_ignored(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    0.0.0.0:111434         0.0.0.0:0              LISTENING       100"))
        assert r.status == "PASS"

    def test_non_english_state_detected_by_foreign_address(self, monkeypatch):
        r = run_with(monkeypatch, netstat(
            "  TCP    0.0.0.0:11434          0.0.0.0:0              ABHÖREN         20860"))
        assert r.status == "FAIL"

    def test_custom_port_from_ollama_host_is_checked(self, monkeypatch):
        r = run_with(monkeypatch,
                     netstat("  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       1"),
                     {"user": "127.0.0.1:8080"})
        assert r.status == "FAIL"

    def test_netstat_failure_returns_error(self, monkeypatch):
        def boom():
            raise OSError("netstat missing")
        monkeypatch.setattr(oe, "run_netstat", boom)
        monkeypatch.setattr(oe, "read_ollama_host_values", lambda: {})
        r = oe.run(CONFIG)
        assert r.status == "ERROR"


# --- OLLAMA_HOST environment -------------------------------------------------

class TestOllamaHostEnv:
    LOOPBACK = "  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       20860"

    @pytest.mark.parametrize("scope", ["process", "user", "machine"])
    def test_wildcard_env_fails_in_any_scope(self, monkeypatch, scope):
        """Pending exposure: env set, listener still loopback until restart."""
        r = run_with(monkeypatch, netstat(self.LOOPBACK), {scope: "0.0.0.0"})
        assert r.status == "FAIL"
        assert scope in r.message

    def test_loopback_env_passes(self, monkeypatch):
        r = run_with(monkeypatch, netstat(self.LOOPBACK), {"user": "127.0.0.1"})
        assert r.status == "PASS"

    def test_remediation_present_on_fail(self, monkeypatch):
        r = run_with(monkeypatch, netstat(self.LOOPBACK), {"user": "0.0.0.0"})
        assert "OLLAMA_HOST" in r.remediation


# --- Pure helpers ------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("", ("127.0.0.1", 11434)),
    ("0.0.0.0", ("0.0.0.0", 11434)),
    ("0.0.0.0:8080", ("0.0.0.0", 8080)),
    ("http://127.0.0.1:11434", ("127.0.0.1", 11434)),
    ("https://localhost:11434/", ("localhost", 11434)),
    (":11434", ("", 11434)),
    ("[::]:11434", ("::", 11434)),
    ("::", ("::", 11434)),
    ("::1", ("::1", 11434)),
])
def test_parse_ollama_host(value, expected):
    assert oe.parse_ollama_host(value) == expected


@pytest.mark.parametrize("host,exposed", [
    ("127.0.0.1", False), ("127.0.0.2", False), ("::1", False),
    ("localhost", False), ("0.0.0.0", True), ("::", True),
    ("192.168.1.50", True), ("", True), ("my-pc.local", True),
])
def test_host_is_exposed(host, exposed):
    assert oe.host_is_exposed(host) is exposed
