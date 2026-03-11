"""Tests for skyhigh_scanner.core.ip_utils."""

from unittest.mock import patch

from skyhigh_scanner.core.ip_utils import expand_ip_range, is_private, reverse_dns

# ── expand_ip_range ───────────────────────────────────────────────────

class TestExpandIpRange:
    def test_single_ip(self):
        result = expand_ip_range("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_small(self):
        result = expand_ip_range("10.0.0.0/30")
        # /30 has 2 usable hosts: .1 and .2
        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_cidr_24(self):
        result = expand_ip_range("192.168.1.0/24")
        assert len(result) == 254  # .1 through .254
        assert result[0] == "192.168.1.1"
        assert result[-1] == "192.168.1.254"

    def test_range_full_form(self):
        result = expand_ip_range("10.0.0.1-10.0.0.5")
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]

    def test_range_short_form(self):
        result = expand_ip_range("192.168.1.10-15")
        assert len(result) == 6
        assert result[0] == "192.168.1.10"
        assert result[-1] == "192.168.1.15"

    def test_comma_separated(self):
        result = expand_ip_range("10.0.0.1,10.0.0.5,10.0.0.3")
        assert result == ["10.0.0.1", "10.0.0.3", "10.0.0.5"]

    def test_mixed_input(self):
        result = expand_ip_range("10.0.0.1,192.168.1.0/30")
        assert "10.0.0.1" in result
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_dedup(self):
        result = expand_ip_range("10.0.0.1,10.0.0.1,10.0.0.1")
        assert result == ["10.0.0.1"]

    def test_sorted_output(self):
        result = expand_ip_range("10.0.0.5,10.0.0.1,10.0.0.3")
        assert result == ["10.0.0.1", "10.0.0.3", "10.0.0.5"]

    def test_empty_string(self):
        result = expand_ip_range("")
        assert result == []

    def test_invalid_cidr(self):
        result = expand_ip_range("999.999.999.999/24")
        assert result == []

    def test_reversed_range(self):
        # Should auto-swap start/end
        result = expand_ip_range("10.0.0.5-10.0.0.1")
        assert len(result) == 5

    @patch("skyhigh_scanner.core.ip_utils.socket.gethostbyname")
    def test_hostname_resolution(self, mock_dns):
        mock_dns.return_value = "93.184.216.34"
        result = expand_ip_range("example.com")
        assert result == ["93.184.216.34"]
        mock_dns.assert_called_once_with("example.com")

    @patch("skyhigh_scanner.core.ip_utils.socket.gethostbyname")
    def test_hostname_unresolvable(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("DNS lookup failed")
        result = expand_ip_range("nonexistent.invalid")
        assert result == []


# ── is_private ────────────────────────────────────────────────────────

class TestIsPrivate:
    def test_private_rfc1918(self):
        assert is_private("192.168.1.1") is True
        assert is_private("10.0.0.1") is True
        assert is_private("172.16.0.1") is True

    def test_public(self):
        assert is_private("8.8.8.8") is False
        assert is_private("93.184.216.34") is False

    def test_loopback(self):
        assert is_private("127.0.0.1") is True

    def test_invalid(self):
        assert is_private("not-an-ip") is False


# ── reverse_dns ───────────────────────────────────────────────────────

class TestReverseDns:
    @patch("skyhigh_scanner.core.ip_utils.socket.gethostbyaddr")
    def test_success(self, mock_rdns):
        mock_rdns.return_value = ("server.example.com", [], ["10.0.0.1"])
        assert reverse_dns("10.0.0.1") == "server.example.com"

    @patch("skyhigh_scanner.core.ip_utils.socket.gethostbyaddr")
    def test_failure(self, mock_rdns):
        import socket
        mock_rdns.side_effect = socket.herror("No PTR record")
        assert reverse_dns("10.0.0.1") == ""
