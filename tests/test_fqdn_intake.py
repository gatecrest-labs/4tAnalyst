import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intake_mcp.fqdn_parser import parse_fqdn_rows


def _rows():
    return [
        {"Hostname / Domain": "*.push.apple.com", "Port(s)": "80, 443, 5223",
         "Protocol": "TCP", "Direction": "Outbound", "Vendor": "Apple",
         "Category": "APNs", "Required?": "Required",
         "Purpose / Notes": "APNs push channel"},
        {"Hostname / Domain": "axm-adm-scep.apple.com", "Port(s)": "443",
         "Protocol": "TCP", "Direction": "Outbound", "Vendor": "Apple",
         "Category": "APNs", "Required?": "Yes", "Purpose / Notes": "SCEP"},
    ]


def test_parse_basic():
    req = parse_fqdn_rows(_rows(), src_ip="10.1.2.3", ticket_id="CHG001",
                          firewalls=["FW1:OT-ADOM"])
    assert req.vendor == "Apple"
    assert req.category == "APNs"
    assert req.src_ip == "10.1.2.3"
    assert req.ticket_id == "CHG001"
    assert req.firewalls == ["FW1:OT-ADOM"]
    assert len(req.entries) == 2
    assert req.warnings == []
    assert req.missing_fields == []


def test_wildcard_detection():
    req = parse_fqdn_rows(_rows(), src_ip="10.1.2.3", ticket_id="CHG001",
                          firewalls=[])
    wildcard = req.entries[0]
    exact = req.entries[1]
    assert wildcard.fqdn == "*.push.apple.com"
    assert wildcard.is_wildcard is True
    assert exact.fqdn == "axm-adm-scep.apple.com"
    assert exact.is_wildcard is False


def test_multi_port_parsing():
    req = parse_fqdn_rows(_rows(), src_ip="10.1.2.3", ticket_id="CHG001",
                          firewalls=[])
    assert req.entries[0].ports == [80, 443, 5223]
    assert req.entries[1].ports == [443]


def test_direction_warning_on_inbound():
    rows = [
        {"Hostname / Domain": "example.com", "Port(s)": "443",
         "Protocol": "TCP", "Direction": "Inbound", "Vendor": "Acme",
         "Category": "Test", "Required?": "Yes", "Purpose / Notes": ""},
    ]
    req = parse_fqdn_rows(rows, src_ip="10.0.0.1", ticket_id="CHG002",
                          firewalls=[])
    assert any("Inbound" in w for w in req.warnings)


def test_missing_src_ip():
    req = parse_fqdn_rows(_rows(), src_ip="", ticket_id="CHG001",
                          firewalls=[])
    assert "src_ip" in req.missing_fields


def test_empty_fqdn_skipped():
    rows = [
        {"Hostname / Domain": "", "Port(s)": "443", "Protocol": "TCP",
         "Direction": "Outbound", "Vendor": "Acme", "Category": "Test",
         "Required?": "Yes", "Purpose / Notes": ""},
        {"Hostname / Domain": "valid.example.com", "Port(s)": "80",
         "Protocol": "TCP", "Direction": "Outbound", "Vendor": "Acme",
         "Category": "Test", "Required?": "Yes", "Purpose / Notes": ""},
    ]
    req = parse_fqdn_rows(rows, src_ip="10.0.0.1", ticket_id="CHG003",
                          firewalls=[])
    assert len(req.entries) == 1
    assert any("skipped" in w.lower() or "empty" in w.lower() for w in req.warnings)


def test_required_field_parsing():
    req = parse_fqdn_rows(_rows(), src_ip="10.1.2.3", ticket_id="CHG001",
                          firewalls=[])
    assert req.entries[0].required is True
    assert req.entries[1].required is True


def test_comment_from_purpose():
    req = parse_fqdn_rows(_rows(), src_ip="10.1.2.3", ticket_id="CHG001",
                          firewalls=[])
    assert "APNs push channel" in req.entries[0].comment
