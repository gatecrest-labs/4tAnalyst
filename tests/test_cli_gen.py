"""
Exact-string tests for planner/cli_gen.py — FortiGate CLI generation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from planner.cli_gen import (
    address_object_cli,
    exception_comment,
    policy_cli,
    service_object_cli,
)


def test_address_object_host():
    cli = address_object_cli("H_10.1.2.3", "10.1.2.3/32")
    assert cli == (
        'config firewall address\n'
        '    edit "H_10.1.2.3"\n'
        '        set type ipmask\n'
        '        set subnet 10.1.2.3 255.255.255.255\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )


def test_address_object_network_mask_conversion():
    cli = address_object_cli("N_10.8.0.0_16", "10.8.0.0/16")
    assert "set subnet 10.8.0.0 255.255.0.0" in cli


def test_service_object():
    cli = service_object_cli("SVC_TCP_8443", "tcp", "8443")
    assert cli == (
        'config firewall service custom\n'
        '    edit "SVC_TCP_8443"\n'
        '        set tcp-portrange 8443\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )


def test_service_object_udp():
    assert "set udp-portrange 514" in service_object_cli("SVC_UDP_514", "udp", "514")


def test_policy_cli_full():
    cli = policy_cli(
        name="CHG1_OT_TO_IT_001",
        srcintf="port1", dstintf="port2",
        srcaddr=["H_10.1.2.3"], dstaddr=["H_10.9.8.7"],
        service=["SVC_TCP_8443"],
        logtraffic="all", logtraffic_start=True,
        comments="Ticket <TICKET_ID>",
        insert_before=42,
    )
    assert 'edit 0' in cli
    assert 'set name "CHG1_OT_TO_IT_001"' in cli
    assert 'set srcintf "port1"' in cli
    assert 'set dstintf "port2"' in cli
    assert 'set srcaddr "H_10.1.2.3"' in cli
    assert 'set dstaddr "H_10.9.8.7"' in cli
    assert 'set service "SVC_TCP_8443"' in cli
    assert 'set action accept' in cli
    assert 'set schedule "always"' in cli
    assert 'set logtraffic all' in cli
    assert 'set logtraffic-start enable' in cli
    assert 'set comments "Ticket <TICKET_ID>"' in cli
    # placement guidance appears as trailing comment
    assert "before policy ID 42" in cli
    assert "move" in cli


def test_policy_cli_no_log_start_no_insert():
    cli = policy_cli(
        name="P", srcintf="a", dstintf="b",
        srcaddr=["x"], dstaddr=["y"], service=["s"],
        logtraffic="utm", logtraffic_start=False,
        comments="", insert_before=None,
    )
    assert "logtraffic-start" not in cli
    assert "move" not in cli
    assert "set comments" not in cli


def test_policy_cli_multiple_addrs():
    cli = policy_cli(
        name="P", srcintf="a", dstintf="b",
        srcaddr=["x1", "x2"], dstaddr=["y"], service=["s"],
        logtraffic="all", logtraffic_start=False,
        comments="", insert_before=None,
    )
    assert 'set srcaddr "x1" "x2"' in cli


def test_exception_comment():
    text = exception_comment("CHG0099")
    assert "CHG0099" in text
    assert "exception" in text.lower()
    assert "<SecOps approver>" in text


def test_addrgrp_append_cli_exact():
    from planner.cli_gen import addrgrp_append_cli
    assert addrgrp_append_cli("WAN-to-Internet-Wifi", "H_10.1.1.7") == (
        'config firewall addrgrp\n'
        '    edit "WAN-to-Internet-Wifi"\n'
        '        append member "H_10.1.1.7"\n'
        '    next\n'
        'end'
    )


def test_addrgrp_append_cli_multiple_members():
    from planner.cli_gen import addrgrp_append_cli
    assert addrgrp_append_cli("GRP_X", ["H_A", "H_B"]) == (
        'config firewall addrgrp\n'
        '    edit "GRP_X"\n'
        '        append member "H_A"\n'
        '        append member "H_B"\n'
        '    next\n'
        'end'
    )


def test_addrgrp_create_cli_exact():
    from planner.cli_gen import addrgrp_create_cli
    assert addrgrp_create_cli("GRP_CHG1_SRC", ["H_10.0.0.1", "H_10.0.0.2"]) == (
        'config firewall addrgrp\n'
        '    edit "GRP_CHG1_SRC"\n'
        '        set member "H_10.0.0.1" "H_10.0.0.2"\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )
