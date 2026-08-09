import ipaddress
from standards_mcp import policy_engine


def test_service_aliases_for_port():
    aliases = policy_engine._service_aliases('22')
    assert '22' in aliases
    assert 'ssh' in aliases


def test_parse_endpoint_ip():
    e = policy_engine.parse_endpoint('10.0.0.1')
    assert isinstance(e, ipaddress.IPv4Address)


def test_parse_endpoint_cidr():
    n = policy_engine.parse_endpoint('10.0.0.0/24')
    assert n.prefixlen == 24


def test_zones_for_endpoint_public_no_match():
    # Public IP not found in zones -> Internet
    zones = {'A': {'subnets': [{'subnet': '192.0.2.0/24'}]}}
    res = policy_engine.zones_for_endpoint('8.8.8.8', zones)
    assert res == ['Internet']


def test_evaluate_block_all():
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'block all','services':[]}] 
    verdict, gov = policy_engine.evaluate(policies, [])
    assert verdict == 'BLOCKED'


def test_evaluate_block_only_service_match():
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'block only','services':['ssh']}]
    verdict, gov = policy_engine.evaluate(policies, ['22'])
    assert verdict == 'BLOCKED'


def test_evaluate_allow_when_no_block():
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'allow all','services':[]}]
    verdict, gov = policy_engine.evaluate(policies, ['22'])
    assert verdict == 'ALLOWED'


def test_evaluate_allow_only_service_match():
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'allow only','services':['ssh','https']}]
    verdict, gov = policy_engine.evaluate(policies, ['tcp/443'])
    assert verdict == 'ALLOWED'
    assert gov == [policies[0]]


def test_evaluate_allow_only_service_not_listed_is_blocked():
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'allow only','services':['ssh','https']}]
    verdict, gov = policy_engine.evaluate(policies, ['tcp/3389'])
    assert verdict == 'BLOCKED'
    assert gov == [policies[0]]


def test_evaluate_allow_only_without_service_query_is_allowed():
    # No service specified — the zone pair is at least partially open
    policies = [{'policy_set':'ps','from_zone':'A','to_zone':'B','access_type':'allow only','services':['ssh']}]
    verdict, gov = policy_engine.evaluate(policies, [])
    assert verdict == 'ALLOWED'
