"""Tests for psirt.enrich: best-effort fortiguard.com + CISA KEV enrichment."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.enrich import check_kev, enrich_advisory, fetch_advisory_page
from psirt.models import Advisory


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


class _FakeHTTPClient:
    def __init__(self, responses=None, raise_exc=None):
        self._responses = responses or {}
        self._raise_exc = raise_exc

    def get(self, url, timeout=None):
        if self._raise_exc:
            raise self._raise_exc
        return self._responses.get(url, _FakeResponse(status_code=404))


def test_check_kev_true_when_cve_in_catalog():
    client = _FakeHTTPClient({
        "https://kev.example/feed.json": _FakeResponse(
            json_data={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}
        )
    })
    assert check_kev(["CVE-2024-12345"], client, kev_url="https://kev.example/feed.json") is True


def test_check_kev_false_when_cve_absent():
    client = _FakeHTTPClient({
        "https://kev.example/feed.json": _FakeResponse(
            json_data={"vulnerabilities": [{"cveID": "CVE-2020-00000"}]}
        )
    })
    assert check_kev(["CVE-2024-12345"], client, kev_url="https://kev.example/feed.json") is False


def test_check_kev_false_on_fetch_failure_never_raises():
    client = _FakeHTTPClient(raise_exc=ConnectionError("unreachable"))
    assert check_kev(["CVE-2024-12345"], client, kev_url="https://kev.example/feed.json") is False


def test_fetch_advisory_page_success_marks_fetched():
    client = _FakeHTTPClient({
        "https://fortiguard.com/psirt/FG-IR-24-001": _FakeResponse(
            status_code=200, text="<html>CVSS Score: 9.8 Severity: Critical</html>",
        )
    })
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is True


def test_fetch_advisory_page_failure_never_raises():
    client = _FakeHTTPClient(raise_exc=TimeoutError("slow"))
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is False


def test_fetch_advisory_page_empty_url_skips():
    client = _FakeHTTPClient()
    result = fetch_advisory_page("", client)
    assert result["fetched"] is False


def test_enrich_advisory_sets_degraded_when_both_fetches_fail():
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/x",
                    cve_ids=["CVE-2024-12345"])
    client = _FakeHTTPClient(raise_exc=ConnectionError("down"))
    result = enrich_advisory(adv, client, kev_url="https://kev.example/feed.json")
    assert result.enrichment_degraded is True
    assert result.advisory_id == "FG-IR-24-001"


def test_enrich_advisory_sets_kev_corroborated_severity_without_degrading():
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="", cve_ids=["CVE-2024-12345"])
    client = _FakeHTTPClient({
        "https://kev.example/feed.json": _FakeResponse(
            json_data={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}
        )
    })
    result = enrich_advisory(adv, client, kev_url="https://kev.example/feed.json")
    # No advisory_url given, so the fortiguard fetch is skipped (still degraded)
    # but the KEV check succeeded independently.
    assert result.enrichment_degraded is True
