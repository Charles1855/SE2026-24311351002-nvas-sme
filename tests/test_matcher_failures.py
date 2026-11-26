"""A failed NVD lookup must be counted, so 'no answer' is never mistaken for 'no CVEs'."""
import requests

from analysis import vuln_matcher


def no_sleep(monkeypatch):
    monkeypatch.setattr(vuln_matcher.time, "sleep", lambda s: None)
    monkeypatch.setattr(vuln_matcher, "_throttle", lambda: None)


def test_failed_request_is_counted(monkeypatch):
    no_sleep(monkeypatch)
    monkeypatch.setattr(vuln_matcher, "lookup_failures", 0)
    monkeypatch.setattr(vuln_matcher, "_warn", lambda text: None)

    def boom(*args, **kwargs):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(vuln_matcher.requests, "get", boom)
    assert vuln_matcher._request({"keywordSearch": "x"}) is None
    assert vuln_matcher.lookup_failures == 1


def test_unknown_cpe_404_is_not_a_failure(monkeypatch):
    no_sleep(monkeypatch)
    monkeypatch.setattr(vuln_matcher, "lookup_failures", 0)

    class Resp:
        status_code = 404

    monkeypatch.setattr(vuln_matcher.requests, "get", lambda *a, **k: Resp())
    assert vuln_matcher._request({"cpeName": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}) is None
    assert vuln_matcher.lookup_failures == 0


def test_counter_resets_at_the_start_of_each_scan(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "lookup_failures", 7)
    vuln_matcher.match_scan_results([])
    assert vuln_matcher.lookup_failures == 0
