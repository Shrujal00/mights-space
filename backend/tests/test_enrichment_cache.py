from app.analysis.reputation.base import ProviderResult
from app.analysis.reputation.cache import EnrichmentCache


class FakeClock:
    def __init__(self):
        self.time = 1000.0

    def now(self) -> float:
        return self.time

    def advance(self, seconds: float) -> None:
        self.time += seconds


def ok_result(detail="hit"):
    return ProviderResult(provider="virustotal", status="ok", detail=detail)


def test_fetches_on_a_miss():
    cache = EnrichmentCache()

    result = cache.get_or_fetch("virustotal", "abc123", lambda: ok_result())

    assert result.status == "ok"


def test_a_second_lookup_does_not_call_the_provider_again():
    # Rate limits are the binding constraint, so repeats must be free.
    cache = EnrichmentCache()
    calls = []

    def fetch():
        calls.append(1)
        return ok_result()

    cache.get_or_fetch("virustotal", "abc123", fetch)
    cache.get_or_fetch("virustotal", "abc123", fetch)

    assert len(calls) == 1


def test_different_indicators_are_cached_separately():
    cache = EnrichmentCache()
    calls = []

    def fetch():
        calls.append(1)
        return ok_result()

    cache.get_or_fetch("virustotal", "abc123", fetch)
    cache.get_or_fetch("virustotal", "def456", fetch)

    assert len(calls) == 2


def test_the_same_indicator_is_cached_separately_per_provider():
    cache = EnrichmentCache()
    calls = []

    def fetch():
        calls.append(1)
        return ok_result()

    cache.get_or_fetch("virustotal", "abc123", fetch)
    cache.get_or_fetch("malwarebazaar", "abc123", fetch)

    assert len(calls) == 2


def test_refetches_once_the_entry_has_expired():
    clock = FakeClock()
    cache = EnrichmentCache(ttl_seconds=3600, now=clock.now)
    calls = []

    def fetch():
        calls.append(1)
        return ok_result()

    cache.get_or_fetch("virustotal", "abc123", fetch)
    clock.advance(3601)
    cache.get_or_fetch("virustotal", "abc123", fetch)

    assert len(calls) == 2


def test_failed_lookups_are_not_cached():
    # A timeout or a 500 is transient. Caching it would suppress the real answer
    # for the whole TTL, which is how a report ends up wrongly saying "unknown".
    cache = EnrichmentCache()
    results = [
        ProviderResult(provider="virustotal", status="unavailable", detail="timeout"),
        ok_result(),
    ]
    cache.get_or_fetch("virustotal", "abc123", lambda: results[0])

    second = cache.get_or_fetch("virustotal", "abc123", lambda: results[1])

    assert second.status == "ok"


def test_not_found_results_are_cached():
    # "This hash is unknown to VirusTotal" is a real answer, not a failure.
    cache = EnrichmentCache()
    calls = []

    def fetch():
        calls.append(1)
        return ProviderResult(provider="virustotal", status="not_found")

    cache.get_or_fetch("virustotal", "abc123", fetch)
    cache.get_or_fetch("virustotal", "abc123", fetch)

    assert len(calls) == 1
