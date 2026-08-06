from app.analysis.ioc_extract import Indicator, extract_iocs


def values_of(indicators, kind):
    return [i.value for i in indicators if i.type == kind]


def test_extracts_http_urls():
    result = extract_iocs(["beacon to http://evil.example.com/gate.php every 60s"])

    assert Indicator("url", "http://evil.example.com/gate.php") in result


def test_records_the_host_of_an_extracted_url_as_a_domain():
    result = extract_iocs(["http://evil.example.com/gate.php"])

    assert "evil.example.com" in values_of(result, "domain")


def test_extracts_public_ipv4_addresses():
    result = extract_iocs(["connect 185.244.25.14 port 443"])

    assert values_of(result, "ipv4") == ["185.244.25.14"]


def test_drops_private_loopback_and_link_local_addresses():
    # These are never exfiltration destinations and would swamp the report.
    result = extract_iocs(["127.0.0.1", "192.168.1.10", "10.0.0.5", "169.254.1.1"])

    assert values_of(result, "ipv4") == []


def test_drops_dotted_quads_that_are_really_version_strings():
    result = extract_iocs(["FileVersion 6.1.7601.24545", "ProductVersion 1.0.0.0"])

    assert values_of(result, "ipv4") == []


def test_drops_library_and_config_filenames_that_look_like_domains():
    # A naive domain regex reads every imported DLL as a hostname. This single
    # filter removes the largest source of false positives in a PE report.
    result = extract_iocs(["kernel32.dll", "advapi32.dll", "config.ini", "libc.so"])

    assert values_of(result, "domain") == []


def test_drops_benign_vendor_infrastructure():
    result = extract_iocs(
        [
            "http://schemas.microsoft.com/office/2006",
            "www.w3.org/2000/svg",
            "crl.verisign.com/pca3.crl",
        ]
    )

    assert result == []


def test_keeps_suspicious_domains_including_cheap_tlds():
    result = extract_iocs(["stealer-panel.top", "drop.evil.tk"])

    assert sorted(values_of(result, "domain")) == ["drop.evil.tk", "stealer-panel.top"]


def test_excludes_values_the_caller_knows_are_not_indicators():
    # A PE version resource stores "1.1.0.14" as a bare string, indistinguishable
    # from an address by pattern alone. The PE parser supplies the exclusions.
    assert extract_iocs(["1.1.0.14"], exclude={"1.1.0.14"}) == []


def test_exclusions_do_not_remove_unrelated_indicators():
    result = extract_iocs(["1.1.0.14", "185.244.25.14"], exclude={"1.1.0.14"})

    assert values_of(result, "ipv4") == ["185.244.25.14"]


def test_deduplicates_repeated_indicators():
    result = extract_iocs(["185.244.25.14", "185.244.25.14 again"])

    assert values_of(result, "ipv4") == ["185.244.25.14"]
