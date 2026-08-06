from app.analysis.strings_extract import extract_strings


def test_extracts_printable_ascii_runs():
    data = b"\x00\x01hello world\xff\xfe"

    assert "hello world" in extract_strings(data)


def test_ignores_runs_shorter_than_minimum_length():
    data = b"\x00abc\x00"

    assert "abc" not in extract_strings(data, min_length=4)


def test_recovers_utf16le_strings():
    # Windows binaries store most strings as UTF-16LE. An ASCII-only scan sees
    # single characters separated by NULs and finds nothing, so missing this
    # encoding silently loses most IOCs in a PE sample.
    data = b"\x00\x00" + "http://evil.example.com".encode("utf-16-le") + b"\x00\x00"

    assert "http://evil.example.com" in extract_strings(data)


def test_deduplicates_repeated_strings():
    data = b"repeated string\x00repeated string\x00"

    assert extract_strings(data).count("repeated string") == 1


from app.analysis.strings_extract import select_notable


class TestNotableStrings:
    def test_selects_a_command_and_control_url(self):
        selected = select_notable(["http://panel.evil.tk/gate.php", "hello there"])

        assert [s["value"] for s in selected] == ["http://panel.evil.tk/gate.php"]

    def test_labels_why_a_string_was_selected(self):
        # An investigator needs to know why a string is in the report, not just
        # that it is.
        (selected,) = select_notable(["https://api.telegram.org/bot123/sendMessage"])

        assert selected["category"] == "Command and control"
        assert selected["why"]

    def test_recognises_a_messaging_channel_used_for_exfiltration(self):
        (selected,) = select_notable(["t.me/joinchat/AAAA"])

        assert selected["category"] == "Messaging channel"

    def test_recognises_references_to_one_time_codes(self):
        (selected,) = select_notable(["otp_received_forward"])

        assert selected["category"] == "One-time codes"

    def test_ignores_ordinary_strings(self):
        assert select_notable(["Hello world", "OK", "androidx.core.app"]) == []

    def test_caps_the_number_returned(self):
        # A modern APK carries tens of thousands of strings; a raw dump is
        # unreadable and would bloat the database.
        many = [f"http://host{i}.example/gate.php" for i in range(1000)]

        assert len(select_notable(many, limit=50)) == 50

    def test_deduplicates(self):
        assert len(select_notable(["http://a.tk/gate.php"] * 5)) == 1
