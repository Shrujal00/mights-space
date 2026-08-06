"""Impersonation heuristics.

Every case below is drawn from a real sample seen in an Indian fraud campaign,
with the package names kept exactly as they appeared. No sample is included in
the repository — only the strings the analysis reads.
"""

from app.analysis.apk_signals import (
    assess_apk,
    brand_impersonation,
    debug_certificate,
    generated_package_name,
    invisible_characters,
    self_describing_package,
    vendor_namespace_abuse,
)

DEBUG_SUBJECT = (
    "Common Name: Android, Organizational Unit: Android, Organization: Google, "
    "Locality: Mountain View"
)


def codes(signals):
    return {s.code for s in signals}


class TestBrandImpersonation:
    def test_a_bank_name_on_an_unrelated_package_is_flagged(self):
        signal = brand_impersonation("com.trgg.bankofbaroda", "Bank of Baroda")

        assert signal is not None
        assert "Bank of Baroda" in signal.plain_language

    def test_a_government_service_name_on_an_unrelated_package_is_flagged(self):
        assert brand_impersonation("com.fvotnk.android", "RTO eChallan") is not None

    def test_a_bank_app_product_name_is_recognised(self):
        # Fraud apps copy the app's name ("Vyom"), not the bank's, so the
        # product names have to be known too.
        assert brand_impersonation("com.smsreceiver.dhruv2", "Vyom") is not None

    def test_the_genuine_publisher_is_not_flagged(self):
        assert brand_impersonation("com.sbi.lotza", "YONO SBI") is None

    def test_an_app_with_no_trusted_brand_in_its_name_is_not_flagged(self):
        assert brand_impersonation("com.example.notes", "Notes") is None


class TestVendorNamespaceAbuse:
    def test_a_package_in_another_companys_namespace_is_flagged(self):
        signal = vendor_namespace_abuse("com.facebook.smsrecevies", "YONO SBI")

        assert signal is not None
        assert "Facebook" in signal.plain_language

    def test_the_vendors_own_app_is_not_flagged(self):
        assert vendor_namespace_abuse("com.facebook.katana", "Facebook") is None


class TestInvisibleCharacters:
    def test_zero_width_spaces_in_an_app_name_are_flagged(self):
        # Real sample: the label rendered as "IGL Gas" but carried zero-width
        # spaces between every letter to defeat exact-match searching.
        signal = invisible_characters("I​G​L​ Gas")

        assert signal is not None
        assert "Zero Width Space" in signal.detail

    def test_an_ordinary_name_is_not_flagged(self):
        assert invisible_characters("IGL Gas") is None

    def test_a_right_to_left_override_is_flagged(self):
        assert invisible_characters("invoice‮gpj.apk") is not None


class TestCertificate:
    def test_the_android_debug_certificate_is_flagged(self):
        assert debug_certificate([DEBUG_SUBJECT]) is not None

    def test_a_real_publisher_certificate_is_not_flagged(self):
        assert debug_certificate(["Common Name: State Bank of India"]) is None


class TestPackageNameShape:
    def test_an_unpronounceable_segment_is_flagged(self):
        assert generated_package_name("com.fvotnk.android") is not None

    def test_ordinary_english_segments_are_not_flagged(self):
        # "system" has one written vowel but is a perfectly normal segment.
        assert generated_package_name("com.system.vpn.secure") is None
        assert generated_package_name("com.android.chrome") is None

    def test_a_package_naming_what_it_steals_is_flagged(self):
        signal = self_describing_package("com.smsreceiver.dhruv2")

        assert signal is not None
        assert "smsreceiver" in signal.detail

    def test_an_ordinary_package_is_not_flagged(self):
        assert self_describing_package("com.whatsapp") is None


class TestCombined:
    def test_a_real_otp_stealer_raises_several_signals(self):
        signals = assess_apk("com.facebook.smsrecevies", "YONO SBI", [])

        assert {"brand-impersonation", "vendor-namespace-abuse"} <= codes(signals)

    def test_a_real_echallan_dropper_raises_several_signals(self):
        signals = assess_apk("com.fvotnk.android", "RTO eChallan", [DEBUG_SUBJECT])

        assert {
            "brand-impersonation",
            "debug-certificate",
            "generated-package-name",
        } <= codes(signals)

    def test_an_ordinary_app_raises_nothing(self):
        # False positives here accuse an innocent developer, so this matters as
        # much as the detections above.
        assert assess_apk("com.system.vpn.secure", "System VPN & Security", []) == []

    def test_missing_metadata_does_not_raise_an_error(self):
        assert assess_apk("", "", None) == []
