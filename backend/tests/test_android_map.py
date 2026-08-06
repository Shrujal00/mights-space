from app.analysis.android_map import (
    dangerous,
    high_abuse,
    map_android_to_techniques,
)

P = "android.permission."


def ids_of(techniques):
    return {t.technique_id for t in techniques}


def one(techniques, technique_id):
    return next(t for t in techniques if t.technique_id == technique_id)


class TestPermissionMapping:
    def test_sms_permissions_map_to_message_theft(self):
        # The capability the whole loan-app fraud depends on.
        assert "T1636.004" in ids_of(map_android_to_techniques([P + "READ_SMS"]))

    def test_send_sms_maps_to_sms_control(self):
        assert "T1582" in ids_of(map_android_to_techniques([P + "SEND_SMS"]))

    def test_contacts_permission_maps_to_contact_theft(self):
        assert "T1636.003" in ids_of(map_android_to_techniques([P + "READ_CONTACTS"]))

    def test_location_permission_maps_to_location_tracking(self):
        assert "T1430" in ids_of(
            map_android_to_techniques([P + "ACCESS_FINE_LOCATION"])
        )

    def test_accessibility_binding_maps_to_input_injection(self):
        assert "T1516" in ids_of(
            map_android_to_techniques([P + "BIND_ACCESSIBILITY_SERVICE"])
        )

    def test_notification_access_is_recognised_as_a_route_to_passcodes(self):
        assert "T1517" in ids_of(
            map_android_to_techniques([P + "BIND_NOTIFICATION_LISTENER_SERVICE"])
        )

    def test_an_app_requesting_nothing_reports_nothing(self):
        assert map_android_to_techniques([]) == []


class TestCodeReferences:
    def test_a_code_reference_alone_can_raise_a_technique(self):
        # Screen capture has no permission gate; only the code shows it.
        assert "T1513" in ids_of(
            map_android_to_techniques([], ["Landroid/media/projection/MediaProjection;"])
        )

    def test_evidence_distinguishes_a_permission_from_a_code_reference(self):
        # An investigator has to be able to tell a permission the app merely
        # declared from one its code actually reaches for.
        techniques = map_android_to_techniques([P + "SEND_SMS"], ["sendTextMessage"])

        evidence = one(techniques, "T1582").evidence
        assert "SEND_SMS" in evidence
        assert any(item.startswith("code reference:") for item in evidence)

    def test_evidence_is_not_duplicated(self):
        techniques = map_android_to_techniques(
            [P + "READ_SMS", P + "RECEIVE_SMS"], ["content://sms", "content://sms"]
        )

        evidence = one(techniques, "T1636.004").evidence
        assert len(evidence) == len(set(evidence))


class TestHonesty:
    def test_every_android_technique_is_marked_as_manifest_derived(self):
        # A permission is a request, not an action. Nothing here was observed,
        # and the report must not imply the app was run.
        techniques = map_android_to_techniques([P + "READ_SMS"], [])

        assert all(t.basis == "static-manifest" for t in techniques)

    def test_descriptions_are_written_for_a_non_expert(self):
        technique = one(map_android_to_techniques([P + "READ_SMS"]), "T1636.004")

        assert "one-time" in technique.plain_language.lower()
        assert "T1636" not in technique.plain_language


class TestPermissionClassification:
    def test_personal_data_permissions_are_classed_as_dangerous(self):
        assert dangerous([P + "READ_SMS", P + "INTERNET"]) == [P + "READ_SMS"]

    def test_fraud_enabling_permissions_are_classed_separately(self):
        # Android does not call these "dangerous", but they are the defining
        # tell of the fraud families this tool exists for.
        assert high_abuse([P + "BIND_ACCESSIBILITY_SERVICE"]) == [
            P + "BIND_ACCESSIBILITY_SERVICE"
        ]

    def test_ordinary_permissions_are_in_neither_list(self):
        assert dangerous([P + "VIBRATE"]) == []
        assert high_abuse([P + "VIBRATE"]) == []
