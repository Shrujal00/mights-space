from app.analysis.attack_map import map_imports_to_techniques


def ids_of(techniques):
    return {t.technique_id for t in techniques}


def test_maps_keyboard_hooking_to_input_capture():
    assert "T1056.001" in ids_of(map_imports_to_techniques(["SetWindowsHookExA"]))


def test_maps_remote_thread_creation_to_process_injection():
    techniques = map_imports_to_techniques(["CreateRemoteThread", "WriteProcessMemory"])

    assert "T1055" in ids_of(techniques)


def test_maps_screen_blitting_to_screen_capture():
    assert "T1113" in ids_of(map_imports_to_techniques(["BitBlt"]))


def test_maps_internet_apis_to_application_layer_protocol():
    assert "T1071" in ids_of(map_imports_to_techniques(["InternetOpenUrlA"]))


def test_maps_run_key_writes_to_registry_persistence():
    assert "T1547.001" in ids_of(map_imports_to_techniques(["RegSetValueExA"]))


def test_reports_nothing_for_ordinary_imports():
    assert map_imports_to_techniques(["ExitProcess", "GetCommandLineW"]) == []


def test_collapses_several_imports_into_one_technique():
    techniques = map_imports_to_techniques(
        ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"]
    )

    assert [t.technique_id for t in techniques] == ["T1055"]


def test_records_which_imports_triggered_the_technique():
    (technique,) = map_imports_to_techniques(["CreateRemoteThread", "VirtualAllocEx"])

    assert sorted(technique.evidence) == ["CreateRemoteThread", "VirtualAllocEx"]


def test_marks_every_mapping_as_import_derived_rather_than_observed():
    # Static imports show capability, not behaviour. The report must not imply
    # the sample was seen doing this, because nothing was executed.
    (technique,) = map_imports_to_techniques(["BitBlt"])

    assert technique.basis == "static-import"


def test_carries_a_plain_language_description_for_non_experts():
    (technique,) = map_imports_to_techniques(["SetWindowsHookExA"])

    assert "keyboard" in technique.plain_language.lower()


def test_matching_ignores_the_ansi_and_wide_suffix():
    # Windows exports most APIs as both ...A and ...W variants.
    assert ids_of(map_imports_to_techniques(["SetWindowsHookExW"])) == {"T1056.001"}
