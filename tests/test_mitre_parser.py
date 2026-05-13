from backend.app.mitre_parser import diff_techniques, load_mitre_asset_catalog, parse_stix_bundle


SAMPLE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--1",
            "name": "Initial Access",
            "x_mitre_shortname": "initial-access",
            "description": "Gain access",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Spearphishing Attachment",
            "description": "Users open a malicious attachment.",
            "modified": "2025-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0865"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-ics-attack", "phase_name": "initial-access"}],
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--1",
            "name": "User Training",
            "description": "Train users.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1017"}],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--1",
            "target_ref": "attack-pattern--1",
        },
    ],
}


def test_parse_stix_bundle_extracts_ics_objects():
    parsed = parse_stix_bundle(SAMPLE_BUNDLE)

    assert len(parsed["techniques"]) == 1
    assert len(parsed["tactics"]) == 1
    assert len(parsed["mitigations"]) == 1
    assert parsed["techniques"][0]["external_id"] == "T0865"
    assert parsed["technique_mitigations"][0] == ("T0865", "M1017")


def test_diff_techniques_detects_new_and_modified():
    old = {"T0865": {"modified": "2024-01-01T00:00:00.000Z", "name": "Old Name"}}
    new = {
        "T0865": {"modified": "2025-01-01T00:00:00.000Z", "name": "New Name"},
        "T0888": {"modified": "2025-01-01T00:00:00.000Z", "name": "Point & Tag Identification"},
    }

    diff = diff_techniques(old, new)

    assert diff["new"] == ["T0888"]
    assert diff["modified"] == ["T0865"]


def test_load_mitre_asset_catalog_returns_official_ics_assets():
    assets = load_mitre_asset_catalog()
    lookup = {asset["external_id"]: asset["name"] for asset in assets}

    assert lookup["A0002"] == "Human-Machine Interface (HMI)"
    assert lookup["A0003"] == "Programmable Logic Controller (PLC)"
