from backend.app.mapping_engine import MappingEngine


TECHNIQUES = [
    {
        "external_id": "T0801",
        "name": "Monitor Process State",
        "description": "Network monitoring of process state.",
        "tactics": ["Discovery"],
        "mitigations": ["Network Segmentation"],
    },
    {
        "external_id": "T0835",
        "name": "Manipulation of Control",
        "description": "Requires user interaction through the HMI.",
        "tactics": ["Execution"],
        "mitigations": ["Restrict Access"],
    },
]


def test_mapping_engine_suggests_assets_and_builds_deduplicated_matrix():
    engine = MappingEngine()

    suggestions = engine.suggest_assets_for_technique(TECHNIQUES[1])
    assert "Human-Machine Interface (HMI)" in suggestions

    matrix = engine.generate_zone_matrix(
        selected_assets=["Human-Machine Interface (HMI)", "Control Server"],
        approved_asset_technique_map={
            "Human-Machine Interface (HMI)": [TECHNIQUES[1]],
            "Control Server": [TECHNIQUES[0], TECHNIQUES[1]],
        },
    )

    assert len(matrix) == 2
    assert matrix[0]["technique_id"].startswith("T")
    assert any("Restrict Access" in row["mitigations"] for row in matrix)
