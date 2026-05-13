from __future__ import annotations

from collections import defaultdict
from typing import Any


DEFAULT_RULES = {
    "Human-Machine Interface (HMI)": ["hmi", "operator", "user interaction", "display", "screen", "alarm"],
    "Workstation": ["engineering", "workstation", "project file", "logic download", "operator station"],
    "Programmable Logic Controller (PLC)": ["plc", "controller", "firmware", "control logic", "ladder logic"],
    "Distributed Control System (DCS) Controller": ["dcs", "distributed control", "process controller"],
    "Programmable Automation Controller (PAC)": ["pac", "programmable automation controller", "automation controller"],
    "Remote Terminal Unit (RTU)": ["rtu", "telemetry unit", "remote site", "outstation"],
    "Control Server": ["server", "windows", "opc", "database", "remote service", "domain"],
    "Data Historian": ["historian", "time-series", "archive"],
    "Field I/O": ["i/o", "io module", "point & tag", "sensor", "actuator"],
    "Safety Controller": ["safety", "sis", "trip", "interlock"],
    "Jump Host": ["jump host", "bastion", "administration host"],
    "Virtual Private Network (VPN) Server": ["vpn", "remote access gateway", "tunnel"],
    "Routers": ["router", "routing", "network path"],
    "Application Server": ["application", "middleware", "business logic"],
}


class MappingEngine:
    def __init__(self, rules: dict[str, list[str]] | None = None):
        self.rules = rules or DEFAULT_RULES

    def _score_assets(self, technique: dict[str, Any]) -> list[tuple[str, list[str]]]:
        text = f"{technique.get('name', '')} {technique.get('description', '')}".lower()
        scored: list[tuple[str, list[str]]] = []
        for asset_name, keywords in self.rules.items():
            matches = sorted({keyword for keyword in keywords if keyword in text})
            if matches:
                scored.append((asset_name, matches))
        scored.sort(key=lambda item: (-len(item[1]), item[0]))
        return scored

    def suggest_assets_for_technique(self, technique: dict[str, Any]) -> list[str]:
        return [asset_name for asset_name, _ in self._score_assets(technique)]

    def suggest_assets_with_reasoning(self, technique: dict[str, Any]) -> list[dict[str, Any]]:
        suggestions = []
        for asset_name, matches in self._score_assets(technique):
            suggestions.append(
                {
                    "asset": asset_name,
                    "reasoning": f"Deterministic keyword match: {', '.join(matches)}",
                    "confidence": min(1.0, 0.6 + len(matches) * 0.1),
                }
            )
        return suggestions

    def build_deterministic_mapping_report(self, techniques: list[dict[str, Any]]) -> dict[str, Any]:
        mappings: list[dict[str, Any]] = []
        mapped_asset_links = 0
        unmapped_count = 0

        for technique in sorted(techniques, key=lambda item: (item.get("external_id", ""), item.get("name", ""))):
            scored = self._score_assets(technique)
            mapped_assets = [asset_name for asset_name, _ in scored]
            traceability = "; ".join(
                f"{asset_name}: {', '.join(matches)}" for asset_name, matches in scored
            ) or "No deterministic keyword match found"

            if not mapped_assets:
                unmapped_count += 1
            mapped_asset_links += len(mapped_assets)
            # [IMPROVEMENT] Include per-asset confidence in the report output so that
            # callers persisting mappings to the DB can store the engine's actual
            # uncertainty value instead of a hardcoded 1.0.
            # confidence formula mirrors suggest_assets_with_reasoning():
            #   min(1.0, 0.6 + len(keyword_matches) * 0.1)
            # [SOURCE] Audit finding: Medium (M-9)
            confidence_map: dict[str, float] = {
                asset_name: min(1.0, 0.6 + len(matches) * 0.1)
                for asset_name, matches in scored
            }
            mappings.append(
                {
                    "technique_id": technique.get("external_id", ""),
                    "technique_name": technique.get("name", ""),
                    "mapped_assets": mapped_assets,
                    "traceability": traceability,
                    "confidence_map": confidence_map,
                }
            )

        return {
            "coverage_summary": {
                "technique_count": len(mappings),
                "mapped_techniques": len(mappings) - unmapped_count,
                "unmapped_techniques": unmapped_count,
                "asset_technique_links": mapped_asset_links,
            },
            "deduplication": {
                "duplicate_assets_removed": 0,
            },
            "mappings": mappings,
        }

    def generate_zone_matrix(
        self,
        selected_assets: list[str],
        approved_asset_technique_map: dict[str, list[dict[str, Any]]],
        zone_name: str = "",
    ) -> list[dict[str, Any]]:
        deduplicated: dict[str, dict[str, Any]] = {}

        for asset_name in sorted(set(selected_assets)):
            for technique in approved_asset_technique_map.get(asset_name, []):
                technique_id = technique.get("external_id") or technique.get("technique_id")
                if not technique_id:
                    continue

                if technique_id not in deduplicated:
                    deduplicated[technique_id] = {
                        "zone": zone_name,
                        "asset": asset_name,
                        "tactic": "; ".join(sorted(set(technique.get("tactics", [])))) or "Unassigned",
                        "technique_id": technique_id,
                        "technique_name": technique.get("name", "Unnamed Technique"),
                        "description": technique.get("description", ""),
                        "mitigations": "; ".join(sorted(set(technique.get("mitigations", [])))),
                    }
                else:
                    existing_assets = set(filter(None, deduplicated[technique_id]["asset"].split("; ")))
                    deduplicated[technique_id]["asset"] = "; ".join(sorted(existing_assets | {asset_name}))

                    existing_tactics = set(filter(None, deduplicated[technique_id]["tactic"].split("; ")))
                    incoming_tactics = set(technique.get("tactics", []))
                    deduplicated[technique_id]["tactic"] = "; ".join(sorted(existing_tactics | incoming_tactics))

                    existing_mitigations = set(filter(None, deduplicated[technique_id]["mitigations"].split("; ")))
                    incoming_mitigations = set(technique.get("mitigations", []))
                    deduplicated[technique_id]["mitigations"] = "; ".join(sorted(existing_mitigations | incoming_mitigations))

        return sorted(deduplicated.values(), key=lambda row: (row["technique_id"], row["asset"]))
