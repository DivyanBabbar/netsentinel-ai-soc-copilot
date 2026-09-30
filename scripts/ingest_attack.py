"""Convert MITRE's enterprise-attack STIX bundle into the techniques.json format.

Usage:
    1. Download enterprise-attack.json from https://github.com/mitre-attack/attack-stix-data
    2. python scripts/ingest_attack.py path/to/enterprise-attack.json knowledge_base/attack_full.json

Status: written but not yet run against the real file. Check the output before using it.
The 'response' field is left empty because ATT&CK describes behavior, not response steps.
"""
import json
import sys


def first_paragraph(text):
    return (text or "").strip().split("\n\n")[0][:700]


def main(bundle_path, output_path):
    with open(bundle_path, encoding="utf-8") as file:
        bundle = json.load(file)
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = ""
        for reference in obj.get("external_references", []):
            if reference.get("source_name") == "mitre-attack":
                technique_id = reference.get("external_id", "")
        if not technique_id:
            continue
        rows.append({
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": first_paragraph(obj.get("description")),
            "detection": first_paragraph(obj.get("x_mitre_detection")),
            "response": "",
        })
    rows.sort(key=lambda row: row["id"])
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(rows, file, indent=2)
    print(f"wrote {len(rows)} techniques to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python scripts/ingest_attack.py <enterprise-attack.json> <output.json>")
    main(sys.argv[1], sys.argv[2])
