"""Convert MITRE's enterprise-attack STIX bundle into the techniques.json format.

Usage:
    1. Download enterprise-attack.json from https://github.com/mitre-attack/attack-stix-data
    2. python scripts/ingest_attack.py path/to/enterprise-attack.json knowledge_base/attack_full.json
       Add --skip-pre-attack to drop techniques that are only reconnaissance or resource-development
       (they happen before the attacker touches your network, so network logs rarely show them).

Status: run against the real enterprise-attack.json (October 2026): 697 active techniques and
sub-techniques written, and the output loads with netsentinel.retriever.load_techniques.
The 'response' field is left empty because ATT&CK describes behavior, not response steps.

Caveat, measured: plain BM25 over all 697 techniques retrieves far worse than the curated 20 on
eval/dataset.jsonl (see docs/eval.md). Do not swap it in as the default knowledge base.
Compare with:  python -m eval.run_eval --mode retrieval --kb knowledge_base/attack_full.json
"""
import argparse
import json

PRE_ATTACK_TACTICS = {"reconnaissance", "resource-development"}


def first_paragraph(text):
    return (text or "").strip().split("\n\n")[0][:700]


def main(bundle_path, output_path, skip_pre_attack=False):
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
        phases = {phase["phase_name"] for phase in obj.get("kill_chain_phases", [])}
        if skip_pre_attack and phases and phases <= PRE_ATTACK_TACTICS:
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
    parser = argparse.ArgumentParser(description="Convert the ATT&CK STIX bundle to techniques.json format")
    parser.add_argument("bundle", help="path to enterprise-attack.json")
    parser.add_argument("output", help="where to write the techniques JSON")
    parser.add_argument("--skip-pre-attack", action="store_true", help="drop reconnaissance / resource-development-only techniques")
    args = parser.parse_args()
    main(args.bundle, args.output, args.skip_pre_attack)
