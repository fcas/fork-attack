import json
import logging
import os
from datetime import date

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def download_attack_bundle():
    response = requests.get(ATTACK_STIX_URL)
    response.raise_for_status()
    return response.json()


def _technique_id(stix_object):
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _tactics(stix_object):
    return [phase.get("phase_name") for phase in stix_object.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"]


def parse_attack_bundle(bundle):
    entries = []
    for stix_object in bundle.get("objects", []):
        if stix_object.get("type") != "attack-pattern":
            continue
        if stix_object.get("revoked") or stix_object.get("x_mitre_deprecated"):
            continue

        technique_id = _technique_id(stix_object)
        if not technique_id:
            continue

        entries.append({
            "technique_id": technique_id,
            "name": stix_object.get("name"),
            "description": stix_object.get("description"),
            "tactics": _tactics(stix_object),
            "platforms": stix_object.get("x_mitre_platforms", []),
            "is_subtechnique": stix_object.get("x_mitre_is_subtechnique", False),
        })

    return entries


def fetch_and_save_attack(output_file=None):
    # Persisted under today's date, the raw extraction date, following the same
    # convention as the per-repo Dependabot/CodeQL dumps in data/<date>/.
    if output_file is None:
        output_file = f"data/{date.today()}/attack.json"

    logger.info(f"Downloading MITRE ATT&CK Enterprise bundle from {ATTACK_STIX_URL}...")
    bundle = download_attack_bundle()

    logger.info("Parsing ATT&CK STIX bundle...")
    entries = parse_attack_bundle(bundle)

    logger.info(f"Parsed {len(entries)} ATT&CK techniques.")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=4)

    logger.info(f"Saved to '{output_file}'.")


if __name__ == "__main__":
    fetch_and_save_attack()
