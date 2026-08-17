import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import date

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"


def download_capec_xml():
    response = requests.get(CAPEC_XML_URL)
    response.raise_for_status()
    return response.content


def _local_tag(element):
    return re.sub(r"^\{.*\}", "", element.tag)


def _find_by_local_tag(parent, local_tag):
    return [child for child in parent if _local_tag(child) == local_tag]


def _text_of(parent, local_tag):
    matches = _find_by_local_tag(parent, local_tag)
    return matches[0].text.strip() if matches and matches[0].text else None


def _parse_related_weaknesses(attack_pattern):
    cwe_ids = []
    for related_weaknesses in _find_by_local_tag(attack_pattern, "Related_Weaknesses"):
        for related_weakness in _find_by_local_tag(related_weaknesses, "Related_Weakness"):
            cwe_id = related_weakness.get("CWE_ID")
            if cwe_id:
                cwe_ids.append(f"CWE-{cwe_id}")
    return cwe_ids


def _parse_related_attack_patterns(attack_pattern):
    related_capec_ids = []
    for related_patterns in _find_by_local_tag(attack_pattern, "Related_Attack_Patterns"):
        for related_pattern in _find_by_local_tag(related_patterns, "Related_Attack_Pattern"):
            capec_id = related_pattern.get("CAPEC_ID")
            if capec_id:
                related_capec_ids.append(f"CAPEC-{capec_id}")
    return related_capec_ids


def _parse_attack_mappings(attack_pattern):
    technique_ids = []
    for taxonomy_mappings in _find_by_local_tag(attack_pattern, "Taxonomy_Mappings"):
        for taxonomy_mapping in _find_by_local_tag(taxonomy_mappings, "Taxonomy_Mapping"):
            if taxonomy_mapping.get("Taxonomy_Name") != "ATTACK":
                continue
            entry_id = _text_of(taxonomy_mapping, "Entry_ID")
            if entry_id:
                technique_ids.append(f"T{entry_id}")
    return technique_ids


def parse_capec_xml(xml_bytes):
    root = ET.fromstring(xml_bytes)

    attack_patterns_container = _find_by_local_tag(root, "Attack_Patterns")
    if not attack_patterns_container:
        logger.error("No <Attack_Patterns> element found in CAPEC XML.")
        return []

    entries = []
    for attack_pattern in _find_by_local_tag(attack_patterns_container[0], "Attack_Pattern"):
        capec_id = f"CAPEC-{attack_pattern.get('ID')}"
        entries.append({
            "capec_id": capec_id,
            "name": attack_pattern.get("Name"),
            "abstraction": attack_pattern.get("Abstraction"),
            "status": attack_pattern.get("Status"),
            "description": _text_of(attack_pattern, "Description"),
            "likelihood_of_attack": _text_of(attack_pattern, "Likelihood_Of_Attack"),
            "typical_severity": _text_of(attack_pattern, "Typical_Severity"),
            "related_weaknesses": _parse_related_weaknesses(attack_pattern),
            "related_attack_patterns": _parse_related_attack_patterns(attack_pattern),
            "related_attack_techniques": _parse_attack_mappings(attack_pattern),
        })

    return entries


def fetch_and_save_capec(output_file=None):
    # Persisted under today's date, the raw extraction date, following the same
    # convention as the per-repo Dependabot/CodeQL dumps in data/<date>/.
    if output_file is None:
        output_file = f"data/{date.today()}/capec.json"

    logger.info(f"Downloading CAPEC catalog from {CAPEC_XML_URL}...")
    xml_bytes = download_capec_xml()

    logger.info("Parsing CAPEC XML...")
    entries = parse_capec_xml(xml_bytes)

    total_cwe_links = sum(len(e["related_weaknesses"]) for e in entries)
    total_attack_links = sum(len(e["related_attack_techniques"]) for e in entries)
    logger.info(f"Parsed {len(entries)} attack patterns, {total_cwe_links} CAPEC-CWE links, {total_attack_links} CAPEC-ATT&CK links.")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=4)

    logger.info(f"Saved to '{output_file}'.")


if __name__ == "__main__":
    fetch_and_save_capec()
