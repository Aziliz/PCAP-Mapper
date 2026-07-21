"""MITRE ATT&CK Enterprise STIX dataset loader.

This module intentionally uses only the Python standard library. It loads a
local Enterprise ATT&CK v18 STIX JSON bundle by default, with ATTACK_STIX_PATH
available as an override. The bundled file keeps Docker/offline deployments
self-contained; compliance-critical deployments may replace it with the official
MITRE Enterprise v18 STIX bundle without changing application code.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
SUPPORTED_ATTACK_VERSIONS = [str(v) for v in range(13, 20)]
DEFAULT_ATTACK_VERSION = "18"
ENTERPRISE_V18_FILE = DATA_DIR / "enterprise-attack-18.0.json"
OFFICIAL_ENTERPRISE_URL_TEMPLATE = (
    "https://github.com/mitre-attack/attack-stix-data/"
    "releases/download/v{version}.0/enterprise-attack.json"
)


def normalize_attack_version(version=None):
    raw = str(version or os.getenv("PCAP_MAPPER_ATTACK_VERSION") or os.getenv("ATTACK_VERSION") or DEFAULT_ATTACK_VERSION).strip().lower()
    raw = raw.replace("enterprise", "").replace("attack", "").replace("v", "").strip()
    if raw.endswith(".0"):
        raw = raw[:-2]
    if raw not in SUPPORTED_ATTACK_VERSIONS:
        raw = DEFAULT_ATTACK_VERSION
    return raw


def dataset_path_for_version(version=None):
    version = normalize_attack_version(version)
    return DATA_DIR / f"enterprise-attack-{version}.0.json"


def official_url_for_version(version=None):
    version = normalize_attack_version(version)
    return OFFICIAL_ENTERPRISE_URL_TEMPLATE.format(version=version)

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class AttackDatasetError(RuntimeError):
    pass


def _env_enabled(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def ensure_dataset(version=None) -> Tuple[Path | None, str]:
    """Return the local official STIX path, downloading it when enabled.

    Set ATTACK_STIX_PATH to point at a downloaded Enterprise v18 STIX bundle.
    Set ATTACK_STIX_AUTO_DOWNLOAD=1 to allow a best-effort download at runtime.
    Set ATTACK_STIX_STRICT=0 to explicitly allow fallback legacy data. Strict mode defaults to enabled because complete ATT&CK v18 sub-technique coverage requires the official STIX bundle.
    The default URL points to the official MITRE ATT&CK Enterprise v18.0 STIX
    release asset. In offline environments, download that asset and set
    ATTACK_STIX_PATH to its local path.
    """
    version = normalize_attack_version(version)
    version_specific = os.getenv(f"ATTACK_STIX_V{version}_PATH", "").strip()
    explicit = version_specific or os.getenv("ATTACK_STIX_PATH", "").strip()
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p, "explicit"
        if _env_enabled("ATTACK_STIX_STRICT", "1"):
            raise AttackDatasetError(f"ATTACK_STIX_PATH does not exist: {p}")

    bundle_path = dataset_path_for_version(version)
    if bundle_path.exists():
        return bundle_path, "bundled"
    if version == DEFAULT_ATTACK_VERSION and ENTERPRISE_V18_FILE.exists():
        return ENTERPRISE_V18_FILE, "bundled"

    if _env_enabled("ATTACK_STIX_AUTO_DOWNLOAD", "1"):
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            bundle_path = dataset_path_for_version(version)
            tmp = bundle_path.with_suffix(".json.tmp")
            with urllib.request.urlopen(official_url_for_version(version), timeout=8) as response:
                tmp.write_bytes(response.read())
            # A small sanity parse avoids caching error pages.
            with tmp.open("r", encoding="utf-8") as f:
                parsed = json.load(f)
            if not isinstance(parsed, dict) or "objects" not in parsed:
                raise AttackDatasetError("Downloaded file is not a STIX bundle.")
            tmp.replace(bundle_path)
            return bundle_path, "downloaded"
        except Exception as exc:
            if _env_enabled("ATTACK_STIX_STRICT", "1"):
                raise AttackDatasetError(f"Unable to load ATT&CK v{version} STIX dataset: {exc}") from exc

    return None, "fallback"


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref.get("external_id")
    return None


def _is_enterprise_attack_pattern(obj: dict) -> bool:
    if obj.get("type") != "attack-pattern":
        return False
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return False
    domains = obj.get("x_mitre_domains") or []
    return (not domains) or ("enterprise-attack" in domains)


def load_official_techniques(version=None) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Load technique registry from official Enterprise ATT&CK v18 STIX.

    Returns (techniques, metadata).  The technique dictionary is keyed by ATT&CK
    ID and contains name/tactic/platform/data-source information used by the app.
    """
    version = normalize_attack_version(version)
    path, source = ensure_dataset(version)
    if not path:
        return {}, {"source": source, "path": "", "version": f"{version}.0", "official": False, "stix_format": "", "dataset_label": "Legacy fallback"}

    with Path(path).open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    techniques: Dict[str, dict] = {}
    for obj in bundle.get("objects", []) or []:
        if not _is_enterprise_attack_pattern(obj):
            continue
        tid = _attack_id(obj)
        if not tid:
            continue
        phases = obj.get("kill_chain_phases") or []
        tactics = [p.get("phase_name") for p in phases if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
        if not tactics:
            continue
        techniques[tid] = {
            "name": obj.get("name", tid),
            "tactic": tactics[0],
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "platforms": obj.get("x_mitre_platforms") or [],
            "data_sources": obj.get("x_mitre_data_sources") or [],
            "stix_id": obj.get("id"),
            "modified": obj.get("modified", ""),
        }

    if not techniques and _env_enabled("ATTACK_STIX_STRICT", "1"):
        raise AttackDatasetError("Official STIX bundle contained no Enterprise ATT&CK techniques.")

    dataset_note = bundle.get("x_pcap_mapper_note", "")
    dataset_label = f"Official ATT&CK Enterprise v{version} STIX" if not dataset_note else f"Bundled ATT&CK Enterprise v{version} STIX"
    return techniques, {
        "source": source,
        "path": str(path),
        "version": f"{version}.0",
        "official": not bool(dataset_note),
        "bundled": source == "bundled",
        "stix_format": bundle.get("spec_version", "2.1"),
        "dataset_label": dataset_label,
        "dataset_note": dataset_note,
    }


def tactic_counts(techniques: Dict[str, dict]) -> Dict[str, dict]:
    counts = {t: {"techniques": 0, "subtechniques": 0, "total": 0} for t in TACTIC_ORDER}
    for tid, meta in techniques.items():
        tactics = meta.get("tactics") or [meta.get("tactic")]
        for tactic in tactics:
            if tactic not in counts:
                counts[tactic] = {"techniques": 0, "subtechniques": 0, "total": 0}
            if meta.get("is_subtechnique") or "." in tid:
                counts[tactic]["subtechniques"] += 1
            else:
                counts[tactic]["techniques"] += 1
            counts[tactic]["total"] += 1
    return counts


def all_tactic_items(techniques: Dict[str, dict], tactic: str) -> List[Tuple[str, dict]]:
    out = []
    for tid, meta in techniques.items():
        tactics = meta.get("tactics") or [meta.get("tactic")]
        if tactic in tactics:
            out.append((tid, meta))
    return sorted(out, key=lambda x: [int(part) if part.isdigit() else part for part in x[0].replace('T','').replace('.', ' . ').split()])
