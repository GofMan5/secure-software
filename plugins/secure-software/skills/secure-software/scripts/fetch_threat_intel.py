#!/usr/bin/env python3
"""Fetch a current, provenance-rich ATT&CK + CISA KEV snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
ATTACK_COLLECTIONS = {
    "enterprise": "Enterprise ATT&CK",
    "mobile": "Mobile ATT&CK",
    "ics": "ICS ATT&CK",
}
KNOWN_ATTACK_PLATFORMS = frozenset(
    {
        "Android",
        "Containers",
        "ESXi",
        "IaaS",
        "Identity Provider",
        "iOS",
        "Linux",
        "macOS",
        "Network Devices",
        "Office Suite",
        "PRE",
        "SaaS",
        "Windows",
    }
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_JSON_CONTAINERS = 400_000
# Reviewed live baselines. A legitimate count decrease must fail closed until this code is reviewed.
ATTACK_COUNT_BASELINE_VERSION = "19.1"
MIN_ACTIVE_TECHNIQUES = {"enterprise": 697, "mobile": 124, "ics": 97}
KEV_COUNT_BASELINE_VERSION = "2026.07.23"
MIN_KEV_ENTRIES = 1_653
USER_AGENT = "Codex-secure-software/1.0 (+https://attack.mitre.org/)"
ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
STIX_ID_RE = re.compile(
    r"[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CATALOG_VERSION_RE = re.compile(r"\d{4}\.\d{2}\.\d{2}")
ATTACK_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)(?:-([0-9A-Za-z.-]+))?")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


NO_REDIRECT_OPENER = build_opener(NoRedirect())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_json_object(raw: bytes, url: str) -> dict[str, Any]:
    containers = raw.count(b"{") + raw.count(b"[")
    if containers > MAX_JSON_CONTAINERS:
        raise ValueError(f"Source exceeds {MAX_JSON_CONTAINERS} JSON containers: {url}")
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object from {url}")
    return value


def fetch_json(
    url: str, timeout: float, expected_final_url: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    if urlsplit(url).scheme != "https":
        raise ValueError(f"Refusing non-HTTPS source: {url}")
    request = Request(
        url,
        headers={"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": USER_AGENT},
    )
    with NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:
        final_url = response.geturl()
        if not final_url.lower().startswith("https://"):
            raise ValueError(f"Refusing non-HTTPS redirect target: {final_url}")
        if expected_final_url is not None and final_url != expected_final_url:
            raise ValueError(f"Refusing unexpected redirect target: {final_url}")
        raw = response.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError(f"Source exceeds {MAX_SOURCE_BYTES} bytes: {url}")
        metadata = {
            "url": url,
            "final_url": final_url,
            "fetched_at": utc_now(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
            "http_date": response.headers.get("Date"),
            "age": response.headers.get("Age"),
            "cache_control": response.headers.get("Cache-Control"),
            "content_type": response.headers.get("Content-Type"),
            "bytes": len(raw),
        }
    return decode_json_object(raw, url), metadata


def list_field(obj: dict[str, Any], field: str, item_type: type | tuple[type, ...]) -> list[Any]:
    value = obj.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, item_type) for item in value):
        raise ValueError(f"STIX {obj.get('id', '<unknown>')} has invalid {field}")
    return value


def string_list_field(obj: dict[str, Any], field: str) -> list[str]:
    return list_field(obj, field, str)


def is_active(obj: dict[str, Any], object_type: str | None = None) -> bool:
    for field in ("revoked", "x_mitre_deprecated"):
        if field in obj and not isinstance(obj[field], bool):
            raise ValueError(f"STIX {obj.get('id', '<unknown>')} has non-boolean {field}")
    return (
        (object_type is None or obj.get("type") == object_type)
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    )


def attack_reference(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    matches: list[tuple[str, str | None]] = []
    for reference in list_field(obj, "external_references", dict):
        attack_id = reference.get("external_id")
        if reference.get("source_name") == "mitre-attack":
            if not isinstance(attack_id, str) or not ATTACK_ID_RE.fullmatch(attack_id):
                raise ValueError(f"STIX {obj.get('id', '<unknown>')} has an invalid ATT&CK id")
            url = reference.get("url")
            if url is not None and not isinstance(url, str):
                raise ValueError(f"STIX {obj.get('id', '<unknown>')} has an invalid ATT&CK URL")
            matches.append((attack_id, url))
    if len(matches) != 1:
        raise ValueError(f"STIX {obj.get('id', '<unknown>')} must have exactly one ATT&CK reference")
    return matches[0]


def object_url(obj: dict[str, Any]) -> str | None:
    for reference in list_field(obj, "external_references", dict):
        if reference.get("source_name") == "mitre-attack" and reference.get("url"):
            return reference["url"]
    return None


def technique_record(obj: dict[str, Any], domain: str) -> dict[str, Any]:
    attack_id, url = attack_reference(obj)
    platforms = sorted(
        {
            platform
            for platform in string_list_field(obj, "x_mitre_platforms")
            if platform.casefold() != "none"
        }
    )
    phases = list_field(obj, "kill_chain_phases", dict)
    if any(not isinstance(phase.get("phase_name"), str) for phase in phases):
        raise ValueError(f"STIX {obj.get('id', '<unknown>')} has invalid kill_chain_phases")
    return {
        "attack_id": attack_id,
        "stix_id": obj["id"],
        "name": obj.get("name"),
        "domains": [domain],
        "platforms": platforms,
        "platforms_unlabeled": not platforms,
        "tactics": sorted(
            {
                phase["phase_name"]
                for phase in phases
            }
        ),
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        "parent_attack_id": None,
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "version": obj.get("x_mitre_version"),
        "description": obj.get("description"),
        "legacy_detection": obj.get("x_mitre_detection"),
        "detection_strategies": [],
        "data_sources": string_list_field(obj, "x_mitre_data_sources"),
        "permissions_required": string_list_field(obj, "x_mitre_permissions_required"),
        "effective_permissions": string_list_field(obj, "x_mitre_effective_permissions"),
        "system_requirements": string_list_field(obj, "x_mitre_system_requirements"),
        "impact_type": string_list_field(obj, "x_mitre_impact_type"),
        "remote_support": obj.get("x_mitre_remote_support"),
        "url": url,
        "external_references": list_field(obj, "external_references", dict),
    }


def merge_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    domains = sorted(set(existing["domains"]) | set(incoming["domains"]))
    platforms = sorted(set(existing["platforms"]) | set(incoming["platforms"]))
    tactics = sorted(set(existing["tactics"]) | set(incoming["tactics"]))
    newest = incoming if (incoming.get("modified") or "") > (existing.get("modified") or "") else existing
    merged = dict(newest)
    merged.update(
        domains=domains,
        platforms=platforms,
        platforms_unlabeled=not platforms,
        tactics=tactics,
        detection_strategies=[],
    )
    return merged


def newest_object(existing: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    if existing is None or (incoming.get("modified") or "") > (existing.get("modified") or ""):
        return incoming
    return existing


def analytic_record(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "stix_id": obj["id"],
        "name": obj.get("name"),
        "description": obj.get("description"),
        "platforms": string_list_field(obj, "x_mitre_platforms"),
        "log_sources": list_field(obj, "x_mitre_log_source_references", dict),
        "mutable_elements": list_field(obj, "x_mitre_mutable_elements", dict),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "version": obj.get("x_mitre_version"),
        "url": object_url(obj),
        "external_references": list_field(obj, "external_references", dict),
    }


def strategy_record(obj: dict[str, Any], analytics: dict[str, dict[str, Any]]) -> dict[str, Any]:
    analytic_refs = string_list_field(obj, "x_mitre_analytic_refs")
    missing = [ref for ref in analytic_refs if ref not in analytics]
    if missing:
        raise ValueError(f"STIX {obj.get('id', '<unknown>')} has dangling analytic refs: {missing}")
    records = [analytic_record(analytics[ref]) for ref in analytic_refs]
    records.sort(key=lambda item: (item.get("name") or "", item["stix_id"]))
    return {
        "stix_id": obj["id"],
        "name": obj.get("name"),
        "analytics": records,
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "version": obj.get("x_mitre_version"),
        "url": object_url(obj),
        "external_references": list_field(obj, "external_references", dict),
    }


def normalize_attack(
    bundles: dict[str, dict[str, Any]], platform_filters: list[str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    records: dict[str, dict[str, Any]] = {}
    attack_ids: dict[str, str | None] = {}
    parent_refs: dict[str, str] = {}
    strategies: dict[str, dict[str, Any]] = {}
    analytics: dict[str, dict[str, Any]] = {}
    detection_targets: dict[str, set[str]] = {}
    domain_counts: dict[str, int] = {}

    for domain, bundle in bundles.items():
        objects = bundle.get("objects")
        if not isinstance(objects, list) or any(not isinstance(obj, dict) for obj in objects):
            raise ValueError(f"ATT&CK {domain} bundle has no objects array")
        active_techniques = [obj for obj in objects if is_active(obj, "attack-pattern")]
        if not active_techniques:
            raise ValueError(f"ATT&CK {domain} bundle has no active techniques")
        domain_counts[domain] = len(active_techniques)
        domain_stix_ids: set[str] = set()
        domain_attack_ids: set[str] = set()
        for obj in active_techniques:
            record = technique_record(obj, domain)
            stix_id = record["stix_id"]
            attack_id = record["attack_id"]
            if stix_id in domain_stix_ids or attack_id in domain_attack_ids:
                raise ValueError(f"ATT&CK {domain} bundle has duplicate technique identity")
            domain_stix_ids.add(stix_id)
            domain_attack_ids.add(attack_id)
            attack_ids[stix_id] = record["attack_id"]
            records[stix_id] = merge_record(records[stix_id], record) if stix_id in records else record

        for obj in objects:
            object_type = obj.get("type")
            if object_type == "x-mitre-detection-strategy" and is_active(obj):
                strategies[obj["id"]] = newest_object(strategies.get(obj["id"]), obj)
            elif object_type == "x-mitre-analytic" and is_active(obj):
                analytics[obj["id"]] = newest_object(analytics.get(obj["id"]), obj)
            elif object_type == "relationship" and is_active(obj):
                if obj.get("relationship_type") == "subtechnique-of":
                    source_ref = obj.get("source_ref")
                    target_ref = obj.get("target_ref")
                    if not isinstance(source_ref, str) or not isinstance(target_ref, str):
                        raise ValueError(f"STIX {obj.get('id', '<unknown>')} has invalid relationship refs")
                    parent_refs[source_ref] = target_ref
                elif obj.get("relationship_type") == "detects":
                    source_ref = obj.get("source_ref")
                    target_ref = obj.get("target_ref")
                    if not isinstance(source_ref, str) or not isinstance(target_ref, str):
                        raise ValueError(f"STIX {obj.get('id', '<unknown>')} has invalid relationship refs")
                    detection_targets.setdefault(source_ref, set()).add(target_ref)

    for stix_id, record in records.items():
        record["parent_attack_id"] = attack_ids.get(parent_refs.get(stix_id, ""))
        if record["is_subtechnique"] and not record["parent_attack_id"]:
            raise ValueError(f"ATT&CK sub-technique {stix_id} has no active parent")

    normalized_strategies = {stix_id: strategy_record(obj, analytics) for stix_id, obj in strategies.items()}
    for strategy_id, targets in detection_targets.items():
        strategy = normalized_strategies.get(strategy_id)
        if not strategy:
            raise ValueError(f"ATT&CK detection relationship has unknown strategy: {strategy_id}")
        for technique_id in targets:
            if technique_id not in records:
                raise ValueError(f"ATT&CK detection relationship has unknown technique: {technique_id}")
            records[technique_id]["detection_strategies"].append(strategy)
    for record in records.values():
        record["detection_strategies"].sort(key=lambda item: (item.get("name") or "", item["stix_id"]))

    wanted = {value.casefold() for value in platform_filters or []}
    known_platforms = {platform.casefold(): platform for platform in KNOWN_ATTACK_PLATFORMS}
    known_platforms.update(
        (platform.casefold(), platform)
        for record in records.values()
        for platform in record["platforms"]
    )
    unknown_platforms = wanted - known_platforms.keys()
    if unknown_platforms:
        names = ", ".join(sorted(unknown_platforms))
        expected = ", ".join(sorted(known_platforms.values(), key=str.casefold))
        raise ValueError(f"Unknown ATT&CK platform(s): {names}. Known for selected domains: {expected}")
    techniques = [
        record
        for record in records.values()
        if not wanted
        or record["platforms_unlabeled"]
        or wanted.intersection(platform.casefold() for platform in record["platforms"])
    ]
    techniques.sort(key=lambda item: (item.get("attack_id") or "", item["stix_id"]))
    stats = {
        "active_detection_strategies": len(strategies),
        "active_analytics": len(analytics),
        "techniques_with_detection": sum(
            bool(record["detection_strategies"] or record["legacy_detection"]) for record in techniques
        ),
        "unlabeled_platform_techniques": sum(record["platforms_unlabeled"] for record in records.values()),
        "unlabeled_included_by_platform_filter": sum(
            bool(wanted) and record["platforms_unlabeled"] for record in techniques
        ),
        "filtered_out_techniques": len(records) - len(techniques),
    }
    return techniques, domain_counts, stats


def validate_fetched_attack_bundle(bundle: dict[str, Any], domain: str) -> None:
    bundle_id = bundle.get("id")
    if bundle.get("type") != "bundle" or not isinstance(bundle_id, str) or not STIX_ID_RE.fullmatch(bundle_id):
        raise ValueError(f"ATT&CK {domain} source is not a valid STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or any(not isinstance(obj, dict) for obj in objects):
        raise ValueError(f"ATT&CK {domain} bundle has no objects array")
    active = [obj for obj in objects if is_active(obj, "attack-pattern")]
    minimum = MIN_ACTIVE_TECHNIQUES[domain]
    if len(active) < minimum:
        # ponytail: the reviewed embedded baseline avoids a state store; update it explicitly
        # after a legitimate publisher count decrease.
        raise ValueError(f"ATT&CK {domain} active technique count {len(active)} is below floor {minimum}")
    for obj in active:
        stix_id = obj.get("id")
        if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--") or not STIX_ID_RE.fullmatch(stix_id):
            raise ValueError(f"ATT&CK {domain} bundle has an invalid technique STIX id")
        if not isinstance(obj.get("name"), str) or not obj["name"].strip():
            raise ValueError(f"ATT&CK technique {stix_id} has no name")


def attack_version_key(value: Any) -> tuple[tuple[int, ...], bool, str]:
    match = ATTACK_VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"ATT&CK index has an invalid version: {value!r}")
    base, prerelease = match.groups()
    return tuple(int(part) for part in base.split(".")), prerelease is None, prerelease or ""


def validate_attack_source_url(url: str, domain: str, version: str) -> str:
    attack_version_key(version)
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"ATT&CK index has an invalid URL for {domain}: {url}") from error
    expected_path = (
        f"/mitre-attack/attack-stix-data/master/{domain}-attack/"
        f"{domain}-attack-{version}.json"
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname != "raw.githubusercontent.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"ATT&CK index has an untrusted bundle URL for {domain}: {url}")
    return url


def resolve_attack_sources(index: dict[str, Any], domains: list[str]) -> dict[str, dict[str, str]]:
    collections = index.get("collections")
    if not isinstance(collections, list) or any(not isinstance(collection, dict) for collection in collections):
        raise ValueError("ATT&CK index has no collections array")
    resolved: dict[str, dict[str, str]] = {}
    for domain in domains:
        matches = [collection for collection in collections if collection.get("name") == ATTACK_COLLECTIONS[domain]]
        if len(matches) != 1:
            raise ValueError(f"ATT&CK index must contain exactly one collection for {domain}")
        collection = matches[0]
        versions = collection.get("versions")
        if not isinstance(versions, list) or not versions:
            raise ValueError(f"ATT&CK index has no version for {domain}")
        if any(not isinstance(item, dict) for item in versions):
            raise ValueError(f"ATT&CK index has an invalid version entry for {domain}")
        version_values = [item.get("version") for item in versions]
        version_keys = [attack_version_key(value) for value in version_values]
        if len(set(version_values)) != len(version_values):
            raise ValueError(f"ATT&CK index has duplicate versions for {domain}")
        latest = versions[max(range(len(versions)), key=version_keys.__getitem__)]
        url = latest.get("url")
        version = str(latest.get("version") or "")
        if not isinstance(url, str):
            raise ValueError(f"ATT&CK index has an invalid latest version for {domain}")
        if attack_version_key(version) < attack_version_key(ATTACK_COUNT_BASELINE_VERSION):
            raise ValueError(
                f"ATT&CK {domain} version {version} is older than reviewed baseline "
                f"{ATTACK_COUNT_BASELINE_VERSION}"
            )
        validate_attack_source_url(url, domain, version)
        resolved[domain] = {
            "collection_id": collection.get("id"),
            "collection_name": collection.get("name"),
            "catalog_version": str(version),
            "url": url,
        }
    selected_versions = {source["catalog_version"] for source in resolved.values()}
    if len(selected_versions) != 1:
        raise ValueError(f"ATT&CK domains resolved to inconsistent versions: {sorted(selected_versions)}")
    return resolved


def normalize_kev(kev: dict[str, Any], minimum_entries: int = MIN_KEV_ENTRIES) -> dict[str, Any]:
    vulnerabilities = kev.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError("CISA KEV feed has no vulnerabilities")
    if any(not isinstance(item, dict) for item in vulnerabilities):
        raise ValueError("CISA KEV feed has invalid vulnerability entries")
    if len(vulnerabilities) < minimum_entries:
        # ponytail: the reviewed embedded baseline avoids a state store; update it explicitly
        # after a legitimate publisher count decrease.
        raise ValueError(
            f"CISA KEV entry count {len(vulnerabilities)} is below floor {minimum_entries}"
        )
    cve_ids = [item.get("cveID") for item in vulnerabilities]
    if any(not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id) for cve_id in cve_ids):
        raise ValueError("CISA KEV feed has invalid CVE identifiers")
    if len(set(cve_ids)) != len(cve_ids):
        raise ValueError("CISA KEV feed has duplicate CVE identifiers")
    required_text = (
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "notes",
    )
    for item in vulnerabilities:
        if any(not isinstance(item.get(field), str) or not item[field].strip() for field in required_text):
            raise ValueError(f"CISA KEV {item.get('cveID', '<unknown>')} has missing required fields")
        try:
            date.fromisoformat(item["dateAdded"])
            date.fromisoformat(item["dueDate"])
        except ValueError as error:
            raise ValueError(f"CISA KEV {item['cveID']} has an invalid date") from error
        if item["knownRansomwareCampaignUse"] not in {"Known", "Unknown"}:
            raise ValueError(f"CISA KEV {item['cveID']} has invalid ransomware status")
        cwes = item.get("cwes")
        if not isinstance(cwes, list) or any(
            not isinstance(cwe, str) or not re.fullmatch(r"CWE-\d+", cwe) for cwe in cwes
        ):
            raise ValueError(f"CISA KEV {item['cveID']} has invalid CWE values")
    declared_count = kev.get("count")
    if not isinstance(declared_count, int) or declared_count != len(vulnerabilities):
        raise ValueError("CISA KEV declared count does not match vulnerabilities")
    catalog_version = kev.get("catalogVersion")
    date_released = kev.get("dateReleased")
    if not isinstance(catalog_version, str) or not CATALOG_VERSION_RE.fullmatch(catalog_version):
        raise ValueError("CISA KEV feed has an invalid catalog version")
    catalog_date = date.fromisoformat(catalog_version.replace(".", "-"))
    baseline_date = date.fromisoformat(KEV_COUNT_BASELINE_VERSION.replace(".", "-"))
    if catalog_date < baseline_date:
        raise ValueError(
            f"CISA KEV catalog {catalog_version} is older than reviewed baseline "
            f"{KEV_COUNT_BASELINE_VERSION}"
        )
    if not isinstance(date_released, str):
        raise ValueError("CISA KEV feed has no release date")
    try:
        released = datetime.fromisoformat(date_released.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("CISA KEV feed has an invalid release date") from error
    if released.tzinfo is None:
        raise ValueError("CISA KEV feed release date has no timezone")
    if released.date() != catalog_date:
        raise ValueError("CISA KEV catalog version and release date disagree")
    return {
        "catalog_version": catalog_version,
        "date_released": date_released,
        "count_baseline_version": (
            KEV_COUNT_BASELINE_VERSION if minimum_entries == MIN_KEV_ENTRIES else None
        ),
        "minimum_expected_entries": minimum_entries,
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def build_snapshot(
    domains: list[str], platform_filters: list[str], include_kev: bool, timeout: float
) -> dict[str, Any]:
    sources: dict[str, dict[str, Any]] = {}
    index, sources["mitre_attack_index"] = fetch_json(ATTACK_INDEX_URL, timeout, ATTACK_INDEX_URL)
    attack_sources = resolve_attack_sources(index, domains)
    bundles: dict[str, dict[str, Any]] = {}
    for domain, source in attack_sources.items():
        bundles[domain], metadata = fetch_json(source["url"], timeout, source["url"])
        validate_fetched_attack_bundle(bundles[domain], domain)
        metadata.update({key: source[key] for key in ("collection_id", "collection_name", "catalog_version")})
        sources[f"mitre_attack_{domain}"] = metadata

    techniques, domain_counts, normalization = normalize_attack(bundles, platform_filters)
    snapshot: dict[str, Any] = {
        "generated_at": utc_now(),
        "freshness": {
            "retrieved_now": True,
            "publisher_freshness": "recorded_not_independently_guaranteed",
        },
        "filters": {
            "domains": domains,
            "platforms": platform_filters,
            "unlabeled_platform_behavior": "include_as_unknown",
        },
        "sources": sources,
        "mitre_attack": {
            "active_definition": "type=attack-pattern, revoked!=true, x_mitre_deprecated!=true",
            "count_baseline_version": ATTACK_COUNT_BASELINE_VERSION,
            "minimum_expected_by_domain": {
                domain: MIN_ACTIVE_TECHNIQUES[domain] for domain in domains
            },
            "catalog_versions_by_domain": {
                domain: source["catalog_version"] for domain, source in attack_sources.items()
            },
            "source_counts_by_domain": domain_counts,
            "normalization": normalization,
            "unique_technique_count": len(techniques),
            "techniques": techniques,
        },
    }

    if include_kev:
        kev, sources["cisa_kev"] = fetch_json(KEV_URL, timeout, KEV_URL)
        snapshot["cisa_kev"] = normalize_kev(kev)
        snapshot["generated_at"] = utc_now()
    return snapshot


def write_snapshot(path: Path, snapshot: dict[str, Any], force: bool) -> None:
    expanded = path.expanduser()
    if expanded.name in {"", ".", ".."}:
        raise ValueError(f"Output must name a file: {path}")
    path = expanded.parent.resolve() / expanded.name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite {path}; pass --force to replace it")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(snapshot, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        if force:
            os.replace(temporary_name, path)
        else:
            os.link(temporary_name, path)
            os.unlink(temporary_name)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def self_test() -> None:
    if not __debug__:
        raise RuntimeError("self-test requires assertions; run Python without -O")
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--parent",
                "name": "Parent",
                "x_mitre_platforms": ["Windows"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T0001", "url": "https://example/T0001"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--child",
                "name": "Child",
                "x_mitre_is_subtechnique": True,
                "x_mitre_platforms": ["Windows"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0001.001"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--unlabeled",
                "name": "Unlabeled",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
            },
            {"type": "attack-pattern", "id": "attack-pattern--revoked", "revoked": True},
            {"type": "attack-pattern", "id": "attack-pattern--deprecated", "x_mitre_deprecated": True},
            {
                "type": "x-mitre-analytic",
                "id": "x-mitre-analytic--one",
                "name": "Analytic 1",
                "description": "Detect the fixture",
                "x_mitre_log_source_references": [{"name": "fixture:events", "channel": "audit"}],
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": "x-mitre-detection-strategy--one",
                "name": "Strategy 1",
                "x_mitre_analytic_refs": ["x-mitre-analytic--one"],
            },
            {
                "type": "relationship",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--child",
                "target_ref": "attack-pattern--parent",
            },
            {
                "type": "relationship",
                "relationship_type": "detects",
                "source_ref": "x-mitre-detection-strategy--one",
                "target_ref": "attack-pattern--parent",
            },
        ]
    }
    techniques, counts, stats = normalize_attack({"enterprise": bundle})
    assert counts == {"enterprise": 3}
    assert [item["attack_id"] for item in techniques] == ["T0001", "T0001.001", "T0002"]
    assert techniques[1]["parent_attack_id"] == "T0001"
    assert techniques[0]["detection_strategies"][0]["analytics"][0]["description"] == "Detect the fixture"
    windows, _, windows_stats = normalize_attack({"enterprise": bundle}, ["windows"])
    assert len(windows) == 3
    assert windows_stats["unlabeled_included_by_platform_filter"] == 1
    ics_only_windows, _, ics_only_stats = normalize_attack(
        {"ics": {"objects": [bundle["objects"][2]]}}, ["windows"]
    )
    assert len(ics_only_windows) == 1
    assert ics_only_stats["unlabeled_included_by_platform_filter"] == 1
    assert stats["techniques_with_detection"] == 1
    try:
        normalize_attack({"enterprise": bundle}, ["Plan 9"])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown platform was accepted")

    malformed = {"objects": [dict(bundle["objects"][0], x_mitre_platforms="Windows")]}
    try:
        normalize_attack({"enterprise": malformed})
    except ValueError:
        pass
    else:
        raise AssertionError("string-valued ATT&CK platforms were accepted")

    missing_identity = {"objects": [dict(bundle["objects"][0], external_references=[])]}
    try:
        normalize_attack({"enterprise": missing_identity})
    except ValueError:
        pass
    else:
        raise AssertionError("ATT&CK technique without a canonical id was accepted")

    try:
        normalize_attack({"enterprise": {"objects": []}})
    except ValueError:
        pass
    else:
        raise AssertionError("empty ATT&CK bundle was accepted")

    valid_kev = {
        "catalogVersion": "2026.07.23",
        "dateReleased": "2026-07-23T00:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Fixture Vendor",
                "product": "Fixture Product",
                "vulnerabilityName": "Fixture vulnerability",
                "dateAdded": "2026-01-01",
                "shortDescription": "Fixture description",
                "requiredAction": "Apply the fixture update",
                "dueDate": "2026-01-22",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "Fixture note",
                "cwes": ["CWE-20"],
            }
        ],
    }
    assert normalize_kev(valid_kev, minimum_entries=1)["count"] == 1
    try:
        normalize_kev(valid_kev)
    except ValueError:
        pass
    else:
        raise AssertionError("collapsed CISA KEV catalog was accepted")
    try:
        normalize_kev(dict(valid_kev, count=2), minimum_entries=1)
    except ValueError:
        pass
    else:
        raise AssertionError("inconsistent CISA KEV count was accepted")
    malformed_kev = dict(valid_kev)
    malformed_kev["vulnerabilities"] = [dict(valid_kev["vulnerabilities"][0], cveID="CVE-")]
    try:
        normalize_kev(malformed_kev, minimum_entries=1)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed CISA KEV identifier was accepted")
    stale_kev = dict(
        valid_kev,
        catalogVersion="2020.01.01",
        dateReleased="2020-01-01T00:00:00Z",
    )
    try:
        normalize_kev(stale_kev, minimum_entries=1)
    except ValueError:
        pass
    else:
        raise AssertionError("stale replayed CISA KEV catalog was accepted")

    try:
        decode_json_object(b"[" * (MAX_JSON_CONTAINERS + 1), "fixture")
    except ValueError:
        pass
    else:
        raise AssertionError("pathological JSON container count was accepted")

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from urllib.error import HTTPError

    requests: list[str] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/redirect-sink")
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        start = f"http://127.0.0.1:{server.server_port}/start"
        try:
            NO_REDIRECT_OPENER.open(start, timeout=2)
        except HTTPError:
            pass
        else:
            raise AssertionError("HTTP redirect was accepted")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert requests == ["/start"]

    index = {
        "collections": [
            {
                "id": "collection--enterprise",
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": "18.0",
                        "url": (
                            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                            "master/enterprise-attack/enterprise-attack-18.0.json"
                        ),
                    },
                    {
                        "version": "19.1-beta",
                        "url": (
                            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                            "master/enterprise-attack/enterprise-attack-19.1-beta.json"
                        ),
                    },
                    {
                        "version": "19.1",
                        "url": (
                            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                            "master/enterprise-attack/enterprise-attack-19.1.json"
                        ),
                    }
                ],
            }
        ]
    }
    source = resolve_attack_sources(index, ["enterprise"])["enterprise"]
    assert source["catalog_version"] == "19.1"
    mixed_index = json.loads(json.dumps(index))
    mixed_index["collections"].append(
        {
            "id": "collection--mobile",
            "name": "Mobile ATT&CK",
            "versions": [
                {
                    "version": "20.0",
                    "url": (
                        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                        "master/mobile-attack/mobile-attack-20.0.json"
                    ),
                }
            ],
        }
    )
    try:
        resolve_attack_sources(mixed_index, ["enterprise", "mobile"])
    except ValueError:
        pass
    else:
        raise AssertionError("mixed ATT&CK domain versions were accepted")
    duplicate_index = json.loads(json.dumps(index))
    duplicate_index["collections"][0]["versions"].append(
        dict(duplicate_index["collections"][0]["versions"][2])
    )
    try:
        resolve_attack_sources(duplicate_index, ["enterprise"])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate ATT&CK index version was accepted")
    index["collections"][0]["versions"][2]["url"] = "https://127.0.0.1/internal"
    try:
        resolve_attack_sources(index, ["enterprise"])
    except ValueError:
        pass
    else:
        raise AssertionError("feed-controlled ATT&CK bundle URL was accepted")

    collapsed_bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "Collapsed fixture",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            }
        ],
    }
    try:
        validate_fetched_attack_bundle(collapsed_bundle, "enterprise")
    except ValueError:
        pass
    else:
        raise AssertionError("collapsed ATT&CK catalog was accepted")

    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "snapshot.json"
        write_snapshot(target, {"version": 1}, False)
        try:
            write_snapshot(target, {"version": 2}, False)
        except FileExistsError:
            pass
        else:
            raise AssertionError("no-clobber write replaced an existing file")
        assert json.loads(target.read_text(encoding="utf-8"))["version"] == 1
        write_snapshot(target, {"version": 2}, True)
        assert json.loads(target.read_text(encoding="utf-8"))["version"] == 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch all active MITRE ATT&CK techniques for selected domains and the CISA KEV catalog."
    )
    parser.add_argument(
        "--domain",
        action="append",
        choices=sorted(ATTACK_COLLECTIONS),
        help="ATT&CK domain; repeat to select several (default: enterprise, mobile, ics)",
    )
    parser.add_argument(
        "--platform",
        action="append",
        default=[],
        help="Case-insensitive ATT&CK platform filter; unlabeled techniques remain as unknown",
    )
    parser.add_argument("--no-kev", action="store_true", help="Skip the CISA KEV feed")
    parser.add_argument("--output", type=Path, help="Write the full JSON snapshot; otherwise print a summary")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file atomically")
    parser.add_argument("--timeout", type=float, default=90.0, help="Per-source network timeout in seconds")
    parser.add_argument(
        "--self-test", action="store_true", help="Run offline parser and write-safety checks, then exit"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("self-test: ok")
        return 0
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise SystemExit("--timeout must be finite and greater than zero")
    if args.output and args.output.expanduser().exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite {args.output}; pass --force to replace it")

    domains = list(dict.fromkeys(args.domain or ATTACK_COLLECTIONS))
    snapshot = build_snapshot(domains, args.platform, not args.no_kev, args.timeout)
    if args.output:
        write_snapshot(args.output, snapshot, args.force)
        print(f"wrote {args.output.resolve()}")
    print(
        json.dumps(
            {
                "generated_at": snapshot["generated_at"],
                "domains": domains,
                "platforms": args.platform,
                "catalog_versions": snapshot["mitre_attack"]["catalog_versions_by_domain"],
                "active_unique_techniques": snapshot["mitre_attack"]["unique_technique_count"],
                "active_source_counts": snapshot["mitre_attack"]["source_counts_by_domain"],
                "normalization": snapshot["mitre_attack"]["normalization"],
                "cisa_kev_entries": snapshot.get("cisa_kev", {}).get("count"),
                "sources": snapshot["sources"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
