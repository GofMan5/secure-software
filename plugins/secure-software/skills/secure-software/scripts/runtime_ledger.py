#!/usr/bin/env python3
"""Validate runtime/IAM/deployment evidence ledgers and find bounded attack paths."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import platform
import tempfile
import time
from pathlib import Path
from typing import Any

import evidence_adapter as evidence

LEDGER_VERSION = "1.0"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_PATHS = 1_000
MAX_PATH_EXPANSIONS = 100_000
MAX_PATH_QUEUE = 10_000
NODE_KINDS = {
    "asset", "principal", "identity", "permission", "role", "policy", "network", "service",
    "workload", "secret", "component", "advisory", "deployment", "data", "control", "sink",
}
EDGE_STATES = {"active", "blocked", "unknown"}
DISPOSITIONS = {"reportable", "suppressed", "not_applicable", "deferred"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_ledger(path: Path) -> tuple[list[dict[str, Any]], str]:
    require(path.is_file(), f"ledger not found: {path}")
    require(path.stat().st_size <= MAX_INPUT_BYTES, f"ledger exceeds {MAX_INPUT_BYTES} bytes")
    raw = path.read_bytes()
    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        if not raw_line.strip():
            continue
        require(len(records) < MAX_RECORDS, f"ledger exceeds {MAX_RECORDS} records")
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise ValueError(f"line {line_number}: invalid JSON: {error.msg}") from error
        require(isinstance(value, dict), f"line {line_number}: record must be an object")
        value["_line"] = line_number
        records.append(value)
    require(records, "ledger contains no records")
    return records, hashlib.sha256(raw).hexdigest()


def string_list(value: Any, field: str, line: int, limit: int = 100) -> list[str]:
    if value is None:
        return []
    require(isinstance(value, list) and len(value) <= limit and all(isinstance(item, str) and item for item in value),
            f"line {line}: {field} must be a string array with at most {limit} entries")
    return value


def validate(records: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]],
                                                      list[dict[str, Any]], dict[str, Any]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    dispositions: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    all_ids: set[str] = set()
    for record in records:
        line = record["_line"]
        try:
            require(type(record.get("schema_version")) is int and record["schema_version"] == 1,
                    f"line {line}: schema_version must be integer 1")
            kind = record.get("record")
            require(kind in {"node", "edge", "disposition"}, f"line {line}: unknown record type")
            record_id = record.get("id")
            require(isinstance(record_id, str) and record_id and len(record_id) <= 256,
                    f"line {line}: id must be a non-empty string of at most 256 characters")
            require(record_id not in all_ids, f"line {line}: duplicate id {record_id}")
            all_ids.add(record_id)
            if kind == "node":
                allowed = {"schema_version", "record", "id", "kind", "label", "evidence", "attributes", "_line"}
                require(set(record) <= allowed, f"line {line}: unknown node fields {sorted(set(record) - allowed)}")
                require(record.get("kind") in NODE_KINDS, f"line {line}: unsupported node kind {record.get('kind')!r}")
                require("label" not in record or isinstance(record["label"], str), f"line {line}: label must be a string")
                string_list(record.get("evidence"), "evidence", line)
                require("attributes" not in record or isinstance(record["attributes"], dict),
                        f"line {line}: attributes must be an object")
                nodes[record_id] = record
            elif kind == "edge":
                allowed = {"schema_version", "record", "id", "from", "to", "relation", "state", "conditions",
                           "evidence", "counterevidence", "attributes", "_line"}
                require(set(record) <= allowed, f"line {line}: unknown edge fields {sorted(set(record) - allowed)}")
                require(all(isinstance(record.get(field), str) and record[field] for field in ("from", "to", "relation")),
                        f"line {line}: edge from, to, and relation are required strings")
                require(record.get("state") in EDGE_STATES, f"line {line}: edge state must be active, blocked, or unknown")
                string_list(record.get("conditions"), "conditions", line)
                evidence_refs = string_list(record.get("evidence"), "evidence", line)
                string_list(record.get("counterevidence"), "counterevidence", line)
                require("attributes" not in record or isinstance(record["attributes"], dict),
                        f"line {line}: attributes must be an object")
                if record["state"] == "active" and not evidence_refs:
                    warnings.append(f"line {line}: active edge {record_id} has no evidence reference")
                edges[record_id] = record
            else:
                allowed = {"schema_version", "record", "id", "source", "control", "sink", "edge_ids", "impact",
                           "disposition", "evidence", "counterevidence", "assumptions", "_line"}
                require(set(record) <= allowed, f"line {line}: unknown disposition fields {sorted(set(record) - allowed)}")
                require(all(isinstance(record.get(field), str) and record[field] for field in ("source", "control", "sink")),
                        f"line {line}: disposition source, control, and sink are required strings")
                edge_ids = string_list(record.get("edge_ids"), "edge_ids", line)
                require(edge_ids, f"line {line}: disposition must reference at least one edge")
                require(len(edge_ids) == len(set(edge_ids)), f"line {line}: disposition edge_ids must be unique")
                require(record["source"] != record["sink"],
                        f"line {line}: disposition source and sink must differ")
                require(record.get("disposition") in DISPOSITIONS, f"line {line}: invalid disposition")
                require(isinstance(record.get("impact", ""), str), f"line {line}: impact must be a string")
                evidence_refs = string_list(record.get("evidence"), "evidence", line)
                counterevidence_refs = string_list(record.get("counterevidence"), "counterevidence", line)
                assumptions = string_list(record.get("assumptions"), "assumptions", line)
                if record["disposition"] == "reportable":
                    require(record.get("impact", "").strip(), f"line {line}: reportable disposition requires impact")
                    require(evidence_refs, f"line {line}: reportable disposition requires evidence")
                if record["disposition"] == "suppressed":
                    require(counterevidence_refs, f"line {line}: suppressed disposition requires counterevidence")
                if record["disposition"] == "deferred":
                    require(assumptions, f"line {line}: deferred disposition requires assumptions")
                dispositions.append(record)
        except ValueError as error:
            errors.append(str(error))

    for edge in edges.values():
        line = edge["_line"]
        if edge["from"] not in nodes:
            errors.append(f"line {line}: edge {edge['id']} references missing from node {edge['from']}")
        if edge["to"] not in nodes:
            errors.append(f"line {line}: edge {edge['id']} references missing to node {edge['to']}")
    for item in dispositions:
        line = item["_line"]
        for field in ("source", "control", "sink"):
            if item[field] not in nodes:
                errors.append(f"line {line}: disposition {item['id']} references missing {field} node {item[field]}")
        for edge_id in item["edge_ids"]:
            if edge_id not in edges:
                errors.append(f"line {line}: disposition {item['id']} references missing edge {edge_id}")
        if all(edge_id in edges for edge_id in item["edge_ids"]) and item["source"] in nodes and item["sink"] in nodes:
            current = item["source"]
            path_nodes = [current]
            path_edges = [edges[edge_id] for edge_id in item["edge_ids"]]
            for edge in path_edges:
                if edge["from"] != current:
                    errors.append(
                        f"line {line}: disposition {item['id']} edge {edge['id']} does not continue from {current}"
                    )
                    break
                current = edge["to"]
                path_nodes.append(current)
            if current != item["sink"]:
                errors.append(f"line {line}: disposition {item['id']} edge chain does not end at {item['sink']}")
            if item["control"] not in path_nodes:
                errors.append(f"line {line}: disposition {item['id']} control is outside its edge chain")
            if item["disposition"] == "reportable" and any(edge["state"] != "active" for edge in path_edges):
                errors.append(f"line {line}: reportable disposition {item['id']} contains a non-active edge")
            if item["disposition"] == "reportable" and any(not edge.get("evidence") for edge in path_edges):
                errors.append(f"line {line}: reportable disposition {item['id']} contains an edge without evidence")
    report = {
        "valid": not errors,
        "counts": {
            "records": len(records), "nodes": len(nodes), "edges": len(edges),
            "active_edges": sum(edge["state"] == "active" for edge in edges.values()),
            "blocked_edges": sum(edge["state"] == "blocked" for edge in edges.values()),
            "unknown_edges": sum(edge["state"] == "unknown" for edge in edges.values()),
            "dispositions": len(dispositions),
        },
        "node_kinds": dict(sorted(collections.Counter(node["kind"] for node in nodes.values()).items())),
        "errors": errors,
        "warnings": warnings,
    }
    return nodes, edges, dispositions, report


def bounded_paths(nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], source: str, sink: str,
                  max_depth: int, include_unknown: bool, max_paths: int,
                  max_queue: int = MAX_PATH_QUEUE) -> tuple[list[dict[str, Any]], bool]:
    require(source in nodes, f"source node not found: {source}")
    require(sink in nodes, f"sink node not found: {sink}")
    require(source != sink, "source and sink must differ")
    require(max_queue >= 1, "max_queue must be positive")
    allowed_states = {"active", "unknown"} if include_unknown else {"active"}
    adjacency: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for edge in edges.values():
        if edge["state"] in allowed_states:
            adjacency[edge["from"]].append(edge)
    for items in adjacency.values():
        items.sort(key=lambda edge: (edge["to"], edge["relation"], edge["id"]))
    queue: collections.deque[tuple[str, list[str], list[str]]] = collections.deque([(source, [source], [])])
    results: list[dict[str, Any]] = []
    expansions = 0
    while queue:
        current, node_path, edge_path = queue.popleft()
        if len(edge_path) >= max_depth:
            continue
        for edge in adjacency.get(current, []):
            if expansions >= MAX_PATH_EXPANSIONS:
                return results, True
            expansions += 1
            target = edge["to"]
            if target in node_path:
                continue
            next_nodes = [*node_path, target]
            next_edges = [*edge_path, edge["id"]]
            if target == sink:
                if len(results) >= max_paths:
                    return results, True
                path_edges = [edges[edge_id] for edge_id in next_edges]
                results.append({
                    "nodes": next_nodes,
                    "edges": [
                        {"id": item["id"], "from": item["from"], "to": item["to"],
                         "relation": item["relation"], "state": item["state"],
                         "evidence": item.get("evidence", []), "counterevidence": item.get("counterevidence", []),
                         "conditions": item.get("conditions", [])}
                        for item in path_edges
                    ],
                    "contains_unknown": any(item["state"] == "unknown" for item in path_edges),
                })
            else:
                if len(queue) >= max_queue:
                    return results, True
                queue.append((target, next_nodes, next_edges))
    return results, False


def clean_record(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "_line"}


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    started_at = evidence.utc_now()
    started = time.monotonic()
    path = args.input.resolve(strict=True)
    records, digest = read_ledger(path)
    nodes, edges, dispositions, validation = validate(records)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "adapter": {"name": "secure-software-runtime-ledger", "version": LEDGER_VERSION},
        "kind": args.command,
        "input": {"path": str(path), "sha256": digest},
        "started_at": started_at,
        "finished_at": None,
        "duration_ms": None,
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "validation": validation,
    }
    if args.command == "paths" and validation["valid"]:
        paths, search_truncated = bounded_paths(
            nodes, edges, args.source, args.sink, args.max_depth, args.include_unknown, args.max_paths
        )
        receipt["query"] = {
            "source": args.source, "sink": args.sink, "max_depth": args.max_depth,
            "include_unknown": args.include_unknown, "max_paths": args.max_paths,
        }
        receipt["paths"] = paths
        receipt["paths_truncated"] = search_truncated
    elif args.command == "validate":
        receipt["dispositions"] = [
            {key: value for key, value in clean_record(item).items() if key not in {"impact", "assumptions"}}
            for item in dispositions
        ]
    receipt["finished_at"] = evidence.utc_now()
    receipt["duration_ms"] = round((time.monotonic() - started) * 1000)
    receipt = evidence.redact_value(receipt, evidence.secret_values({}))
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return receipt


def self_test() -> None:
    if not __debug__:
        raise RuntimeError("self-test requires assertions; run Python without -O")
    records = [
        {"schema_version": 1, "record": "node", "id": "workload:reader", "kind": "principal"},
        {"schema_version": 1, "record": "node", "id": "role:deployer", "kind": "role"},
        {"schema_version": 1, "record": "node", "id": "service:prod", "kind": "sink"},
        {"schema_version": 1, "record": "edge", "id": "e1", "from": "workload:reader", "to": "role:deployer",
         "relation": "can_assume", "state": "active", "evidence": ["runtime.json#/bindings/0"]},
        {"schema_version": 1, "record": "edge", "id": "e2", "from": "role:deployer", "to": "service:prod",
         "relation": "can_deploy", "state": "active", "evidence": ["runtime.json#/permissions/0"]},
        {"schema_version": 1, "record": "edge", "id": "e3", "from": "workload:reader", "to": "service:prod",
         "relation": "network_only", "state": "blocked", "evidence": ["runtime.json#/network/0"]},
        {"schema_version": 1, "record": "disposition", "id": "p1", "source": "workload:reader",
         "control": "role:deployer", "sink": "service:prod", "edge_ids": ["e1", "e2"],
         "impact": "deployment control", "disposition": "reportable", "evidence": ["runtime.json"]},
    ]
    nodes, edges, dispositions, report = validate([dict(record, _line=index) for index, record in enumerate(records, 1)])
    assert report["valid"] and len(dispositions) == 1
    paths, truncated = bounded_paths(nodes, edges, "workload:reader", "service:prod", 4, False, 1)
    assert len(paths) == 1 and [edge["id"] for edge in paths[0]["edges"]] == ["e1", "e2"]
    assert not truncated
    alternate = dict(edges)
    alternate["e4"] = {"id": "e4", "from": "workload:reader", "to": "service:prod",
                       "relation": "direct", "state": "active", "evidence": ["runtime.json#/direct"]}
    limited, truncated = bounded_paths(nodes, alternate, "workload:reader", "service:prod", 4, False, 1)
    assert len(limited) == 1 and truncated
    branching_nodes = dict(nodes)
    branching_nodes.update({"service:a": {"id": "service:a"}, "service:b": {"id": "service:b"}})
    branching_edges = {
        "q1": {"id": "q1", "from": "workload:reader", "to": "service:a", "relation": "next",
               "state": "active", "evidence": ["q1"]},
        "q2": {"id": "q2", "from": "workload:reader", "to": "service:b", "relation": "next",
               "state": "active", "evidence": ["q2"]},
    }
    assert bounded_paths(branching_nodes, branching_edges, "workload:reader", "service:prod",
                         4, False, 10, max_queue=1)[1]
    broken = [dict(record, _line=index) for index, record in enumerate(records, 1)]
    broken[3]["to"] = "missing"
    assert not validate(broken)[3]["valid"]
    unknown_reportable = [dict(record, _line=index) for index, record in enumerate(records, 1)]
    unknown_reportable[3]["state"] = "unknown"
    assert not validate(unknown_reportable)[3]["valid"]
    for mutate in (
        lambda value: value[0].update(schema_version=True),
        lambda value: value[6].update(edge_ids=["e1", "e1"]),
        lambda value: value[3].pop("evidence"),
        lambda value: value[6].update(source="service:prod"),
    ):
        invalid = json.loads(json.dumps(records))
        mutate(invalid)
        invalid_report = validate([dict(record, _line=index) for index, record in enumerate(invalid, 1)])[3]
        assert not invalid_report["valid"]
    try:
        bounded_paths(nodes, edges, "workload:reader", "workload:reader", 4, False, 10)
        raise AssertionError("identical source and sink were accepted")
    except ValueError:
        pass
    with tempfile.TemporaryDirectory(prefix="runtime-ledger-self-test-") as directory:
        root = Path(directory)
        input_path = root / "ledger.jsonl"
        input_path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        args = argparse.Namespace(command="paths", input=input_path, source="workload:reader", sink="service:prod",
                                  max_depth=4, include_unknown=False, max_paths=10)
        receipt = build_receipt(args)
        assert receipt["validation"]["valid"] and len(receipt["paths"]) == 1
        output = root / "receipt.json"
        evidence.write_receipt(output, receipt, False)
        try:
            evidence.write_receipt(output, receipt, False)
            raise AssertionError("existing receipt was overwritten")
        except FileExistsError:
            pass


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True, help="JSONL ledger path")
    parser.add_argument("--output", type=Path, required=True, help="Atomic JSON receipt path")
    parser.add_argument("--force", action="store_true", help="Replace an existing receipt")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline validation and path-search checks")
    commands = parser.add_subparsers(dest="command")
    validate_parser = commands.add_parser("validate", help="Validate ledger records and references")
    add_common(validate_parser)
    paths_parser = commands.add_parser("paths", help="Find bounded active paths between two nodes")
    add_common(paths_parser)
    paths_parser.add_argument("--source", required=True, help="Source node id")
    paths_parser.add_argument("--sink", required=True, help="Sink node id")
    paths_parser.add_argument("--max-depth", type=int, default=8)
    paths_parser.add_argument("--max-paths", type=int, default=100)
    paths_parser.add_argument("--include-unknown", action="store_true",
                              help="Traverse unknown edges but mark resulting paths")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("self-test: ok")
        return 0
    if args.command is None:
        raise SystemExit("select validate, paths, or --self-test")
    if args.command == "paths":
        if not 1 <= args.max_depth <= 64:
            raise SystemExit("--max-depth must be 1..64")
        if not 1 <= args.max_paths <= MAX_PATHS:
            raise SystemExit(f"--max-paths must be 1..{MAX_PATHS}")
    try:
        receipt = build_receipt(args)
        evidence.write_receipt(args.output, receipt, args.force)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    valid = receipt["validation"]["valid"]
    print(json.dumps({"output": str(args.output), "valid": valid,
                      "paths": len(receipt.get("paths", [])), "receipt_sha256": receipt["receipt_sha256"]},
                     sort_keys=True))
    return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
