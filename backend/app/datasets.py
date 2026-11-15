"""Adapters for public flow datasets. Never reinterpret flows as login events."""
import csv
import hashlib
import io
import math
from dataclasses import asdict, dataclass
from typing import Literal

MAX_ROWS = 1000


@dataclass(frozen=True)
class Flow:
    row: int
    duration_seconds: float
    packets: int
    source_bytes: int
    destination_bytes: int


def number(row, key, row_number, integer=False):
    value = row.get(key, "")
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"Row {row_number}: {key} must be numeric") from None
    if not math.isfinite(parsed) or parsed < 0 or (integer and not parsed.is_integer()):
        raise ValueError(f"Row {row_number}: invalid {key}")
    return int(parsed) if integer else parsed


def parse_csv(dataset: Literal["unsw-nb15", "cicids2017"], text: str):
    if dataset not in ("unsw-nb15", "cicids2017"):
        raise ValueError("Unsupported dataset")
    if len(text.encode("utf-8")) > 1_000_000:
        raise ValueError("CSV exceeds the 1 MB request limit")
    reader = csv.DictReader(io.StringIO(text, newline=""), skipinitialspace=True, strict=True)
    try:
        header = reader.fieldnames
    except csv.Error as exc:
        raise ValueError("Malformed CSV header") from exc
    if header is None:
        raise ValueError("CSV requires a header")
    names = [name.strip().lstrip("\ufeff") for name in header]
    if len(names) != len(set(names)) or any(not name for name in names):
        raise ValueError("CSV headers must be non-empty and unique")
    reader.fieldnames = names
    required = {"dur", "spkts", "dpkts", "sbytes", "dbytes", "label", "attack_cat"} if dataset == "unsw-nb15" else {"Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"}
    missing = required.difference(names)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    records = []
    try:
        for index, row in enumerate(reader, start=1):
            if index > MAX_ROWS:
                raise ValueError(f"CSV exceeds {MAX_ROWS} rows; upload a smaller sample")
            if None in row:
                raise ValueError(f"Row {index}: unexpected extra columns")
            if dataset == "unsw-nb15":
                duration = number(row, "dur", index)
                packets = number(row, "spkts", index, True) + number(row, "dpkts", index, True)
                src, dst = number(row, "sbytes", index, True), number(row, "dbytes", index, True)
                raw_label = (row.get("label") or "").strip()
                if raw_label not in ("0", "1"):
                    raise ValueError(f"Row {index}: label must be 0 or 1")
                label = "benign" if raw_label == "0" else (row.get("attack_cat") or "unknown").strip() or "unknown"
            else:
                duration = number(row, "Flow Duration", index) / 1_000_000
                packets = number(row, "Total Fwd Packets", index, True) + number(row, "Total Backward Packets", index, True)
                src, dst = number(row, "Total Length of Fwd Packets", index, True), number(row, "Total Length of Bwd Packets", index, True)
                label = (row.get("Label") or "").strip()
                if not label:
                    raise ValueError(f"Row {index}: Label is required")
            flow = Flow(index, duration, packets, src, dst)
            records.append((flow, label))
    except csv.Error as exc:
        raise ValueError("Malformed CSV") from exc
    if not records:
        raise ValueError("CSV contains no flow records")
    return records, hashlib.sha256(text.encode("utf-8")).hexdigest()


def classify(flow: Flow):
    """Two observable flow heuristics; labels are not inputs and are not verified outcomes."""
    if flow.source_bytes >= 100_000_000:
        return {"classification": "high_outbound_volume", "action": "flag", "matched_rules": ["flow-high-outbound-v1"], "explanation": "A single flow contains at least 100 MB of outbound data."}
    if flow.duration_seconds > 0 and flow.packets >= 200 and flow.packets / flow.duration_seconds >= 10_000:
        return {"classification": "high_packet_rate", "action": "flag", "matched_rules": ["flow-high-packet-rate-v1"], "explanation": "A single flow contains at least 200 packets at 10,000 packets per second or more."}
    return {"classification": "no_flow_rule_match", "action": "monitor", "matched_rules": [], "explanation": "No flow heuristic matched; this does not establish benign activity."}


def analyze(dataset, text, include_labels=False):
    records, digest = parse_csv(dataset, text)
    return {"dataset": dataset, "sha256": digest, "record_count": len(records), "unit": "network flow", "results": [{"flow": asdict(flow), "assessment": classify(flow), **({"dataset_label": label} if include_labels else {})} for flow, label in records]}
