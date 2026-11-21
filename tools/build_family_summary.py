"""Builds a real malware-family summary from local EMBER2024 JSONL metadata.

Reads only the metadata prefix of each record (everything before the large
"histogram" field) so the full 18 GB corpus can be summarized quickly.
Output: artifacts/dataset/family_summary.json, consumed by /api/families.

Every number in the output is counted from the dataset; nothing is invented.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict

PREFIX_MARKER = ', "histogram"'
TAG_FIELDS = ("behavior", "file_property", "packer", "exploit", "group")


def parse_metadata_prefix(line: str) -> Dict[str, Any] | None:
    """Parses the metadata fields that precede the feature payload of an EMBER2024 record."""
    cut = line.find(PREFIX_MARKER)
    text = (line[:cut] + "}") if cut > 0 else line
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None


def summarize(data_dir: Path, min_confidence: float, top_n: int) -> Dict[str, Any]:
    fam_counts: Counter[str] = Counter()
    fam_conf_sum: Dict[str, float] = defaultdict(float)
    fam_first: Dict[str, int] = {}
    fam_last: Dict[str, int] = {}
    fam_types: Dict[str, Counter[str]] = defaultdict(Counter)
    fam_partitions: Dict[str, Counter[str]] = defaultdict(Counter)
    fam_tags: Dict[str, Dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    totals = Counter()

    files = sorted(data_dir.rglob("*.jsonl"))
    file_digests = {}
    for jf in files:
        partition = jf.parent.name
        h = hashlib.sha256()
        with open(jf, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                h.update(line.encode("utf-8", errors="replace"))
                if not line.strip():
                    continue
                rec = parse_metadata_prefix(line)
                if rec is None:
                    totals["unparseable"] += 1
                    continue
                totals["records"] += 1
                if rec.get("label") != 1:
                    continue
                totals["malicious"] += 1
                fam = rec.get("family")
                conf = float(rec.get("family_confidence") or 0.0)
                if not fam:
                    totals["malicious_no_family"] += 1
                    continue
                if conf < min_confidence:
                    totals["malicious_low_confidence_family"] += 1
                    continue
                totals["malicious_with_family"] += 1
                fam_counts[fam] += 1
                fam_conf_sum[fam] += conf
                ts = int(rec.get("first_submission_date") or 0)
                if ts:
                    fam_first[fam] = min(fam_first.get(fam, ts), ts)
                    fam_last[fam] = max(fam_last.get(fam, ts), ts)
                fam_types[fam][str(rec.get("file_type", "unknown"))] += 1
                fam_partitions[fam][partition] += 1
                for tf in TAG_FIELDS:
                    for tag in rec.get(tf) or []:
                        fam_tags[fam][tf][str(tag)] += 1
        file_digests[str(jf.relative_to(data_dir))] = h.hexdigest()
        print(f"  [+] {jf.relative_to(data_dir)}  (malicious so far: {totals['malicious']:,})", flush=True)

    def iso(ts: int | None) -> str | None:
        return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else None

    families = []
    for fam, count in fam_counts.most_common(top_n):
        families.append({
            "id": f"fam-{fam}",
            "name": fam,
            "sample_count": count,
            "mean_family_confidence": round(fam_conf_sum[fam] / count, 4),
            "first_seen": iso(fam_first.get(fam)),
            "last_seen": iso(fam_last.get(fam)),
            "file_types": dict(fam_types[fam].most_common()),
            "partitions": dict(fam_partitions[fam].most_common()),
            "tags": {tf: dict(fam_tags[fam][tf].most_common(5)) for tf in TAG_FIELDS if fam_tags[fam][tf]},
        })

    return {
        "available": True,
        "kind": "dataset_metadata",
        "source": "EMBER2024 record metadata (family, family_confidence, behavior, packer, ...) from local JSONL files",
        "data_dir": str(data_dir),
        "min_family_confidence": min_confidence,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": dict(totals),
        "distinct_families": len(fam_counts),
        "families": families,
        "source_file_sha256": file_digests,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default="data/ember2024")
    ap.add_argument("--out", default="artifacts/dataset/family_summary.json")
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--top", type=int, default=60)
    args = ap.parse_args()

    data_dir = Path(args.data_dir).resolve()
    if not data_dir.is_dir():
        print(f"[!] Data directory not found: {data_dir}")
        return 1
    summary = summarize(data_dir, args.min_confidence, args.top)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] Wrote {out} ({summary['distinct_families']} families, {summary['totals'].get('malicious_with_family', 0):,} samples)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
