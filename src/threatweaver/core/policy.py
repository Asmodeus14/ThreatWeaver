"""Verdict policy v2 — the single, versioned place where evidence becomes a verdict.

Pure function, no I/O, exhaustively unit-tested. Rules (first match wins):

1. parse failed / not a PE                      -> Analysis Error / Unsupported Format
2. known-bad hash or YARA rule match            -> Known Malicious      (names the match)
3. P(malicious) >= tau_high (0.1% val FPR)      -> Likely Malicious     (even if validly signed)
4. tau_low <= P < tau_high (1% val FPR)         -> Suspicious
5. P < tau_low and embedding is unfamiliar      -> Unfamiliar           (never called malicious)
6. P < tau_low and trusted Authenticode signer  -> Trusted Signer
7. otherwise                                    -> Likely Benign

A valid signature is evidence, not a bypass: it can only move a low-score file from
"Likely Benign" to "Trusted Signer"; it never suppresses a high model score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

POLICY_VERSION = "policy-v2.0"


@dataclass(frozen=True)
class Evidence:
    parse_ok: bool
    is_pe: bool = True
    p_malicious: Optional[float] = None
    tau_high: Optional[float] = None
    tau_low: Optional[float] = None
    signature_trusted: bool = False
    signer: Optional[str] = None
    is_novel: Optional[bool] = None          # None = novelty not evaluated
    known_bad: Optional[str] = None          # name of matching hash list / YARA rule
    parse_error: Optional[str] = None


@dataclass
class Decision:
    verdict: str
    reasons: List[str] = field(default_factory=list)
    policy_version: str = POLICY_VERSION


# Verdict labels (string values match ScanVerdict)
ANALYSIS_ERROR = "Analysis Error"
UNSUPPORTED = "Unsupported Format"
KNOWN_MALICIOUS = "Known Malicious"
LIKELY_MALICIOUS = "Likely Malicious"
SUSPICIOUS = "Suspicious"
UNFAMILIAR = "Unfamiliar / Out-of-Distribution"
TRUSTED_SIGNER = "Trusted Signer"
LIKELY_BENIGN = "Likely Benign"


def decide(e: Evidence) -> Decision:
    if not e.parse_ok:
        return Decision(ANALYSIS_ERROR, [f"Static parsing failed: {e.parse_error or 'unknown error'}. Treat as unknown, not benign."])
    if not e.is_pe:
        return Decision(UNSUPPORTED, ["Not a Windows PE file; the model was not applied."])
    if e.known_bad:
        return Decision(KNOWN_MALICIOUS, [f"Matches known-malicious indicator: {e.known_bad}."])
    if e.p_malicious is None or e.tau_high is None or e.tau_low is None:
        return Decision(ANALYSIS_ERROR, ["No model score available; no verdict produced."])
    if not (0.0 <= e.tau_low <= e.tau_high <= 1.0):
        raise ValueError("Invalid thresholds: require 0 <= tau_low <= tau_high <= 1")

    p = e.p_malicious
    sig_note = f" File carries a valid signature from {e.signer or 'a trusted signer'}; signatures can be stolen or abused." \
        if e.signature_trusted else ""
    if p >= e.tau_high:
        return Decision(LIKELY_MALICIOUS, [
            f"Model score {p:.1%} is at or above the high-confidence threshold {e.tau_high:.1%} "
            f"(≈0.1% false-positive rate on validation data).{sig_note}"])
    if p >= e.tau_low:
        return Decision(SUSPICIOUS, [
            f"Model score {p:.1%} is between the review threshold {e.tau_low:.1%} and the high-confidence "
            f"threshold {e.tau_high:.1%}.{sig_note}"])
    if e.is_novel:
        return Decision(UNFAMILIAR, [
            f"Model score {p:.1%} is low, but the file is unlike the training data, so the score is less reliable."])
    if e.signature_trusted:
        return Decision(TRUSTED_SIGNER, [
            f"Model score {p:.1%} is below the review threshold {e.tau_low:.1%}, and the file has a valid "
            f"signature from {e.signer or 'a trusted signer'}."])
    reasons = [f"Model score {p:.1%} is below the review threshold {e.tau_low:.1%}."]
    if e.is_novel is None:
        reasons.append("Novelty was not evaluated for this model.")
    return Decision(LIKELY_BENIGN, reasons)
