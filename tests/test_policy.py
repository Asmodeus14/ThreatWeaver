"""Truth-table tests for verdict policy v2."""

import itertools

import pytest

from threatweaver.core import policy as P
from threatweaver.core.policy import Evidence, decide

HI, LO = 0.9, 0.5


def ev(**kw):
    base = dict(parse_ok=True, is_pe=True, p_malicious=0.1, tau_high=HI, tau_low=LO)
    base.update(kw)
    return Evidence(**base)


@pytest.mark.parametrize("p,signed,novel,expected", [
    (0.95, False, False, P.LIKELY_MALICIOUS),
    (0.95, True, False, P.LIKELY_MALICIOUS),     # signature never suppresses a high score
    (0.95, True, True, P.LIKELY_MALICIOUS),
    (0.70, False, False, P.SUSPICIOUS),
    (0.70, True, True, P.SUSPICIOUS),
    (0.10, False, True, P.UNFAMILIAR),
    (0.10, True, True, P.UNFAMILIAR),            # novelty outranks the signature for low scores
    (0.10, True, False, P.TRUSTED_SIGNER),
    (0.10, False, False, P.LIKELY_BENIGN),
    (0.10, False, None, P.LIKELY_BENIGN),
])
def test_score_rules(p, signed, novel, expected):
    assert decide(ev(p_malicious=p, signature_trusted=signed, is_novel=novel)).verdict == expected


def test_threshold_boundaries_are_inclusive():
    assert decide(ev(p_malicious=HI)).verdict == P.LIKELY_MALICIOUS
    assert decide(ev(p_malicious=LO)).verdict == P.SUSPICIOUS
    assert decide(ev(p_malicious=LO - 1e-9)).verdict == P.LIKELY_BENIGN


def test_precedence_parse_unsupported_known_bad():
    assert decide(ev(parse_ok=False, p_malicious=0.99, known_bad="x")).verdict == P.ANALYSIS_ERROR
    assert decide(ev(is_pe=False, known_bad="x")).verdict == P.UNSUPPORTED
    assert decide(ev(known_bad="YARA:Test_Rule", p_malicious=0.0, signature_trusted=True)).verdict == P.KNOWN_MALICIOUS


def test_missing_score_is_not_benign():
    assert decide(ev(p_malicious=None)).verdict == P.ANALYSIS_ERROR


def test_invalid_thresholds_rejected():
    with pytest.raises(ValueError):
        decide(ev(tau_low=0.95, tau_high=0.5))


def test_every_combination_yields_a_reasoned_verdict():
    """Exhaustive grid: the policy is total and always explains itself."""
    valid = {P.ANALYSIS_ERROR, P.UNSUPPORTED, P.KNOWN_MALICIOUS, P.LIKELY_MALICIOUS,
             P.SUSPICIOUS, P.UNFAMILIAR, P.TRUSTED_SIGNER, P.LIKELY_BENIGN}
    for parse_ok, is_pe, p, signed, novel, kb in itertools.product(
            (True, False), (True, False), (None, 0.0, 0.3, 0.5, 0.7, 0.9, 1.0),
            (True, False), (True, False, None), (None, "hash")):
        d = decide(Evidence(parse_ok=parse_ok, is_pe=is_pe, p_malicious=p, tau_high=HI, tau_low=LO,
                            signature_trusted=signed, is_novel=novel, known_bad=kb))
        assert d.verdict in valid and d.reasons and d.policy_version == P.POLICY_VERSION
        if d.verdict in (P.LIKELY_BENIGN, P.TRUSTED_SIGNER):
            assert p is not None and p < LO and not kb
