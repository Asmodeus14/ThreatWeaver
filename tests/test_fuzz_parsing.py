"""Seeded malformed-PE fuzzing through the sandboxed analysis path.

Every mutated input must yield a ScanResult with a known verdict, without raising, within
the isolation timeout. Crashes and hangs inside workers are allowed to happen — they must
simply be contained and reported, never take the scanner down.
"""

import random
import struct
import time
from pathlib import Path

import pytest

from threatweaver.scanner.inference import InferenceEngine, ScanVerdict
from tests.fixtures import create_minimal_pe

REPO = Path(__file__).resolve().parent.parent
SEEDS = [REPO / "samples" / n for n in ("benign_utility.exe", "suspicious_packed.exe", "benign_helper.dll")]
BUNDLE = REPO / "artifacts" / "models" / "lgbm-v3-dotnet"
TIMEOUT_S = 10.0


def _mutations(data: bytes, rng: random.Random):
    """Yields (name, bytes) structured and random corruptions of a PE file."""
    n = len(data)
    lfanew = struct.unpack_from("<I", data, 0x3C)[0] if n >= 0x40 else 0
    for cut in (2, 0x3C, 0x40, lfanew + 4, lfanew + 24, lfanew + 0xF8, n // 2, n - 1):
        if 0 < cut < n:
            yield f"truncate@{cut}", data[:cut]
    b = bytearray(data)
    if n > lfanew + 8:
        struct.pack_into("<H", b, lfanew + 6, 0xFFFF)          # NumberOfSections = 65535
        yield "huge_section_count", bytes(b)
    for bad in (0, 0x3C, n + 100, 0xFFFFFFF0):
        b = bytearray(data)
        struct.pack_into("<I", b, 0x3C, bad & 0xFFFFFFFF)       # e_lfanew out of range
        yield f"lfanew={bad:#x}", bytes(b)
    if n > lfanew + 0x100:
        b = bytearray(data)
        sec = lfanew + 0x18 + struct.unpack_from("<H", data, lfanew + 0x14)[0]
        if sec + 40 <= n:
            struct.pack_into("<II", b, sec + 16, 0x7FFFFFFF, 0x7FFFFFFF)  # SizeOfRawData / PointerToRawData
            yield "absurd_section_size", bytes(b)
    yield "zeroed_headers", b"MZ" + bytes(min(n, 4096) - 2) + data[4096:]
    for i in range(12):                                          # random flips in the header region
        b = bytearray(data)
        for _ in range(rng.randint(1, 24)):
            pos = rng.randrange(0, min(n, 1024))
            b[pos] = rng.randrange(256)
        yield f"flip#{i}", bytes(b)
    yield "random_tail", data[:512] + bytes(rng.randrange(256) for _ in range(2048))


def _corpus(tmp_path: Path):
    rng = random.Random(1337)
    seeds = [p.read_bytes() for p in SEEDS if p.is_file()]
    seeds.append(create_minimal_pe(tmp_path / "fixture.exe").read_bytes())
    out = []
    for si, data in enumerate(seeds):
        for name, blob in _mutations(data, rng):
            p = tmp_path / f"s{si}_{name.replace('@', '_').replace('=', '_').replace('#', '_')}.exe"
            p.write_bytes(blob)
            out.append(p)
    return out


@pytest.mark.parametrize("mode", ["v2_lightgbm", "legacy"])
def test_malformed_inputs_are_contained(tmp_path, mode):
    if mode == "v2_lightgbm":
        pytest.importorskip("thrember")
        if not BUNDLE.is_dir():
            pytest.skip("bundle not present")
        eng = InferenceEngine(bundle_path=BUNDLE, enable_hash_cache=False, enable_signature_verifier=False,
                              isolate_extraction=True, extraction_timeout_s=TIMEOUT_S)
    else:
        eng = InferenceEngine(checkpoint_path=REPO / "artifacts" / "checkpoints" / "threatweaver_128d.pt",
                              enable_hash_cache=False, enable_signature_verifier=False,
                              isolate_extraction=True, extraction_timeout_s=TIMEOUT_S)
    corpus = _corpus(tmp_path)
    assert len(corpus) > 60
    verdicts = {}
    try:
        for p in corpus:
            t0 = time.time()
            r = eng.analyze_file(p)                              # must never raise
            elapsed = time.time() - t0
            assert isinstance(r.verdict, ScanVerdict), p.name
            assert elapsed < TIMEOUT_S + 60, f"{p.name} took {elapsed:.0f}s"
            verdicts[r.verdict.value] = verdicts.get(r.verdict.value, 0) + 1
            if r.verdict in (ScanVerdict.LIKELY_BENIGN, ScanVerdict.TRUSTED_SIGNER):
                # Benign verdicts must come from a real model score, never from a failure path.
                assert r.warning_message is None, p.name
    finally:
        eng.close()
    assert sum(verdicts.values()) == len(corpus)
    print(f"\n{mode}: {len(corpus)} malformed inputs -> {verdicts}")
