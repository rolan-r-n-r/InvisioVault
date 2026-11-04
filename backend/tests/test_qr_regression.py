"""Fixture-driven QR steganography regression tests (implementation plan Phase 0).

These tests do **not** assert that every fixture decodes. They assert that the
current, measured behaviour still matches the recorded baseline, so an
intentional change (Phase 1-4) shows up as a visible manifest/baseline diff
rather than an unnoticed drift.

Run the fast smoke subset (default):      pytest tests/test_qr_regression.py -q
Run the release matrix (minutes):         pytest tests/test_qr_regression.py -q -m slow
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from PIL import Image

from tests import qr_harness as H


# ── Manifest integrity ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def manifest():
    return H.read_manifest()


@pytest.fixture(scope="module")
def baseline():
    return H.read_baseline()


def test_manifest_is_committed_and_well_formed(manifest):
    assert manifest["schema"] == H.MANIFEST_SCHEMA
    assert manifest["public_data"] == H.DEFAULT_PUBLIC
    assert manifest["fixtures"], "fixture matrix is empty"
    assert set(manifest["renders"]) == {r.id for r in H.RENDERS}

    required = {
        "id",
        "render",
        "degradation",
        "split",
        "fast",
        "public_data",
        "secret_class",
        "secret_sha256",
        "version",
        "ecc",
        "image",
        "degradations",
        "outcome",
    }
    for record in manifest["fixtures"]:
        missing = required - set(record)
        assert not missing, f"{record.get('id')} missing {sorted(missing)}"


def test_no_real_captures_are_committed(manifest):
    """Fixture provenance must stay synthetic: real captures leak secrets."""
    for record in manifest["fixtures"]:
        assert record["source"] == "synthetic", record["id"]
    for filename in os.listdir(H.PNG_DIR):
        assert filename.endswith(".png"), filename
        assert not filename.startswith("debug_"), filename


def test_secret_hashes_match_the_deterministic_recipe(manifest):
    for render_id, meta in manifest["renders"].items():
        expected = hashlib.sha256(
            H.build_secret(meta["secret_class"]).encode("utf-8")
        ).hexdigest()
        assert meta["secret_sha256"] == expected, render_id
        assert meta["secret_bytes"] == len(
            H.build_secret(meta["secret_class"]).encode("utf-8")
        ), render_id


def test_committed_pngs_match_recorded_geometry(manifest):
    for render_id, meta in manifest["renders"].items():
        path = os.path.join(H.FIXTURE_ROOT, meta["image"])
        assert os.path.exists(path), f"missing committed render: {path}"
        with Image.open(path) as handle:
            image = handle.convert("RGB")
            image.load()
            width = image.size[0]
        dimension = width // meta["render_scale"] - 2 * H.DEFAULT_BORDER
        assert (dimension - 17) // 4 == meta["version"], render_id
        assert H.estimate_px_per_module(image) == pytest.approx(
            meta["render_scale"], rel=0.02
        ), render_id


def test_committed_pngs_match_pinned_sha256():
    """Verify that every committed base PNG matches its pinned SHA-256 digest."""
    ok, errors = H.verify_fixture_hashes()
    assert ok, "Fixture SHA-256 verification failed:\n" + "\n".join(errors)


# ── Round trips on clean renders ─────────────────────────────────────────────


@pytest.mark.parametrize("render", H.RENDERS, ids=[r.id for r in H.RENDERS])
def test_clean_renders_roundtrip(render):
    """Every committed clean render must still decode and return the exact secret."""
    result = H.run_extract(H.png_path(render), password=render.password)
    assert result.outcome == "success", (render.id, result.as_dict())
    assert result.secret_text == H.build_secret(render.payload_class)
    assert result.diagnostics.get("version") is not None
    assert result.diagnostics.get("stage") in ("SUCCESS", "NO_HIDDEN_DATA")


@pytest.mark.parametrize("render", H.RENDERS, ids=[r.id for r in H.RENDERS])
def test_clean_render_channel_probe_is_exact(render):
    """The BER probe must reproduce the embedded bits exactly on a clean render.

    This is the self-check that licenses using the probe on degraded images: if
    the carrier map or polarity mapping were wrong, the clean BER would be
    non-zero.
    """
    with Image.open(H.png_path(render)) as handle:
        base = handle.convert("RGB")
        base.load()
    dimension = base.size[0] // render.scale - 2 * H.DEFAULT_BORDER
    version = (dimension - 17) // 4
    secret = H.build_secret(render.payload_class)

    bit_count = H.carrier_bit_count(secret, render.password)
    bits, meta = H.sample_channel_bits(base, H.DEFAULT_PUBLIC, version, bit_count)
    assert bits, (render.id, meta)
    assert H.bit_error_rate(bits, bits) == 0.0
    # A clean render must not have collapsed polarity classes.
    assert "dark" not in meta["skipped"] or "light" not in meta["skipped"], meta


# ── Baseline parity ──────────────────────────────────────────────────────────


def _fast_fixture_ids(baseline):
    return sorted(
        fid for fid, rec in baseline["fixtures"].items() if rec.get("fast")
    )


def test_fast_subset_matches_baseline(baseline, manifest):
    """The default run pins current behaviour on the fast subset."""
    fast = _fast_fixture_ids(baseline)
    assert fast, "baseline has no fast fixtures"
    assert len(fast) <= 20, f"fast subset must stay <= 20 fixtures, got {len(fast)}"

    by_id = {r["id"]: r for r in manifest["fixtures"]}
    mismatches = []
    for fid in fast:
        recorded = baseline["fixtures"][fid]
        record = by_id[fid]
        render = next(r for r in H.RENDERS if r.id == record["render"])
        degradation = next(d for d in H.DEGRADATIONS if d.id == record["degradation"])
        measured = H.evaluate_fixture(render, degradation)

        if measured["outcome"] != recorded["outcome"]:
            mismatches.append((fid, recorded["outcome"], measured["outcome"]))
        elif recorded["outcome"] == "success" and not measured["secret_match"]:
            mismatches.append((fid, "secret_match=True", "False"))
        if measured["version"] != recorded["version"]:
            mismatches.append((fid, f"version={recorded['version']}", f"version={measured['version']}"))

    assert not mismatches, (
        "QR behaviour drifted from the recorded baseline. If the change is "
        "intentional (Phase 1-4), re-record with `python -m tests.qr_harness "
        f"build --force` and explain the diff. Mismatches: {mismatches[:10]}"
    )


def test_matrix_reproduces_the_measured_camera_failure_band(baseline):
    """The matrix must be able to fail, or it cannot judge a later fix.

    Calibration source: 87 real captures of the shipped app reached the FEC
    payload stage 62% of the time at 3 ppm, 83% at 4 ppm and 100% at 5 ppm and
    above (v11). A noise-free synthetic matrix showed 100% success everywhere,
    which would have made every Phase 3/4 comparison meaningless.
    """
    rows = baseline["fixtures"]
    low_ppm = [
        rec
        for rec in rows.values()
        if (rec["degradations"]["px_per_module"] or 99) <= 4
        and not rec["degradations"]["frontend_transform"]
    ]
    assert low_ppm, "baseline has no fixture at <=4 px/module"
    failures = [rec["id"] for rec in low_ppm if rec["outcome"] != "success"]
    assert failures, (
        "the synthetic matrix cannot reproduce the measured 3-4 px/module failure "
        "band; the degradation model is too optimistic to be useful"
    )
    # The 8 ppm cells must stay healthy, matching the real captures.
    high_ppm = [
        rec for rec in rows.values() if rec["degradations"]["px_per_module"] == 8
        and rec["degradation"] == "ppm8"
    ]
    assert high_ppm and all(rec["outcome"] == "success" for rec in high_ppm)


# ── Statistics ──────────────────────────────────────────────────────────────


def test_wilson_interval_behaves_at_the_extremes():
    low, high = H.wilson_interval(0, 20)
    assert low == 0.0
    assert 0.13 < high < 0.20
    low, high = H.wilson_interval(20, 20)
    assert high == 1.0
    assert 0.80 < low < 0.87
    assert H.wilson_interval(0, 0) == (0.0, 1.0)


def test_release_sample_sizes_match_the_plan():
    """Exact minimums. Two of the plan's rounded figures are slightly low.

    * 99% within 1pp needs **381**, not 380 (380 under-powers the cell).
    * zero failures at 95%/1% needs **299**; the plan's 300 is that rounded up,
      so the 300 gate remains valid and is what a release report must use.
    """
    assert H.sample_size_for_proportion(0.95, 0.05) == 73
    assert H.sample_size_for_proportion(0.99, 0.01) == 381
    assert H.zero_failure_samples(0.95, 0.01) == 299
    assert H.zero_failure_samples(0.95, 0.01) < 300  # release gate stays at 300


def test_bit_error_rate_math():
    assert H.bit_error_rate([1, 0, 1, 1], [1, 0, 1, 1]) == 0.0
    assert H.bit_error_rate([1, 0, 1, 1], [1, 1, 1, 0]) == 0.5
    assert H.bit_error_rate({(0, 0): 1, (0, 1): 0}, {(0, 0): 0, (0, 1): 0}) == 0.5
    with pytest.raises(ValueError):
        H.bit_error_rate([1, 0], [1])
    with pytest.raises(ValueError):
        H.bit_error_rate({(0, 0): 1}, {(0, 1): 1})


# ── Full matrix (release evidence only) ─────────────────────────────────────


@pytest.mark.slow
def test_full_matrix_matches_phase3_reference():
    """Every fixture against the verified Phase 1-3 reference (101/112)."""
    reference = H.read_reference()
    mismatches = []
    for fid, recorded in reference["fixtures"].items():
        render = next(r for r in H.RENDERS if r.id == recorded["render"])
        degradation = next(d for d in H.DEGRADATIONS if d.id == recorded["degradation"])
        measured = H.evaluate_fixture(render, degradation)
        if measured["outcome"] != recorded["outcome"]:
            mismatches.append((fid, recorded["outcome"], measured["outcome"]))
    assert not mismatches, f"{len(mismatches)} fixtures drifted from Phase 1-3 reference: {mismatches[:10]}"


@pytest.mark.slow
def test_historical_baseline_drift_is_isolated_to_known_cell(baseline):
    """Confirm the historical Phase 0 baseline has exactly one known classification drift.

    Cell: small_sealed_s20__ppm8_persp03
    Historical: no_magic / OPTICAL_SENSOR_SATURATION
    Current: payload_fail / HIDDEN_PAYLOAD_CORRUPTED / PAYLOAD_DECODE_FAILED

    Both are failures (101/112 successes in both). No other cells drift.
    """
    mismatches = []
    for fid, recorded in baseline["fixtures"].items():
        render = next(r for r in H.RENDERS if r.id == recorded["render"])
        degradation = next(d for d in H.DEGRADATIONS if d.id == recorded["degradation"])
        measured = H.evaluate_fixture(render, degradation)
        if measured["outcome"] != recorded["outcome"]:
            mismatches.append((fid, recorded["outcome"], measured["outcome"]))
    assert len(mismatches) == 1, (
        f"Expected exactly 1 historical classification drift, got {len(mismatches)}: {mismatches}"
    )
    fid, hist_out, curr_out = mismatches[0]
    assert fid == "small_sealed_s20__ppm8_persp03"
    assert hist_out == "no_magic"
    assert curr_out == "payload_fail"
