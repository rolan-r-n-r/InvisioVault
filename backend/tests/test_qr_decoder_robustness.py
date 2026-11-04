"""Phase 2 decoder robustness tests.

Covers BCH version information, client-hint validation, grid realignment,
confidence diagnostics, and the failure-stage taxonomy. No encoder changes are
exercised here: these tests read the existing v1 payload format.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile

import pytest
import segno
from PIL import Image

from utils import qr_stego as S
from utils.qr_module_map import (
    VERSION_INFO_MAX_ERRORS,
    decode_version_information,
    get_qr_dimension,
    read_version_information,
    version_info_codeword,
)

PUBLIC = "https://invisiovault.com/verify?id=987654"
SECRET = "Decoder robustness payload 2026"
PASSWORD = "fixture-correct-horse-battery"


@pytest.fixture()
def workdir():
    path = tempfile.mkdtemp(prefix="iv_qr_phase2_")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# ── A. BCH version information ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "version,expected",
    [(7, 0x07C94), (8, 0x085BC), (9, 0x09A99)],
)
def test_codewords_match_the_reference_implementation(version, expected):
    """Known-good ZXing VERSION_DECODE_INFO values validate the generator."""
    assert version_info_codeword(version) == expected


def test_codeword_roundtrip_covers_every_version():
    for version in range(7, 41):
        decoded, distance = decode_version_information(version_info_codeword(version))
        assert decoded == version
        assert distance == 0


def test_codeword_rejects_out_of_range_versions():
    with pytest.raises(ValueError):
        version_info_codeword(6)
    with pytest.raises(ValueError):
        version_info_codeword(41)


def test_corrects_up_to_the_bch_radius():
    """Each single-bit flip within the radius must still decode to version 15."""
    codeword = version_info_codeword(15)
    for bit in range(VERSION_INFO_MAX_ERRORS):
        decoded, distance = decode_version_information(codeword ^ (1 << bit))
        assert decoded == 15
        assert distance == 1

    # Cumulative damage up to the correction radius is still recovered.
    damaged = codeword
    for bit in range(VERSION_INFO_MAX_ERRORS):
        damaged ^= 1 << bit
    decoded, distance = decode_version_information(damaged)
    assert decoded == 15
    assert distance == VERSION_INFO_MAX_ERRORS


def test_beyond_the_radius_is_reported_unresolved():
    codeword = version_info_codeword(15)
    damaged = codeword ^ 0b1111  # 4 bit errors
    decoded, distance = decode_version_information(damaged)
    assert decoded is None, f"4-bit damage must not be 'corrected' (got v{decoded})"
    assert distance > VERSION_INFO_MAX_ERRORS


@pytest.mark.parametrize("version", [7, 10, 14, 18, 22])
def test_read_version_information_from_a_rendered_symbol(version):
    buf = io.BytesIO()
    segno.make(PUBLIC, version=version, error="m", boost_error=False).save(
        buf, kind="png", scale=10, border=0
    )
    buf.seek(0)
    with Image.open(buf) as handle:
        image = handle.convert("RGB")
        image.load()
    size = get_qr_dimension(version)
    assert image.size == (size * 10, size * 10)
    decoded, distance = read_version_information(image, size)
    assert decoded == version
    assert distance == 0


def test_version_information_absent_below_version_seven():
    buf = io.BytesIO()
    segno.make("HI", version=5, error="m", boost_error=False).save(
        buf, kind="png", scale=10, border=0
    )
    buf.seek(0)
    with Image.open(buf) as handle:
        image = handle.convert("RGB")
        image.load()
    decoded, distance = read_version_information(image, get_qr_dimension(5))
    assert decoded is None


# ── A. Client version hint handling ─────────────────────────────────────────


@pytest.mark.parametrize("offset", [-4, -2, 2, 4])
def test_wrong_client_version_hint_does_not_break_extraction(workdir, offset):
    out = os.path.join(workdir, "hint.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC, secret_text=SECRET, output_path=out, scale=10
    )
    with Image.open(out) as handle:
        width = handle.size[0]
    dimension = width // 10 - 2 * S.DEFAULT_BORDER
    true_version = (dimension - 17) // 4
    wrong = max(1, true_version + offset)

    public_data, secret = S.extract_from_qr_stego(
        out, client_version=wrong, return_diagnostics=False
    )
    assert public_data == PUBLIC
    assert secret == SECRET


def test_invalid_hint_outside_the_range_is_ignored(workdir):
    out = os.path.join(workdir, "bad_hint.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC, secret_text=SECRET, output_path=out, scale=10
    )
    public_data, secret = S.extract_from_qr_stego(out, client_version=99)
    assert public_data == PUBLIC
    assert secret == SECRET


def test_version_source_is_reported(workdir):
    out = os.path.join(workdir, "source.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC, secret_text=SECRET, output_path=out, scale=10
    )
    _, _, diag = S.extract_from_qr_stego(out, return_diagnostics=True)
    assert diag["version_source"] in (
        "bch_version_info",
        "timing_pattern",
        "timing_pattern_bch_conflict",
        "client_hint",
        "client_hint_only",
    )
    assert diag["alignment_score"] is not None
    assert 0.0 <= diag["alignment_score"] <= 1.0


# ── B. Geometry ─────────────────────────────────────────────────────────────


def _render(workdir, name="geo.png", scale=10):
    out = os.path.join(workdir, name)
    S.generate_qr_with_stego(
        public_data=PUBLIC, secret_text=SECRET, output_path=out, scale=scale
    )
    return out


@pytest.mark.parametrize("scale", [5, 6, 8, 10, 15, 20])
def test_extracts_across_module_pitches(workdir, scale):
    out = _render(workdir, f"pitch_{scale}.png", scale=scale)
    public_data, secret = S.extract_from_qr_stego(out)
    assert public_data == PUBLIC
    assert secret == SECRET


@pytest.mark.parametrize("angle", [5.0, 12.0, 20.0])
def test_extracts_under_rotation(workdir, angle):
    out = _render(workdir)
    with Image.open(out) as handle:
        rotated = handle.convert("RGB").rotate(
            angle, resample=Image.Resampling.BILINEAR, expand=True, fillcolor=(255, 255, 255)
        )
    rotated_path = os.path.join(workdir, f"rot_{int(angle)}.png")
    rotated.save(rotated_path)
    public_data, secret = S.extract_from_qr_stego(rotated_path)
    assert public_data == PUBLIC
    assert secret == SECRET


def _warp(image, fraction, resample):
    width, height = image.size
    inset = width * fraction
    return image.transform(
        (width, height),
        Image.Transform.QUAD,
        (inset, 0.0, 0.0, float(height), float(width), float(height), float(width) - inset, 0.0),
        resample=resample,
        fillcolor=(255, 255, 255),
    )


def test_extracts_under_mild_perspective(workdir):
    out = _render(workdir)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
    warped_path = os.path.join(workdir, "persp_mild.png")
    _warp(image, 0.02, Image.Resampling.BILINEAR).save(warped_path)
    public_data, secret = S.extract_from_qr_stego(warped_path)
    assert public_data == PUBLIC
    assert secret == SECRET


def test_extracts_under_three_percent_perspective(workdir):
    """Target 2: 3% perspective distortion must extract cleanly."""
    out = _render(workdir)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
    warped_path = os.path.join(workdir, "persp_03.png")
    _warp(image, 0.03, Image.Resampling.BILINEAR).save(warped_path)
    public_data, secret = S.extract_from_qr_stego(warped_path)
    assert public_data == PUBLIC
    assert secret == SECRET


def test_extracts_at_three_pixels_per_module(workdir):
    """Target 1: 3 px/module pitch must extract cleanly."""
    out = _render(workdir, scale=10)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
    w, h = image.size
    modules = w // 10
    target_dim = modules * 3
    downscaled = image.resize((target_dim, target_dim), Image.Resampling.LANCZOS)
    ppm3_path = os.path.join(workdir, "pitch_3ppm.png")
    downscaled.save(ppm3_path)
    public_data, secret = S.extract_from_qr_stego(ppm3_path)
    assert public_data == PUBLIC
    assert secret == SECRET


@pytest.mark.parametrize("fraction", [0.04, 0.06, 0.08])
def test_strong_perspective_never_returns_a_wrong_secret(workdir, fraction):
    """Geometry must not guess. Beyond the optical budget the payload may be lost,
    but it must never be reported as a different, wrong secret."""
    out = _render(workdir)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
    warped_path = os.path.join(workdir, f"persp_{int(fraction * 100)}.png")
    _warp(image, fraction, Image.Resampling.BILINEAR).save(warped_path)

    try:
        public_data, secret, diag = S.extract_from_qr_stego(warped_path, return_diagnostics=True)
    except S.QRStegoError as exc:
        assert exc.error_code in (
            S.QRErrorCode.QR_NOT_DETECTED,
            S.QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
            S.QRErrorCode.VISIBLE_PAYLOAD_DECODE_FAILED,
        )
        return

    if secret:
        assert secret == SECRET, "a wrong secret is never acceptable"
    else:
        assert diag["stage"] not in (None, "SUCCESS")


def test_extracts_small_qr_inside_a_large_photo(workdir):
    """A 300 px symbol in a 2400x1800 frame must still be found."""
    out = _render(workdir, scale=10)
    with Image.open(out) as handle:
        symbol = handle.convert("RGB")
    canvas = Image.new("RGB", (2400, 1800), (245, 245, 245))
    canvas.paste(symbol, (1500, 900))
    big_path = os.path.join(workdir, "small_in_big.png")
    canvas.save(big_path)

    public_data, secret = S.extract_from_qr_stego(big_path)
    assert public_data == PUBLIC
    assert secret == SECRET


# ── C. Confidence diagnostics ───────────────────────────────────────────────


def test_confidence_is_reported_but_not_used_for_fec(workdir):
    out = _render(workdir)
    _, _, diag = S.extract_from_qr_stego(out, return_diagnostics=True)
    confidence = diag.get("confidence")
    assert isinstance(confidence, dict)
    assert confidence["n"] > 0
    assert 0.0 <= confidence["mean"] <= 1.0
    assert 0.0 <= confidence["p10"] <= 1.0
    assert 0 <= confidence["uncertain"] <= confidence["n"]
    # No erasure machinery was added: the extractor still calls plain RSCodec.
    import inspect

    source = inspect.getsource(S)
    assert "erase_pos" not in source, "Phase 2 must not claim erasure decoding"


# ── D. Failure-stage taxonomy ───────────────────────────────────────────────


def test_missing_qr_reports_detection_stage(workdir):
    blank = os.path.join(workdir, "blank.png")
    Image.new("RGB", (300, 300), (255, 255, 255)).save(blank)
    with pytest.raises(S.QRStegoError) as ctx:
        S.extract_from_qr_stego(blank)
    assert ctx.value.error_code is S.QRErrorCode.QR_NOT_DETECTED


def test_damaged_version_area_reports_unresolved(workdir):
    """Painting over both version blocks must not silently guess a version."""
    out = _render(workdir)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
    width = image.size[0]
    dimension = width // 10 - 2 * S.DEFAULT_BORDER
    scale = width // (dimension + 2 * S.DEFAULT_BORDER)
    offset = S.DEFAULT_BORDER * scale
    # Cover the top-right and bottom-left version blocks with mid-grey noise.
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    tr_x = offset + (dimension - 11) * scale
    draw.rectangle(
        [tr_x, offset, offset + (dimension - 8) * scale - 1, offset + 6 * scale - 1],
        fill=(128, 128, 128),
    )
    bl_y = offset + (dimension - 11) * scale
    draw.rectangle(
        [offset, bl_y, offset + 6 * scale - 1, offset + (dimension - 8) * scale - 1],
        fill=(128, 128, 128),
    )
    damaged_path = os.path.join(workdir, "damaged_version.png")
    image.save(damaged_path)

    try:
        public_data, secret = S.extract_from_qr_stego(damaged_path, return_diagnostics=False)
    except S.QRStegoError:
        return
    # If it still decodes, it must not have produced a wrong secret.
    assert secret in ("", SECRET)


def test_plain_qr_without_payload_is_not_an_error(workdir):
    plain = os.path.join(workdir, "plain.png")
    segno.make(PUBLIC, error="m").save(plain, scale=10, border=4)
    public_data, secret = S.extract_from_qr_stego(plain)
    assert public_data == PUBLIC
    assert secret == ""


# ── E. Legacy v1 compatibility through the image path ───────────────────────


def test_legacy_v1_container_still_extracts_from_an_image(workdir):
    out = os.path.join(workdir, "v1.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC,
        secret_text=SECRET,
        output_path=out,
        password=PASSWORD,
        scale=10,
    )
    public_data, secret = S.extract_from_qr_stego(out, password=PASSWORD)
    assert public_data == PUBLIC
    assert secret == SECRET
