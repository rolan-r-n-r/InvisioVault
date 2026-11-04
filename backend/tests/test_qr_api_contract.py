"""Phase 1 contract tests: exact payloads, colour validation, self-check,
capacity honesty, and scan error classification.

These are fast, function- and route-level checks. The photo-realistic matrix
lives in ``test_qr_regression.py``; this file pins the API contract.
"""

from __future__ import annotations

import base64
import io
import os
import shutil
import tempfile

import pytest
import segno
from PIL import Image
from unittest.mock import patch

from app import create_app
from extensions import limiter
from utils import qr_stego as S
from utils.qr_container import pack_qr_container, unpack_qr_container
from utils.validators import (
    MIN_QR_LUMA_DELTA,
    qr_contrast_ratio,
    validate_qr_colors,
)

PUBLIC = "https://invisiovault.com"
PASSWORD = "fixture-correct-horse-battery"


@pytest.fixture(scope="module")
def app():
    application = create_app("development")
    application.config.update(TESTING=True)
    limiter.reset()
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture()
def workdir():
    path = tempfile.mkdtemp(prefix="iv_qr_phase1_")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _generate(client, **fields):
    payload = {"public_data": PUBLIC, "secret_text": "s", "method": "visual"}
    payload.update(fields)
    return client.post("/api/qr/generate", data=payload)


def _stored_path(app, download_id):
    return os.path.join(app.config["UPLOAD_FOLDER"], download_id)


# ── B. Exact payload preservation ───────────────────────────────────────────


@pytest.mark.parametrize(
    "secret",
    [
        "  leading and trailing  ",
        "\tTabbed\nNewline\r\nEnd\t",
        "emoji \U0001f512\U0001f680 and CJK \u4f60\u597d",
        "zero width\u200bspace and nbsp\u00a0end",
        "a",
        " " * 3 + "middle" + " " * 3,
    ],
    ids=["spaces", "control", "unicode", "zero-width", "single", "padded"],
)
def test_secret_roundtrip_is_byte_exact(workdir, secret, monkeypatch):
    monkeypatch.setenv("QR_SELF_CHECK", "true")
    out = os.path.join(workdir, "exact.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC,
        secret_text=secret,
        output_path=out,
        password=PASSWORD,
        scale=10,
    )
    public_data, extracted = S.extract_from_qr_stego(out, password=PASSWORD)
    assert public_data == PUBLIC
    assert extracted == secret
    assert extracted.encode("utf-8") == secret.encode("utf-8")


def test_route_preserves_whitespace(client, app):
    secret = "  spaced secret  "
    response = _generate(client, secret_text=secret, password=PASSWORD)
    assert response.status_code == 200, response.get_json()
    path = _stored_path(app, response.get_json()["download_id"])
    try:
        _, extracted = S.extract_from_qr_stego(path, password=PASSWORD)
        assert extracted == secret
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_all_whitespace_secret_is_rejected(client):
    response = _generate(client, secret_text="   \t\n ")
    assert response.status_code == 400
    assert "required" in response.get_json()["error"].lower()


def test_ivqr_v1_container_format_is_unchanged():
    """Phase 1 must not alter the v1 container or its legacy stream path."""
    secret = "legacy v1 payload \u4f60\u597d"
    container = pack_qr_container(secret, PASSWORD)
    assert container[:4] == b"IVQR"
    assert container[4] == 1, "container version must stay 1"
    assert unpack_qr_container(container, PASSWORD) == secret

    # Legacy #IVDATA: payloads are base64(container) and must still decode.
    encoded = base64.urlsafe_b64encode(container).decode("ascii")
    assert S._decode_payload(encoded, PASSWORD) == secret

    # Plain (unencrypted) v1 containers must also decode unchanged.
    plain = pack_qr_container(secret, None)
    assert unpack_qr_container(plain, None) == secret
    assert S._decode_payload(base64.urlsafe_b64encode(plain).decode("ascii"), None) == secret


# ── C. Colour validation ────────────────────────────────────────────────────


def test_pre_filter_rejects_inverted_colors():
    ok, reason = validate_qr_colors("#FFFFFF", "#000000")
    assert not ok
    assert "darker" in reason.lower()


def test_pre_filter_rejects_low_luminance_gap():
    ok, reason = validate_qr_colors("#777777", "#888888")
    assert not ok
    assert str(int(MIN_QR_LUMA_DELTA)) in reason


def test_pre_filter_accepts_black_on_white():
    ok, reason = validate_qr_colors("#000000", "#FFFFFF")
    assert ok and reason is None


def test_mid_grey_passes_pre_filter_but_is_caught_by_self_check(client, app):
    """#AAAAAA on white is ~85 luma apart, so arithmetic alone cannot reject it.

    Invariant: the endpoint must never return 200 for an image zxing cannot read.
    """
    response = _generate(client, fg_color="#AAAAAA", bg_color="#FFFFFF")
    if response.status_code == 200:
        path = _stored_path(app, response.get_json()["download_id"])
        try:
            import zxingcpp

            with Image.open(path) as handle:
                results = zxingcpp.read_barcodes(handle.convert("RGB"))
            assert results and results[0].text == PUBLIC, (
                "generation returned success but the output is not scannable"
            )
        finally:
            if os.path.exists(path):
                os.remove(path)
    else:
        assert response.get_json().get("failureReason") in (
            "UNSCANNABLE_COLORS",
            "GENERATION_SELF_CHECK_FAILED",
        )


def test_green_on_white_is_not_rejected(client):
    """Low WCAG contrast but genuinely scannable: must not be rejected on paper."""
    response = _generate(client, fg_color="#00FF00", bg_color="#FFFFFF")
    assert response.status_code == 200, response.get_json()


def test_capacity_contrast_ratio_is_advisory_only():
    assert qr_contrast_ratio("#00FF00", "#FFFFFF") < 4.5
    assert validate_qr_colors("#00FF00", "#FFFFFF")[0] is True


# ── D. Generation self-check ────────────────────────────────────────────────


def test_self_check_failure_deletes_the_output(workdir, monkeypatch):
    monkeypatch.setenv("QR_SELF_CHECK", "true")
    out = os.path.join(workdir, "discarded.png")
    with patch.object(
        S,
        "_self_check_generated_qr",
        side_effect=S.QRStegoError("forced", S.QRErrorCode.GENERATION_SELF_CHECK_FAILED),
    ):
        with pytest.raises(S.QRStegoError):
            S.generate_qr_with_stego(
                public_data=PUBLIC, secret_text="secret", output_path=out, scale=10
            )
    assert not os.path.exists(out), "a failed self-check must not leave the file behind"


def test_self_check_can_be_disabled_for_diagnostics(workdir, monkeypatch):
    monkeypatch.setenv("QR_SELF_CHECK", "false")
    calls = []
    out = os.path.join(workdir, "unchecked.png")
    with patch.object(S, "_self_check_generated_qr", side_effect=lambda *a, **k: calls.append(1)):
        S.generate_qr_with_stego(
            public_data=PUBLIC, secret_text="secret", output_path=out, scale=10
        )
    assert calls == []
    assert os.path.exists(out)


def test_self_check_rejects_a_tampered_payload(workdir, monkeypatch):
    """If the extractor cannot reproduce the secret exactly, generation must fail."""
    monkeypatch.setenv("QR_SELF_CHECK", "true")
    out = os.path.join(workdir, "mismatch.png")
    real_extract = S.extract_from_qr_stego

    def _lossy_extract(qr_path, password=None, **kwargs):
        public_data, secret = real_extract(qr_path, password=password, **kwargs)
        return public_data, secret.rstrip()

    with patch.object(S, "extract_from_qr_stego", side_effect=_lossy_extract):
        with pytest.raises(S.QRStegoError) as ctx:
            S.generate_qr_with_stego(
                public_data=PUBLIC,
                secret_text="trailing space ",
                output_path=out,
                scale=10,
            )
    assert ctx.value.error_code is S.QRErrorCode.GENERATION_SELF_CHECK_FAILED
    assert not os.path.exists(out)


# ── E. Capacity ─────────────────────────────────────────────────────────────


def _dark_safe_modules(public_data: str) -> int:
    safe = S.get_safe_data_modules(S.MAX_SAFE_QR_VERSION)
    probe = segno.make(
        public_data, version=S.MAX_SAFE_QR_VERSION, error="m", boost_error=False
    )
    return sum(1 for (r, c) in safe if probe.matrix[r][c] == 1)


def test_capacity_is_computed_not_a_fixed_constant():
    info = S.get_qr_capacity_info(PUBLIC)
    assert info["capacityBasis"] == "computed-uncompressed-max-at-v22"
    assert info["publicDataFits"] is True
    # The old endpoint returned a hardcoded 1102 for every public payload.
    assert info["safeCapacityBytes"] != 1102


def test_capacity_boundary_is_exact_for_both_modes():
    dark = _dark_safe_modules(PUBLIC)
    for password in (None, PASSWORD):
        limit = S._max_secret_bytes(dark, password)
        assert limit > 0
        assert S._fec_bits_for_secret(limit, password) <= dark
        assert S._fec_bits_for_secret(limit + 1, password) > dark


def test_capacity_report_matches_the_arithmetic():
    info = S.get_qr_capacity_info(PUBLIC)
    dark = _dark_safe_modules(PUBLIC)
    assert info["plainMaxBytes"] == S._max_secret_bytes(dark, None)
    assert info["encryptedMaxBytes"] == S._max_secret_bytes(dark, PASSWORD)
    assert info["encryptedMaxBytes"] <= info["plainMaxBytes"]
    assert info["allSafePlainMaxBytes"] >= info["plainMaxBytes"]
    assert info["allSafeEncryptedMaxBytes"] <= info["allSafePlainMaxBytes"]


def test_capacity_is_zero_when_public_data_cannot_fit():
    info = S.get_qr_capacity_info("x" * 20000)
    assert info["publicDataFits"] is False
    assert info["safeCapacityBytes"] == 0


def test_capacity_endpoint_shape(client):
    response = client.post("/api/qr/capacity", data={"public_data": PUBLIC, "scale": 10})
    assert response.status_code == 200
    body = response.get_json()
    for key in (
        "safeCapacityBytes",
        "plainMaxBytes",
        "encryptedMaxBytes",
        "allSafePlainMaxBytes",
        "allSafeEncryptedMaxBytes",
        "capacityBasis",
        "publicDataFits",
        "maxSafeVersion",
    ):
        assert key in body, key
    assert body["encryptedMaxBytes"] <= body["plainMaxBytes"]


def _incompressible_secret(n_bytes: int) -> str:
    """Exactly ``n_bytes`` of UTF-8 that zlib cannot meaningfully shrink.

    Random CJK code points are 3 bytes each; the remainder is ASCII. A run of a
    repeated character would compress to a few bytes and defeat the boundary.
    """
    import random

    rnd = random.Random(7)
    chars = []
    used = 0
    while used + 3 <= n_bytes:
        chars.append(chr(rnd.randrange(0x4E00, 0x9F00)))
        used += 3
    chars.append("x" * (n_bytes - used))
    return "".join(chars)


def test_reported_capacity_is_achievable_at_the_boundary(workdir):
    """The advertised encrypted limit must actually embed and round-trip."""
    info = S.get_qr_capacity_info(PUBLIC)
    limit = info["encryptedMaxBytes"]
    assert limit > 0
    secret = _incompressible_secret(limit)
    assert len(secret.encode("utf-8")) == limit

    out = os.path.join(workdir, "at-limit.png")
    S.generate_qr_with_stego(
        public_data=PUBLIC,
        secret_text=secret,
        output_path=out,
        password=PASSWORD,
        scale=10,
    )
    _, extracted = S.extract_from_qr_stego(out, password=PASSWORD)
    assert extracted == secret


def test_generation_beyond_reported_capacity_is_refused(workdir):
    """Beyond the all-safe v22 ceiling nothing can fit, compressed or not."""
    info = S.get_qr_capacity_info(PUBLIC)
    secret = _incompressible_secret(info["allSafeEncryptedMaxBytes"] + 300)
    out = os.path.join(workdir, "too-big.png")
    with pytest.raises(S.QRStegoError) as ctx:
        S.generate_qr_with_stego(
            public_data=PUBLIC,
            secret_text=secret,
            output_path=out,
            password=PASSWORD,
            scale=10,
        )
    assert ctx.value.error_code is S.QRErrorCode.CAPACITY_EXCEEDED
    assert not os.path.exists(out)


# ── F. Scan error classification ────────────────────────────────────────────


def _png_bytes(color=(255, 255, 255)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color).save(buf, "PNG")
    return buf.getvalue()


def _post_scan(client, image_bytes, **form):
    data = {"image": (io.BytesIO(image_bytes), "capture.png")}
    data.update(form)
    return client.post("/api/qr/scan", data=data, content_type="multipart/form-data")


def test_damaged_payload_is_not_reported_as_a_successful_scan(client):
    def _fake(qr_path, password=None, raw_qr_text=None, client_corners=None,
              client_version=None, debug_info=None):
        if debug_info is not None:
            debug_info["ivqrMagicDetected"] = True
            debug_info["failureReason"] = "PAYLOAD_DECODE_FAILED"
        return PUBLIC, ""

    with patch("api.routes.extract_from_qr_stego", side_effect=_fake):
        response = _post_scan(client, _png_bytes((250, 250, 250)))
    assert response.status_code == 422
    body = response.get_json()
    assert body["damaged"] is True
    assert body["failureReason"] == "PAYLOAD_DECODE_FAILED"
    assert body.get("success") is False


def test_plain_qr_is_reported_as_no_hidden_payload(client):
    def _fake(qr_path, password=None, raw_qr_text=None, client_corners=None,
              client_version=None, debug_info=None):
        if debug_info is not None:
            debug_info["failureReason"] = "NO_HIDDEN_DATA"
        return PUBLIC, ""

    with patch("api.routes.extract_from_qr_stego", side_effect=_fake):
        response = _post_scan(client, _png_bytes((240, 240, 240)))
    assert response.status_code == 200
    body = response.get_json()
    assert body["publicData"] == PUBLIC
    assert body["secretData"] == ""
    assert body.get("damaged") is not True


def test_unsupported_format_is_classified_not_generic(client):
    def _raise(*args, **kwargs):
        raise S.QRStegoError("legacy scheme", error_code=S.QRErrorCode.UNSUPPORTED_VERSION)

    with patch("api.routes.extract_from_qr_stego", side_effect=_raise):
        response = _post_scan(client, _png_bytes((230, 230, 230)))
    assert response.status_code == 400
    assert response.get_json()["failureReason"] == "UNSUPPORTED_VERSION"


def test_missing_qr_is_classified(client):
    def _raise(*args, **kwargs):
        raise S.QRStegoError("no qr", error_code=S.QRErrorCode.QR_NOT_DETECTED)

    with patch("api.routes.extract_from_qr_stego", side_effect=_raise):
        response = _post_scan(client, _png_bytes((220, 220, 220)))
    assert response.status_code == 400
    assert response.get_json()["failureReason"] == "QR_NOT_DETECTED"


# ── A. Frontend capture contract (static) ───────────────────────────────────


def test_frontend_payload_path_has_no_blur_or_upscale():
    """Guard the exact regression: the client used to upscale then blur the crop."""
    source_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), "..", "..", "frontend", "src", "hooks", "useQRScanner.js"
        )
    )
    if not os.path.exists(source_path):
        pytest.skip("frontend sources are not present in this checkout")
    with open(source_path, "r", encoding="utf-8") as handle:
        source = handle.read()

    assert "blur(1.0px)" not in source, "payload capture must not blur the image"
    assert "MIN_OUTPUT_SIZE = 450" not in source, "payload capture must not upscale"
