"""Phase 3 modulation tests.

Covers the encoder-side light-channel policy, the palette/state-separation
guard, the 1-pixel inset invariant, multi-decoder public readability, and the
optical behaviour the change exists to fix (over-exposed light-module carriers).

The committed Phase 0 fixtures are deliberately *not* re-rendered: they are the
legacy-encoder corpus and remain the backward-compatibility check.
"""

from __future__ import annotations

import os

import pytest
from PIL import Image

from tests import qr_harness as H
from utils import qr_stego as S

PUBLIC = H.DEFAULT_PUBLIC
SMALL = H.build_secret("small")
LARGE = H.build_secret("large")
PASSWORD = H.FIXTURE_PASSWORD


@pytest.fixture()
def workdir(tmp_path):
    return str(tmp_path)


def _render(workdir, name, secret=SMALL, password=None, scale=20, **kwargs):
    out = os.path.join(workdir, name)
    S.generate_qr_with_stego(
        public_data=PUBLIC,
        secret_text=secret,
        output_path=out,
        password=password,
        scale=scale,
        method="visual",
        **kwargs,
    )
    return out


def _rgb_at(image: Image.Image, x: int, y: int):
    return image.getpixel((int(x), int(y)))[:3]


# ── A. Policy ────────────────────────────────────────────────────────────────


def test_phase3_policy_changes_only_the_light_step():
    """The measured win is the light channel; dark keeps its shipped value."""
    dark, light = S._modulation_deltas((0, 0, 0), (255, 255, 255), True)
    assert dark == S.DARK_MODULATION_DELTA == 50
    assert light == S.ADAPTIVE_LIGHT_DELTA == 72


def test_legacy_policy_is_byte_reproducible():
    """Passing adaptive=False must still reproduce the pre-Phase-3 constants."""
    assert S._modulation_deltas((0, 0, 0), (255, 255, 255), False) == (50, 40)


def test_palette_cap_bounds_the_light_step():
    """A low-headroom palette must not receive the full 72-luma step."""
    dark, light = S._modulation_deltas((0x55, 0x55, 0x55), (0xEE, 0xEE, 0xEE), True)
    assert dark == 50
    assert S.MODULATION_LIGHT_FLOOR <= light < S.ADAPTIVE_LIGHT_DELTA
    assert (
        S._modulation_state_separation(
            (0x55, 0x55, 0x55), (0xEE, 0xEE, 0xEE), dark, light
        )
        >= S.MIN_MODULATION_STATE_SEPARATION
    )


def test_state_separation_is_the_binding_constraint():
    """#AAAAAA on white cannot host two modulation states; it must be refused."""
    with pytest.raises(S.QRStegoError) as ctx:
        S._embed_visual_qr(
            public_data=PUBLIC,
            secret_text=SMALL,
            output_path=os.path.join(os.devnull, "never.png"),
            fg_color="#AAAAAA",
            bg_color="#FFFFFF",
        )
    assert ctx.value.error_code is S.QRErrorCode.UNSCANNABLE_COLORS


# ── B. Pixel footprint ───────────────────────────────────────────────────────


def test_one_pixel_inset_survives_on_dark_and_light_carriers(workdir):
    """The module border is never modulated; only the interior carries a bit."""
    out = _render(workdir, "footprint.png", secret=LARGE)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
        image.load()
        width = image.size[0]
    dimension = width // 20 - 2 * S.DEFAULT_BORDER
    version = (dimension - 17) // 4
    assert version >= 7, "expected a light-spilling payload"

    bit_count = H.carrier_bit_count(LARGE, None)
    modules, is_dark = H.module_carrier_map(PUBLIC, version, bit_count)
    offset = S.DEFAULT_BORDER * 20
    dark_interiors = set()
    light_interiors = set()

    for module, dark in zip(modules, is_dark):
        row, col = module
        x0 = offset + col * 20
        y0 = offset + row * 20
        border = _rgb_at(image, x0, y0)
        interior = _rgb_at(image, x0 + 1, y0 + 1)
        if dark:
            assert border == (0, 0, 0), (module, border)
            dark_interiors.add(interior)
        else:
            assert border == (255, 255, 255), (module, border)
            light_interiors.add(interior)

    assert dark_interiors <= {(0, 0, 0), (50, 50, 50)}, dark_interiors
    assert (50, 50, 50) in dark_interiors
    assert light_interiors <= {(255, 255, 255), (183, 183, 183)}, light_interiors
    assert (183, 183, 183) in light_interiors, (
        "the large payload must spill into the light channel, and that channel "
        "must carry the 72-luma step"
    )


# ── C. Optical behaviour ─────────────────────────────────────────────────────


def test_overexposed_light_channel_roundtrips_exactly(workdir):
    """The regression this phase fixes: +20% exposure used to erase light bits.

    A 696-byte secret needs light carrier modules, whose 40-luma step was
    clipped back onto the 255 background (255 -> 215 -> 258 -> 255). The 72-luma
    step leaves 183 -> 220, which the extractor can still separate.
    """
    out = _render(workdir, "exposed.png", secret=LARGE)
    with Image.open(out) as handle:
        base = handle.convert("RGB")
        base.load()
    exposed = H.degrade(base, 8, source_ppm=20, exposure=1.2, noise_sigma=2.0, seed=11)
    result = H.run_extract(exposed)
    assert result.outcome == "success", result.as_dict()
    assert result.secret_text == LARGE


@pytest.mark.parametrize(
    "fg,bg",
    [
        ("#000000", "#FFFFFF"),
        ("#003366", "#FFFFFF"),
        ("#000000", "#FFFF00"),
        ("#555555", "#EEEEEE"),
    ],
)
def test_public_qr_stays_readable_with_independent_decoders(workdir, fg, bg):
    out = _render(workdir, f"palette_{fg[1:]}.png", secret=SMALL, fg_color=fg, bg_color=bg)
    with Image.open(out) as handle:
        image = handle.convert("RGB")
        image.load()

    import zxingcpp

    results = zxingcpp.read_barcodes(image)
    assert results and results[0].text == PUBLIC, (fg, bg)

    # The pure detector is a stricter path: on the low-contrast palettes in this
    # matrix it returns a barcode with empty text, and it does so for the
    # pre-Phase-3 encoder too (measured legacy vs adaptive, same output). Empty is
    # a detector miss, not a misread; a *wrong* public text never is acceptable.
    pure = zxingcpp.read_barcodes(image, is_pure=True)
    if pure:
        assert pure[0].text in (PUBLIC, ""), (fg, bg, pure[0].text)

    try:
        from pyzbar import pyzbar
    except (ImportError, OSError):  # pragma: no cover - optional decoder
        pyzbar = None
    if pyzbar is not None:
        decoded = pyzbar.decode(image)
        if decoded:  # pyzbar is known to miss some valid symbols; never a hard gate
            assert decoded[0].data.decode("utf-8") == PUBLIC, (fg, bg)

    public_data, secret = S.extract_from_qr_stego(out)
    assert public_data == PUBLIC
    assert secret == SMALL


def test_green_on_white_is_still_accepted(workdir):
    """Low WCAG contrast but genuinely scannable: the policy must not reject it."""
    out = _render(workdir, "green.png", fg_color="#00FF00", bg_color="#FFFFFF")
    public_data, secret = S.extract_from_qr_stego(out)
    assert public_data == PUBLIC and secret == SMALL


# ── D. Retention ─────────────────────────────────────────────────────────────


def test_phase0_marginal_band_is_retained_and_healthy_cells_stay_healthy():
    """3 px/module fixtures stay in the matrix; 8 px/module must stay 8/8.

    Phase 3 may change their outcome, but it may not delete them, retire the
    band, or let a healthy cell regress.
    """
    if not os.path.exists(H.BASELINE_PATH):
        pytest.skip("Optional research baseline qr_baseline.json not present in repository")
    baseline = H.read_baseline()
    rows = baseline["fixtures"]

    ppm3 = [r for r in rows.values() if r["degradations"]["px_per_module"] == 3]
    assert len(ppm3) == 8, "the 3 px/module marginal band must remain in the matrix"

    ppm8 = [r for r in rows.values() if r["degradation"] == "ppm8"]
    assert len(ppm8) == 8
    assert all(r["outcome"] == "success" for r in ppm8), [
        (r["id"], r["outcome"]) for r in ppm8 if r["outcome"] != "success"
    ]
