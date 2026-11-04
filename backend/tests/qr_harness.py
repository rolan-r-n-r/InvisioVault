"""QR steganography measurement harness (implementation plan Phase 0).

Test-only infrastructure. It changes no production behaviour. It provides
deterministic fixture rendering, camera-like degradation, extraction with
diagnostics, channel bit-error measurement, and the statistics needed to make
release-evidence claims (Wilson intervals, minimum sample sizes).

Design notes
------------
* Fixtures are **synthetic**. Real captures must never be committed: they
  contain real secrets and public URLs. See ``qr_fixtures/README.md``.
* Secrets are never stored in the manifest, only their SHA-256. The plaintext is
  regenerated deterministically from the fixture description.
* BER is measured with a **channel-model probe**: module interiors are sampled
  in module space and classified per polarity with a 1-D two-cluster split. The
  *clean render* is the reference, so the probe needs no knowledge of the
  encrypted container bytes (Fernet uses a random salt/IV and is not
  reproducible, though its output *length* is).
* ``module_carrier_map`` mirrors the module ordering in
  ``utils.qr_stego._embed_visual_qr``. It is not trusted on faith: a test
  requires BER == 0 on a clean render, and the clean render must also extract
  successfully. Phase 3/4 should replace this mirror with encoder-emitted
  diagnostics.

Nothing in this module is imported by production code.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, BACKEND_DIR)

import segno  # noqa: E402

from utils import qr_stego  # noqa: E402
from utils.qr_container import pack_qr_container  # noqa: E402
from utils.qr_module_map import deterministic_permute, get_safe_data_modules  # noqa: E402

# ── Layout ────────────────────────────────────────────────────────────────────

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURE_ROOT = os.path.join(TESTS_DIR, "qr_fixtures")
PNG_DIR = os.path.join(FIXTURE_ROOT, "png")
MANIFEST_PATH = os.path.join(FIXTURE_ROOT, "manifest.json")
BASELINE_PATH = os.path.join(TESTS_DIR, "qr_baseline.json")
REFERENCE_PATH = os.path.join(TESTS_DIR, "qr_reference_phase3.json")
SHA256_PATH = os.path.join(FIXTURE_ROOT, "fixture_png_sha256.json")

DEFAULT_PUBLIC = "https://invisiovault.com"
DEFAULT_BORDER: int = qr_stego.DEFAULT_BORDER           # 4 modules
DEFAULT_SCALE: int = 20
MAX_VERSION: int = qr_stego.MAX_SAFE_QR_VERSION         # 22
ECC_LEVEL: str = "m"

# Fixture password. Not a secret: it exists only so encrypted-path fixtures are
# reproducible. Manifests reference it by name instead of storing it.
FIXTURE_PASSWORD = "fixture-correct-horse-battery"
FIXTURE_PASSWORD_REF = "FIXTURE_PASSWORD"

MANIFEST_SCHEMA = 1
BASELINE_SCHEMA = 1

# Minimum luma spread inside one polarity class before we trust a BER reading.
MIN_CLASS_SEPARATION = 6.0
MIN_CLASS_MEMBERS = 8


# ── Statistics ────────────────────────────────────────────────────────────────


def wilson_interval(successes: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Two-sided Wilson score interval for a binomial proportion.

    Unlike the normal approximation it behaves correctly at 0% and 100%, which
    is exactly where the reliability targets live.
    """
    if n <= 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1.0 + (z * z) / n
    centre = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) / n) + (z * z) / (4.0 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def sample_size_for_proportion(p: float = 0.95, margin: float = 0.05, z: float = 1.96) -> int:
    """Samples needed to estimate a proportion ``p`` within ``margin`` (95% z)."""
    if margin <= 0:
        raise ValueError("margin must be positive")
    n = (z * z * p * (1.0 - p)) / (margin * margin)
    return int(math.ceil(n))


def zero_failure_samples(confidence: float = 0.95, failure_rate: float = 0.01) -> int:
    """Samples needed to justify a zero-failure claim (rule of three, exact)."""
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if not 0.0 < failure_rate < 1.0:
        raise ValueError("failure_rate must be in (0, 1)")
    return int(math.ceil(math.log(1.0 - confidence) / math.log(1.0 - failure_rate)))


def bit_error_rate(
    expected: "Sequence[int] | Dict[Any, int]",
    sampled: "Sequence[int] | Dict[Any, int]",
) -> float:
    """Fraction of differing bits between two equal-length bit sequences.

    Dicts are compared by key so a caller can align bits by module coordinate.
    Length/key mismatches raise instead of silently scoring a prefix, because a
    silent prefix comparison would understate the error rate.
    """
    if isinstance(expected, dict) or isinstance(sampled, dict):
        if not isinstance(expected, dict) or not isinstance(sampled, dict):
            raise TypeError("expected and sampled must both be dicts or both be sequences")
        if set(expected) != set(sampled):
            raise ValueError("bit alignment mismatch: key sets differ")
        if not expected:
            return 0.0
        wrong = sum(1 for k in expected if expected[k] != sampled[k])
        return wrong / len(expected)

    exp = list(expected)
    got = list(sampled)
    if len(exp) != len(got):
        raise ValueError(f"bit alignment mismatch: {len(exp)} expected vs {len(got)} sampled")
    if not exp:
        return 0.0
    return sum(1 for a, b in zip(exp, got) if a != b) / len(exp)


# ── Fixture payloads ──────────────────────────────────────────────────────────


def build_secret(payload_class: str) -> str:
    """Deterministic secret text for a payload class.

    ``medium``/``large`` use random CJK code points (3 UTF-8 bytes each, near
    incompressible) so the fixtures exercise the worst case for capacity.
    ``small`` is realistic short ASCII text.
    """
    if payload_class == "small":
        return "VaultKey9"
    if payload_class == "medium":
        return _random_text(100, seed=11)
    if payload_class == "large":
        return _random_text(232, seed=29)
    raise ValueError(f"unknown payload class: {payload_class}")


def _random_text(n_chars: int, seed: int) -> str:
    rnd = random.Random(seed)
    # 0x4E00-0x9EFF are valid CJK unified ideographs; each is 3 UTF-8 bytes.
    return "".join(chr(rnd.randrange(0x4E00, 0x9F00)) for _ in range(n_chars))


def secret_utf8_bytes(payload_class: str) -> int:
    return len(build_secret(payload_class).encode("utf-8"))


# ── Rendering ─────────────────────────────────────────────────────────────────


@dataclass
class RenderedQR:
    image: Image.Image
    version: int
    dimension: int
    scale: int
    border: int
    public_data: str
    secret: str
    password: Optional[str]
    path: Optional[str] = None

    @property
    def px_per_module(self) -> float:
        return float(self.scale)


def render_stego(
    secret: str,
    public_data: str = DEFAULT_PUBLIC,
    password: Optional[str] = None,
    scale: int = DEFAULT_SCALE,
    version_policy: str = "current",
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    border: int = DEFAULT_BORDER,
    out_path: Optional[str] = None,
) -> RenderedQR:
    """Render a steganographic QR with the current production encoder.

    ``version_policy`` accepts only ``current``/``auto`` in Phase 0. Explicit
    ``camera``/``max``/``balanced`` modes arrive in Phase 3; asking for them now
    raises instead of silently pretending to honour them.
    """
    if version_policy not in ("current", "auto"):
        raise NotImplementedError(
            f"version_policy={version_policy!r} is not implemented until Phase 3; "
            "Phase 0 fixtures record the existing selector's output."
        )

    tmp_dir = None
    if out_path is None:
        tmp_dir = tempfile.mkdtemp(prefix="iv_qr_render_")
        out_path = os.path.join(tmp_dir, "render.png")
    else:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    try:
        qr_stego.generate_qr_with_stego(
            public_data=public_data,
            secret_text=secret,
            output_path=out_path,
            password=password,
            fg_color=fg_color,
            bg_color=bg_color,
            scale=scale,
            method="visual",
        )
        with Image.open(out_path) as handle:
            image = handle.convert("RGB")
            image.load()

        width = image.size[0]
        if image.size[1] != width:
            raise ValueError(f"expected a square QR image, got {image.size}")
        dimension = width // scale - 2 * border
        if dimension < 21 or (dimension - 17) % 4 != 0:
            raise ValueError(
                f"cannot derive QR version from {width}px at scale {scale}: dimension={dimension}"
            )
        version = (dimension - 17) // 4
        return RenderedQR(
            image=image,
            version=version,
            dimension=dimension,
            scale=scale,
            border=border,
            public_data=public_data,
            secret=secret,
            password=password,
            path=out_path,
        )
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def estimate_px_per_module(img: Image.Image, border: int = DEFAULT_BORDER) -> Optional[float]:
    """Estimate module pitch from the top-left finder pattern.

    Only valid for axis-aligned images that still contain a quiet zone. Returns
    ``None`` when the pattern cannot be found, rather than guessing.
    """
    arr = np.asarray(img.convert("L"), dtype=np.float64)
    lo = float(np.percentile(arr, 1))
    hi = float(np.percentile(arr, 99))
    if hi - lo < 20.0:
        return None
    thr = (lo + hi) / 2.0
    dark = arr < thr
    rows = np.where(dark.any(axis=1))[0]
    if rows.size == 0:
        return None
    r0 = int(rows[0])
    cols = np.where(dark[r0])[0]
    if cols.size < 7:
        return None
    run = 0
    c = int(cols[0])
    while c < dark.shape[1] and dark[r0, c]:
        run += 1
        c += 1
    if run < 7:
        return None
    return round(run / 7.0, 3)


# ── Degradation ───────────────────────────────────────────────────────────────


def jpeg_roundtrip(img: Image.Image, quality: int) -> Image.Image:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=int(quality), subsampling=0)
    buf.seek(0)
    with Image.open(buf) as handle:
        out = handle.convert("RGB")
        out.load()
    return out


def _apply_perspective(img: Image.Image, amount: float) -> Image.Image:
    """Mild trapezoid warp: the top edge is narrowed by ``amount`` of the width."""
    if amount <= 0:
        return img
    w, h = img.size
    dx = float(amount) * w
    quad = (dx, 0.0, 0.0, float(h), float(w), float(h), float(w) - dx, 0.0)
    return img.transform(
        (w, h),
        Image.Transform.QUAD,
        quad,
        resample=Image.Resampling.BILINEAR,
        fillcolor=(255, 255, 255),
    )


def degrade(
    img: Image.Image,
    px_per_module: Optional[float] = None,
    *,
    source_ppm: Optional[float] = None,
    blur_sigma: float = 0.0,
    exposure: float = 1.0,
    noise_sigma: float = 0.0,
    jpeg_quality: Optional[int] = None,
    rotation_deg: float = 0.0,
    perspective: float = 0.0,
    seed: int = 0,
    resample: Any = Image.Resampling.LANCZOS,
    blur_before_resize: bool = False,
) -> Image.Image:
    """Apply a deterministic camera-like degradation chain.

    Order models the optical path: geometry (distance) -> defocus -> exposure ->
    orientation -> perspective -> sensor JPEG. ``blur_before_resize`` exists so a
    caller can reproduce the legacy test order, which the real client did not
    use (RC-02).
    """
    work = img.convert("RGB")
    ppm0 = source_ppm if source_ppm is not None else estimate_px_per_module(work)
    if ppm0 is None:
        raise ValueError("cannot determine source pixels-per-module; pass source_ppm")

    if px_per_module is not None and abs(float(px_per_module) - ppm0) > 1e-6:
        factor = float(px_per_module) / float(ppm0)
        if blur_before_resize and blur_sigma:
            work = work.filter(ImageFilter.GaussianBlur(blur_sigma))
            blur_sigma = 0.0
        new_size = (
            max(1, int(round(work.size[0] * factor))),
            max(1, int(round(work.size[1] * factor))),
        )
        work = work.resize(new_size, resample=resample)

    if blur_sigma:
        work = work.filter(ImageFilter.GaussianBlur(blur_sigma))
    if exposure != 1.0:
        work = ImageEnhance.Brightness(work).enhance(float(exposure))
    if noise_sigma:
        work = add_sensor_noise(work, noise_sigma, seed=seed)
    if rotation_deg:
        work = work.rotate(
            float(rotation_deg),
            resample=Image.Resampling.BILINEAR,
            expand=True,
            fillcolor=(255, 255, 255),
        )
    if perspective:
        work = _apply_perspective(work, float(perspective))
    if jpeg_quality is not None:
        work = jpeg_roundtrip(work, int(jpeg_quality))
    return work


def add_sensor_noise(img: Image.Image, sigma: float, seed: int = 0) -> Image.Image:
    """Additive Gaussian sensor noise (deterministic for a given seed).

    Real captures of a screen always carry sensor/ISO noise. Without it a
    synthetic matrix has BER 0 at every resolution and cannot discriminate a
    good implementation from a bad one, so it is part of the base camera model
    rather than an optional extra.
    """
    if sigma <= 0:
        return img
    arr = np.asarray(img.convert("RGB"), dtype=np.float32)
    rng = np.random.default_rng(seed)
    arr = arr + rng.normal(0.0, float(sigma), size=arr.shape)
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")


def frontend_transform(
    img: Image.Image,
    min_output_size: int = 450,
    blur_radius: float = 1.0,
    anti_moire: bool = True,
) -> Image.Image:
    """Reproduce the current frontend payload path exactly (RC-02).

    Mirrors ``frontend/src/hooks/useQRScanner.js``: the crop is upscaled with
    nearest-neighbour only when either dimension is below ``MIN_OUTPUT_SIZE``
    (450), and the 1px Gaussian blur is applied **only in that same small-crop
    branch** (``isSmallCrop`` + ``antiMoireRef``). A crop that is already >=450px
    is drawn with ``filter: 'none'``. An earlier version of this helper blurred
    unconditionally, which overstated the damage on large captures.
    """
    work = img.convert("RGB")
    w, h = work.size
    is_small_crop = w < min_output_size or h < min_output_size
    if not is_small_crop:
        return work
    factor = max(min_output_size / float(w), min_output_size / float(h))
    work = work.resize(
        (max(1, int(round(w * factor))), max(1, int(round(h * factor)))),
        Image.Resampling.NEAREST,
    )
    if anti_moire and blur_radius:
        work = work.filter(ImageFilter.GaussianBlur(float(blur_radius)))
    return work


# ── Extraction ────────────────────────────────────────────────────────────────


@dataclass
class ExtractionResult:
    ok: bool
    outcome: str                      # success | payload_fail | no_magic | no_qr | error
    public_data: str = ""
    secret_text: str = ""
    error_code: Optional[str] = None
    failure_reason: Optional[str] = None
    elapsed_ms: float = 0.0
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> Optional[int]:
        value = self.diagnostics.get("version")
        return int(value) if isinstance(value, int) else None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "outcome": self.outcome,
            "error_code": self.error_code,
            "failure_reason": self.failure_reason,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "diagnostics": self.diagnostics,
        }


def _save_temp(img: Image.Image, suffix: str = ".png") -> Tuple[str, str]:
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="iv_qr_probe_")
    path = handle.name
    handle.close()
    img.save(path)
    return path, path


def run_extract(
    img: "Image.Image | bytes | str",
    password: Optional[str] = None,
    hint_version: Optional[int] = None,
    client_corners: Optional[Dict[str, Any]] = None,
) -> ExtractionResult:
    """Run the production extractor and normalise its outcome."""
    temp_path = None
    if isinstance(img, (str, os.PathLike)):
        path = str(img)
    else:
        if isinstance(img, bytes):
            buf = io.BytesIO(img)
            with Image.open(buf) as handle:
                loaded = handle.convert("RGB")
                loaded.load()
            img = loaded
        temp_path, path = _save_temp(img)

    started = time.perf_counter()
    try:
        public_data, secret_text, diagnostics = qr_stego.extract_from_qr_stego(
            path,
            password=password,
            client_corners=client_corners,
            client_version=hint_version,
            return_diagnostics=True,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return ExtractionResult(
            ok=True,
            outcome="success" if secret_text else "no_magic",
            public_data=public_data,
            secret_text=secret_text,
            elapsed_ms=elapsed_ms,
            diagnostics=diagnostics,
        )
    except qr_stego.QRStegoError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        diagnostics = dict(getattr(exc, "diagnostics", {}) or {})
        code = getattr(exc.error_code, "value", str(exc.error_code))
        if code in ("QR_NOT_DETECTED",):
            outcome = "no_qr"
        elif code in ("VISIBLE_PAYLOAD_DECODE_FAILED", "HIDDEN_PAYLOAD_CORRUPTED", "WRONG_PASSWORD"):
            outcome = "payload_fail"
        else:
            outcome = "error"
        return ExtractionResult(
            ok=False,
            outcome=outcome,
            error_code=code,
            failure_reason=diagnostics.get("failureReason"),
            elapsed_ms=elapsed_ms,
            diagnostics=diagnostics,
        )
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


# ── Channel BER probe ─────────────────────────────────────────────────────────


def container_length(secret: str, password: Optional[str]) -> int:
    """Packed container length.

    Fernet output is not reproducible (random salt/IV) but its **length** is,
    which is all the carrier map needs.
    """
    return len(pack_qr_container(secret, password))


def carrier_bit_count(secret: str, password: Optional[str]) -> int:
    """Total embedded bits: RS(8) header + RS(24) body, as bytes*8."""
    return (container_length(secret, password) + qr_stego.RS_HEADER_ECC_BYTES + qr_stego.RS_BODY_ECC_BYTES) * 8


def module_carrier_map(public_data: str, version: int, bit_count: int):
    """Mirror of ``_embed_visual_qr`` steps 2-4: which module carries which bit.

    Returns ``(modules, is_dark)``. Validation is by construction: BER on a clean
    render must be exactly zero and the render must still extract.
    """
    qr = segno.make(public_data, version=version, error=ECC_LEVEL, boost_error=False)
    matrix = [bytearray(row) for row in qr.matrix]
    dimension = len(matrix)
    safe_modules = get_safe_data_modules(version)

    seed_material = f"{public_data}|{version}|{dimension}".encode("utf-8")
    dark_safe = [m for m in safe_modules if matrix[m[0]][m[1]] == 1]
    light_safe = [m for m in safe_modules if matrix[m[0]][m[1]] == 0]

    ordered_dark = qr_stego._order_dark_modules(dark_safe, matrix, seed_material)
    seed_light = hashlib.sha256(seed_material + b"_light").digest()
    permuted = ordered_dark + deterministic_permute(light_safe, seed_light)

    if bit_count > len(permuted):
        raise ValueError(
            f"payload needs {bit_count} carrier bits but version {version} has {len(permuted)}"
        )
    modules = permuted[:bit_count]
    is_dark = [matrix[r][c] == 1 for r, c in modules]
    return modules, is_dark


def _otsu_split(values: np.ndarray) -> Optional[float]:
    """Threshold maximising between-class variance for a 1-D sample."""
    ordered = np.sort(values)
    n = ordered.size
    if n < 2:
        return None
    total_sum = float(ordered.sum())
    best_thr = None
    best_score = -1.0
    running_sum = 0.0
    for i in range(1, n):
        running_sum += float(ordered[i - 1])
        w0 = i / n
        w1 = 1.0 - w0
        if w0 <= 0 or w1 <= 0:
            continue
        mu0 = running_sum / i
        mu1 = (total_sum - running_sum) / (n - i)
        score = w0 * w1 * (mu0 - mu1) ** 2
        if score > best_score:
            best_score = score
            best_thr = (float(ordered[i - 1]) + float(ordered[i])) / 2.0
    return best_thr


def _interior_median(gray: np.ndarray, ppm: float, border: int, r: int, c: int) -> Optional[float]:
    x0 = int(round((c + border) * ppm)) + 1
    y0 = int(round((r + border) * ppm)) + 1
    x1 = int(round((c + border + 1) * ppm)) - 1
    y1 = int(round((r + border + 1) * ppm)) - 1
    if x1 <= x0 or y1 <= y0:
        return None
    if y0 < 0 or x0 < 0 or y1 > gray.shape[0] or x1 > gray.shape[1]:
        return None
    return float(np.median(gray[y0:y1, x0:x1]))


def sample_channel_bits(
    img: Image.Image,
    public_data: str,
    version: int,
    bit_count: int,
    border: int = DEFAULT_BORDER,
) -> Tuple[Dict[Tuple[int, int], int], Dict[str, Any]]:
    """Recover embedded bits from an axis-aligned image by sampling module interiors.

    Per polarity, bits are classified with a 1-D two-cluster split. If a class
    lacks separation (too few members or a collapsed luma spread) its bits are
    omitted and reported in ``meta['skipped']`` rather than scored as zeros.
    """
    dimension = 17 + 4 * version
    width = img.size[0]
    ppm = width / float(dimension + 2 * border)
    gray = np.asarray(img.convert("L"), dtype=np.float64)
    modules, is_dark = module_carrier_map(public_data, version, bit_count)

    lumas: List[Optional[float]] = [
        _interior_median(gray, ppm, border, r, c) for r, c in modules
    ]

    bits: Dict[Tuple[int, int], int] = {}
    meta: Dict[str, Any] = {"px_per_module": round(ppm, 3), "skipped": []}

    for polarity_dark in (True, False):
        idx = [
            i
            for i, dark in enumerate(is_dark)
            if dark is polarity_dark and lumas[i] is not None
        ]
        if len(idx) < MIN_CLASS_MEMBERS:
            meta["skipped"].append("dark" if polarity_dark else "light")
            continue
        values = np.array([lumas[i] for i in idx], dtype=np.float64)
        spread = float(values.max() - values.min())
        if spread < MIN_CLASS_SEPARATION:
            meta["skipped"].append("dark" if polarity_dark else "light")
            continue
        threshold = _otsu_split(values)
        if threshold is None:
            meta["skipped"].append("dark" if polarity_dark else "light")
            continue
        meta["separation_dark" if polarity_dark else "separation_light"] = round(spread, 2)
        for i in idx:
            high = lumas[i] >= threshold  # type: ignore[operator]
            # Dark modules: bit 1 is lightened (fg+delta). Light modules: bit 1
            # is darkened (bg-delta). So the mapping inverts by polarity.
            bits[modules[i]] = (1 if high else 0) if polarity_dark else (0 if high else 1)

    return bits, meta


# ── Fixture matrix ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RenderSpec:
    id: str
    payload_class: str
    password: Optional[str]
    scale: int


@dataclass(frozen=True)
class DegradationSpec:
    id: str
    px_per_module: Optional[float] = None
    blur_sigma: float = 0.0
    exposure: float = 1.0
    noise_sigma: float = 0.0
    jpeg_quality: Optional[int] = None
    rotation_deg: float = 0.0
    perspective: float = 0.0
    frontend: bool = False
    split: str = "train"


RENDERS: Tuple[RenderSpec, ...] = (
    RenderSpec("small_plain_s20", "small", None, 20),
    RenderSpec("small_sealed_s20", "small", FIXTURE_PASSWORD, 20),
    RenderSpec("medium_plain_s20", "medium", None, 20),
    RenderSpec("medium_sealed_s20", "medium", FIXTURE_PASSWORD, 20),
    RenderSpec("large_plain_s20", "large", None, 20),
    RenderSpec("large_sealed_s20", "large", FIXTURE_PASSWORD, 20),
    RenderSpec("medium_sealed_s10", "medium", FIXTURE_PASSWORD, 10),
    RenderSpec("small_plain_s10", "small", None, 10),
)

# Degradation profiles are calibrated against 87 real camera captures of the
# shipped app (git-ignored debug frames). Measured FEC-level recovery there was
# 62% at 3 ppm, 83% at 4 ppm and 100% at 5-8 ppm for v11. The matrix therefore
# concentrates on the 3-4 ppm band instead of assuming 6 ppm is marginal.
DEGRADATIONS: Tuple[DegradationSpec, ...] = (
    DegradationSpec("clean", split="train"),
    DegradationSpec("ppm10", px_per_module=10, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm8", px_per_module=8, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm7", px_per_module=7, noise_sigma=2.0, split="heldout"),
    DegradationSpec("ppm6", px_per_module=6, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm5", px_per_module=5, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm4", px_per_module=4, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm3", px_per_module=3, noise_sigma=3.0, split="heldout"),
    DegradationSpec("ppm8_blur05", px_per_module=8, blur_sigma=0.5, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm8_exposure120", px_per_module=8, exposure=1.2, noise_sigma=2.0, split="heldout"),
    DegradationSpec("ppm8_jpeg80", px_per_module=8, jpeg_quality=80, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm8_rot5", px_per_module=8, rotation_deg=5.0, noise_sigma=2.0, split="train"),
    DegradationSpec("ppm8_persp03", px_per_module=8, perspective=0.03, noise_sigma=2.0, split="train"),
    DegradationSpec("frontend_ppm4", px_per_module=4, noise_sigma=2.0, frontend=True, split="train"),
)

# Fast subset: everything clean + every ppm8 + ppm4 for four renders (20 total).
FAST_DEGRADATIONS = {"clean", "ppm8"}
FAST_PPM4_RENDERS = {"small_plain_s20", "medium_plain_s20", "medium_sealed_s20", "large_plain_s20"}


def _noise_seed(name: str) -> int:
    """Stable per-profile seed (Python's str hash is process-randomised)."""
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:4], "big")


def fixture_id(render: RenderSpec, degradation: DegradationSpec) -> str:
    return f"{render.id}__{degradation.id}"


def is_fast(render: RenderSpec, degradation: DegradationSpec) -> bool:
    if degradation.id in FAST_DEGRADATIONS:
        return True
    return degradation.id == "ppm4" and render.id in FAST_PPM4_RENDERS


def fixture_specs() -> List[Tuple[RenderSpec, DegradationSpec]]:
    return [(r, d) for r in RENDERS for d in DEGRADATIONS]


def png_path(render: RenderSpec) -> str:
    return os.path.join(PNG_DIR, f"{render.id}.png")


def materialize(render: RenderSpec, degradation: DegradationSpec) -> Tuple[Image.Image, RenderedQR]:
    """Load the committed base render and apply a degradation profile."""
    path = png_path(render)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"missing base render {path}; run `python -m tests.qr_harness build` first"
        )
    with Image.open(path) as handle:
        base = handle.convert("RGB")
        base.load()
    public_data = DEFAULT_PUBLIC
    dimension = base.size[0] // render.scale - 2 * DEFAULT_BORDER
    version = (dimension - 17) // 4
    rendered = RenderedQR(
        image=base,
        version=version,
        dimension=dimension,
        scale=render.scale,
        border=DEFAULT_BORDER,
        public_data=public_data,
        secret=build_secret(render.payload_class),
        password=render.password,
        path=path,
    )

    img = base
    if (
        degradation.px_per_module is not None
        or degradation.blur_sigma
        or degradation.exposure != 1.0
        or degradation.noise_sigma
    ):
        img = degrade(
            img,
            degradation.px_per_module,
            source_ppm=float(render.scale),
            blur_sigma=degradation.blur_sigma,
            exposure=degradation.exposure,
            noise_sigma=degradation.noise_sigma,
            seed=_noise_seed(degradation.id),
        )
    if degradation.rotation_deg:
        img = img.rotate(
            degradation.rotation_deg,
            resample=Image.Resampling.BILINEAR,
            expand=True,
            fillcolor=(255, 255, 255),
        )
    if degradation.perspective:
        img = _apply_perspective(img, degradation.perspective)
    if degradation.jpeg_quality is not None:
        img = jpeg_roundtrip(img, degradation.jpeg_quality)
    if degradation.frontend:
        img = frontend_transform(img, min_output_size=450, blur_radius=1.0)
    return img, rendered


def evaluate_fixture(
    render: RenderSpec,
    degradation: DegradationSpec,
    *,
    reference_bits: Optional[Dict[Tuple[int, int], int]] = None,
) -> Dict[str, Any]:
    """Run one fixture and return its measured record."""
    img, rendered = materialize(render, degradation)
    result = run_extract(img, password=render.password)

    expected_secret = build_secret(render.payload_class)
    record: Dict[str, Any] = {
        "id": fixture_id(render, degradation),
        "render": render.id,
        "degradation": degradation.id,
        "split": degradation.split,
        "fast": is_fast(render, degradation),
        "source": "synthetic",
        "public_data": DEFAULT_PUBLIC,
        "secret_class": render.payload_class,
        "secret_bytes": secret_utf8_bytes(render.payload_class),
        "secret_sha256": hashlib.sha256(expected_secret.encode("utf-8")).hexdigest(),
        "password_ref": FIXTURE_PASSWORD_REF if render.password else None,
        "version": rendered.version,
        "ecc": ECC_LEVEL,
        "render_scale": render.scale,
        "image": os.path.relpath(png_path(render), FIXTURE_ROOT).replace("\\", "/"),
        "degradations": {
            "px_per_module": degradation.px_per_module,
            "blur_sigma": degradation.blur_sigma,
            "exposure": degradation.exposure,
            "noise_sigma": degradation.noise_sigma,
            "jpeg_quality": degradation.jpeg_quality,
            "rotation_deg": degradation.rotation_deg,
            "perspective": degradation.perspective,
            "frontend_transform": degradation.frontend,
        },
        "outcome": result.outcome,
        "error_code": result.error_code,
        "failure_reason": result.failure_reason,
        "timing_ms": round(result.elapsed_ms, 2),
        "diagnostics": result.diagnostics,
        "secret_match": bool(result.secret_text) and result.secret_text == expected_secret,
        "ber": None,
        "ber_coverage": None,
        "ber_meta": None,
    }

    # BER is only meaningful when the geometric transform preserves module
    # grid alignment; rotation and perspective do not.
    supports_ber = not degradation.rotation_deg and not degradation.perspective
    if supports_ber:
        bit_count = carrier_bit_count(expected_secret, render.password)
        try:
            if reference_bits is None:
                clean_bits, clean_meta = sample_channel_bits(
                    rendered.image, DEFAULT_PUBLIC, rendered.version, bit_count
                )
            else:
                clean_bits, clean_meta = reference_bits, {"reused": True}
            sampled, meta = sample_channel_bits(
                img, DEFAULT_PUBLIC, rendered.version, bit_count
            )
            meta["clean_meta"] = clean_meta
            if clean_bits and sampled:
                # A collapsed polarity class (over-exposure, heavy blur) is omitted
                # from ``sampled``; score the intersection and report coverage so a
                # partial reading is never mistaken for a clean one.
                common = set(clean_bits) & set(sampled)
                if common:
                    record["ber"] = round(
                        bit_error_rate(
                            {k: clean_bits[k] for k in common},
                            {k: sampled[k] for k in common},
                        ),
                        6,
                    )
                    record["ber_coverage"] = round(len(common) / len(clean_bits), 4)
                else:
                    meta["note"] = "no aligned modules"
            record["ber_meta"] = meta
        except ValueError as exc:  # geometry/payload mismatch: record, do not fail
            record["ber_meta"] = {"error": str(exc)}

    return record


# ── Manifest / baseline ───────────────────────────────────────────────────────


def _atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp, path)


def read_manifest() -> Dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def read_baseline() -> Dict[str, Any]:
    with open(BASELINE_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def read_reference() -> Dict[str, Any]:
    with open(REFERENCE_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def read_fixture_hashes() -> Dict[str, str]:
    with open(SHA256_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def verify_fixture_hashes() -> Tuple[bool, List[str]]:
    expected = read_fixture_hashes()
    errors = []
    for filename, exp_hash in expected.items():
        filepath = os.path.join(PNG_DIR, filename)
        if not os.path.exists(filepath):
            errors.append(f"Missing fixture file: {filename}")
            continue
        with open(filepath, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest().lower()
        if actual_hash != exp_hash.lower():
            errors.append(f"Hash mismatch for {filename}: expected {exp_hash}, got {actual_hash}")
    return len(errors) == 0, errors


def _git_commit() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BACKEND_DIR,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _environment() -> Dict[str, Any]:
    import PIL
    import reedsolo
    import zxingcpp

    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "note": (
            "Desktop measurement. Render-like 512MB cgroup timing/RSS is required "
            "for release evidence and is NOT satisfied by this file."
        ),
        "libraries": {
            "Pillow": PIL.__version__,
            "numpy": np.__version__,
            "segno": getattr(segno, "__version__", "unknown"),
            "zxing-cpp": getattr(zxingcpp, "__version__", "unknown"),
            "reedsolo": getattr(reedsolo, "__version__", "unknown"),
        },
        "git_commit": _git_commit(),
    }


def _aggregate(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_ppm: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        ppm = rec["degradations"]["px_per_module"]
        key = "native" if ppm is None else str(ppm)
        by_ppm.setdefault(key, []).append(rec)

    def _bucket(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(items)
        successes = sum(1 for r in items if r["outcome"] == "success")
        bers = [r["ber"] for r in items if isinstance(r["ber"], (int, float))]
        times = [r["timing_ms"] for r in items]
        return {
            "n": n,
            "successes": successes,
            "success_rate": round(successes / n, 4) if n else None,
            "wilson95": [round(v, 4) for v in wilson_interval(successes, n)],
            "mean_ber": round(float(np.mean(bers)), 6) if bers else None,
            "mean_ms": round(float(np.mean(times)), 2) if times else None,
            "p95_ms": round(float(np.percentile(times, 95)), 2) if times else None,
        }

    by_split: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        by_split.setdefault(rec["split"], []).append(rec)

    return {
        "all": _bucket(records),
        "by_px_per_module": {k: _bucket(v) for k, v in sorted(by_ppm.items())},
        "by_split": {k: _bucket(v) for k, v in sorted(by_split.items())},
        "by_outcome": {
            outcome: sum(1 for r in records if r["outcome"] == outcome)
            for outcome in sorted({r["outcome"] for r in records})
        },
    }


def build(force: bool = False, skip_baseline: bool = False) -> Dict[str, Any]:
    """Render base PNGs, measure every fixture, and write manifest + baseline."""
    os.makedirs(PNG_DIR, exist_ok=True)

    render_meta: Dict[str, Dict[str, Any]] = {}
    for render in RENDERS:
        path = png_path(render)
        if force or not os.path.exists(path):
            rendered = render_stego(
                secret=build_secret(render.payload_class),
                public_data=DEFAULT_PUBLIC,
                password=render.password,
                scale=render.scale,
                out_path=path,
            )
            version = rendered.version
        else:
            with Image.open(path) as handle:
                width = handle.size[0]
            dimension = width // render.scale - 2 * DEFAULT_BORDER
            version = (dimension - 17) // 4
        render_meta[render.id] = {
            "image": os.path.relpath(path, FIXTURE_ROOT).replace("\\", "/"),
            "version": version,
            "render_scale": render.scale,
            "secret_class": render.payload_class,
            "secret_bytes": secret_utf8_bytes(render.payload_class),
            "secret_sha256": hashlib.sha256(
                build_secret(render.payload_class).encode("utf-8")
            ).hexdigest(),
            "password_ref": FIXTURE_PASSWORD_REF if render.password else None,
        }

    manifest: Dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "public_data": DEFAULT_PUBLIC,
        "ecc": ECC_LEVEL,
        "border": DEFAULT_BORDER,
        "notes": [
            "Synthetic fixtures only. Never commit real captures.",
            "Secret plaintext is not stored; only SHA-256 plus the deterministic recipe.",
            "expected/outcome values are the pre-change baseline behaviour.",
        ],
        "renders": render_meta,
        "degradations": {d.id: d.__dict__ for d in DEGRADATIONS},
        "fixtures": [],
    }

    records: List[Dict[str, Any]] = []
    if skip_baseline:
        for render, degradation in fixture_specs():
            manifest["fixtures"].append(
                {
                    "id": fixture_id(render, degradation),
                    "render": render.id,
                    "degradation": degradation.id,
                    "split": degradation.split,
                    "fast": is_fast(render, degradation),
                }
            )
    else:
        for render, degradation in fixture_specs():
            record = evaluate_fixture(render, degradation)
            records.append(record)
            manifest["fixtures"].append(record)

    _atomic_write_json(MANIFEST_PATH, manifest)

    baseline: Dict[str, Any] = {
        "schema": BASELINE_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": _environment(),
        "aggregate": _aggregate(records) if records else None,
        "fixtures": {rec["id"]: rec for rec in records},
    }
    if not skip_baseline:
        _atomic_write_json(BASELINE_PATH, baseline)
    return {"manifest": manifest, "baseline": baseline}


def report(path: Optional[str] = None) -> str:
    """Human-readable summary of the recorded baseline or reference."""
    target_path = path or BASELINE_PATH
    label = "reference" if target_path == REFERENCE_PATH else "baseline"
    with open(target_path, "r", encoding="utf-8") as handle:
        baseline = json.load(handle)
    agg = baseline.get("aggregate") or {}
    lines = [
        f"{label} generated: {baseline.get('generated_at')}",
        f"environment: {baseline.get('environment', {}).get('platform')}",
        f"fixtures: {len(baseline.get('fixtures', {}))}",
        "",
        f"{'px/module':>10} {'n':>4} {'ok':>4} {'rate':>7} {'wilson95':>20} {'mean BER':>9} {'p95 ms':>8}",
    ]
    for key, bucket in (agg.get("by_px_per_module") or {}).items():
        low, high = bucket["wilson95"]
        ber = bucket["mean_ber"]
        ber_text = "%.4f" % ber if ber is not None else "-"
        p95 = bucket["p95_ms"]
        p95_text = "%.1f" % p95 if p95 is not None else "-"
        rate = bucket["success_rate"]
        rate_text = "%.3f" % rate if rate is not None else "-"
        lines.append(
            "%10s %4d %4d %7s %20s %9s %8s"
            % (
                key,
                bucket["n"],
                bucket["successes"],
                rate_text,
                "[%.3f, %.3f]" % (low, high),
                ber_text,
                p95_text,
            )
        )
    lines.append("")
    lines.append(f"outcomes: {agg.get('by_outcome')}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="QR steganography fixture harness (Phase 0)")
    sub = parser.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="render fixtures and record the baseline")
    build_cmd.add_argument("--force", action="store_true", help="overwrite committed base renders")
    build_cmd.add_argument(
        "--skip-baseline",
        action="store_true",
        help="write the manifest without running extraction",
    )
    report_cmd = sub.add_parser("report", help="print the recorded baseline or reference")
    report_cmd.add_argument(
        "--reference",
        action="store_true",
        help="print Phase 1-3 reference instead of historical baseline",
    )
    sub.add_parser("verify", help="verify fixture SHA-256 hashes against pinned manifest")

    args = parser.parse_args(argv)
    if args.command == "build":
        build(force=args.force, skip_baseline=args.skip_baseline)
        print(f"wrote {MANIFEST_PATH}")
        if not args.skip_baseline:
            print(f"wrote {BASELINE_PATH}")
            print(report())
        return 0
    if args.command == "report":
        target = REFERENCE_PATH if args.reference else BASELINE_PATH
        print(report(target))
        return 0
    if args.command == "verify":
        ok, errors = verify_fixture_hashes()
        if not ok:
            print("FAILED: Fixture SHA-256 hash verification failed:")
            for err in errors:
                print(f"  {err}")
            return 1
        print("OK: All 8 base fixture PNGs match pinned SHA-256 digests.")
        if os.path.exists(BASELINE_PATH):
            print(f"OK: Historical Phase 0 baseline present: {BASELINE_PATH}")
        if os.path.exists(REFERENCE_PATH):
            print(f"OK: Phase 1-3 verified reference present: {REFERENCE_PATH}")
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
