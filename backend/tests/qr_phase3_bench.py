"""Phase 3 modulation / optical-channel benchmark (test-only).

Renders QR symbols with explicit encoder modulation settings, pushes each one
through a deterministic camera-like channel, and measures:

* public QR decodability through three independent decoder paths
  (zxing default, zxing ``is_pure``, pyzbar);
* hidden-payload extraction success and its failure stage;
* per-polarity channel BER against the clean render of the *same* encoder
  settings, so a modulation change is never scored against a stale reference;
* extraction latency and (optionally) traced peak memory.

Nothing here is imported by production code. Phase 0 fixtures and
``qr_baseline.json`` are deliberately left untouched: the committed PNGs are
the legacy-encoder corpus, and this harness renders its own images.

Usage (from ``backend/``)::

    ./.venv/Scripts/python.exe -m tests.qr_phase3_bench list
    ./.venv/Scripts/python.exe -m tests.qr_phase3_bench run \
        --configs A_fixed_50_40,B_fixed_56_72 --split train --out phase3_train.json
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image, ImageFilter

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, BACKEND_DIR)

import zxingcpp  # noqa: E402

try:  # pragma: no cover - optional at import time
    from pyzbar import pyzbar
except (ImportError, OSError):  # pragma: no cover
    pyzbar = None  # type: ignore[assignment]

from tests import qr_harness as H  # noqa: E402
from utils import qr_stego as S  # noqa: E402

DEFAULT_PUBLIC = H.DEFAULT_PUBLIC
EVIDENCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs_ignore",
    "phase3",
)

# ── Encoder candidates ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ModConfig:
    """One encoder modulation candidate."""

    id: str
    dark: int = S.DARK_MODULATION_DELTA
    light: int = S.LIGHT_MODULATION_DELTA
    adaptive: bool = False
    inset: int = S.MODULATION_INSET

    def describe(self) -> str:
        mode = "adaptive" if self.adaptive else "fixed"
        return (
            f"{self.id}: {mode} dark={self.dark} light={self.light} "
            f"inset={self.inset}"
        )


CONFIGS: Dict[str, ModConfig] = {
    # A = the shipped encoder. Baseline, not a candidate.
    "A_fixed_50_40": ModConfig("A_fixed_50_40", 50, 40, False, 1),
    # B = implementation-plan §6.5 scale tier at export scale >= 15.
    "B_fixed_56_72": ModConfig("B_fixed_56_72", 56, 72, False, 1),
    # C = palette- and scale-aware policy (the proposed production default).
    "C_adaptive": ModConfig("C_adaptive", 56, 72, True, 1),
    # D = strength probe: is more always better?
    "D_fixed_72_96": ModConfig("D_fixed_72_96", 72, 96, False, 1),
    # E = spatial probe: whole-module modulation (inset 0) at the light delta.
    "E_adaptive_inset0": ModConfig("E_adaptive_inset0", 56, 72, True, 0),
    # F = isolate the light-channel change only.
    "F_fixed_50_72": ModConfig("F_fixed_50_72", 50, 72, False, 1),
    # G = light-channel strength probe: does more margin keep helping?
    "G_fixed_50_96": ModConfig("G_fixed_50_96", 50, 96, False, 1),
    # H = dark-channel probe at the measured light delta.
    "H_fixed_64_72": ModConfig("H_fixed_64_72", 64, 72, False, 1),
    # P = the production policy after Phase 3 (adaptive light channel only).
    "P_phase3_policy": ModConfig("P_phase3_policy", 50, 72, True, 1),
}

# ── Channel conditions ────────────────────────────────────────────────────────
#
# ``train`` conditions may be used to choose a candidate. ``heldout`` conditions
# are measured only for the final before/after report and must never be used to
# tune a delta, threshold or footprint.

TRAIN_CONDITIONS: Tuple[H.DegradationSpec, ...] = (
    H.DegradationSpec("clean", split="train"),
    H.DegradationSpec("ppm10", px_per_module=10, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8", px_per_module=8, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm6", px_per_module=6, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm5", px_per_module=5, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm4", px_per_module=4, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm3", px_per_module=3, noise_sigma=3.0, split="train"),
    H.DegradationSpec("ppm8_blur05", px_per_module=8, blur_sigma=0.5, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_blur10", px_per_module=8, blur_sigma=1.0, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_jpeg80", px_per_module=8, jpeg_quality=80, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_rot5", px_per_module=8, rotation_deg=5.0, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_persp03", px_per_module=8, perspective=0.03, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_exposure120", px_per_module=8, exposure=1.2, noise_sigma=2.0, split="train"),
    H.DegradationSpec("ppm8_exposure080", px_per_module=8, exposure=0.8, noise_sigma=2.0, split="train"),
    H.DegradationSpec("frontend_ppm4", px_per_module=4, noise_sigma=2.0, frontend=True, split="train"),
)

HELDOUT_CONDITIONS: Tuple[H.DegradationSpec, ...] = (
    H.DegradationSpec("ppm9", px_per_module=9, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm7", px_per_module=7, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm4_exposure120", px_per_module=4, exposure=1.2, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm4_blur05", px_per_module=4, blur_sigma=0.5, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm8_exposure140", px_per_module=8, exposure=1.4, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm8_persp06", px_per_module=8, perspective=0.06, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm6_jpeg60", px_per_module=6, jpeg_quality=60, noise_sigma=2.0, split="heldout"),
    H.DegradationSpec("ppm3_blur05", px_per_module=3, blur_sigma=0.5, noise_sigma=3.0, split="heldout"),
)

# Tuning renders: short + long payloads, plain + sealed, dark-only + light-spill.
TRAIN_RENDER_IDS = (
    "small_plain_s20",
    "medium_sealed_s20",
    "large_plain_s20",
    "large_sealed_s20",
)
HELDOUT_RENDER_IDS = tuple(r.id for r in H.RENDERS)

MIN_CLASS_SEPARATION = H.MIN_CLASS_SEPARATION
MIN_CLASS_MEMBERS = H.MIN_CLASS_MEMBERS

# ── Rendering ─────────────────────────────────────────────────────────────────


def _render(
    config: ModConfig,
    render: H.RenderSpec,
    out_path: str,
) -> Tuple[Image.Image, int]:
    """Render one candidate image through the production encoder."""
    S._embed_visual_qr(
        public_data=DEFAULT_PUBLIC,
        secret_text=H.build_secret(render.payload_class),
        output_path=out_path,
        password=render.password,
        fg_color="#000000",
        bg_color="#FFFFFF",
        scale=render.scale,
        border=H.DEFAULT_BORDER,
        delta=config.dark,
        light_delta=config.light,
        inset=config.inset,
        adaptive_modulation=config.adaptive,
        logo_path=None,
    )
    with Image.open(out_path) as handle:
        image = handle.convert("RGB")
        image.load()
    dimension = image.size[0] // render.scale - 2 * H.DEFAULT_BORDER
    version = (dimension - 17) // 4
    return image, version


def _apply_channel(
    img: Image.Image,
    condition: H.DegradationSpec,
    source_ppm: float,
) -> Image.Image:
    """Deterministic camera-like degradation, matching ``qr_harness.materialize``."""
    work = img
    if (
        condition.px_per_module is not None
        or condition.blur_sigma
        or condition.exposure != 1.0
        or condition.noise_sigma
    ):
        work = H.degrade(
            work,
            condition.px_per_module,
            source_ppm=float(source_ppm),
            blur_sigma=condition.blur_sigma,
            exposure=condition.exposure,
            noise_sigma=condition.noise_sigma,
            seed=H._noise_seed(condition.id),
        )
    if condition.rotation_deg:
        work = work.rotate(
            condition.rotation_deg,
            resample=Image.Resampling.BILINEAR,
            expand=True,
            fillcolor=(255, 255, 255),
        )
    if condition.perspective:
        work = H._apply_perspective(work, condition.perspective)
    if condition.jpeg_quality is not None:
        work = H.jpeg_roundtrip(work, condition.jpeg_quality)
    if condition.frontend:
        work = H.frontend_transform(work, min_output_size=450, blur_radius=1.0)
    return work


# ── Public QR decodability ────────────────────────────────────────────────────


def public_decode(img: Image.Image) -> Dict[str, Any]:
    """Try every decoder path the app ships; report each independently."""
    result: Dict[str, Any] = {
        "zxing": None,
        "zxing_pure": None,
        "pyzbar": None,
    }
    for key, kwargs in (("zxing", {}), ("zxing_pure", {"is_pure": True})):
        try:
            found = zxingcpp.read_barcodes(img, **kwargs)
        except Exception:
            found = None
        if found:
            text = getattr(found[0], "text", None)
            if text:
                result[key] = text
    if pyzbar is not None:
        try:
            found = pyzbar.decode(img)
        except Exception:
            found = None
        if found:
            try:
                result["pyzbar"] = found[0].data.decode("utf-8")
            except UnicodeDecodeError:
                result["pyzbar"] = None
    decoders = [k for k, v in result.items() if v is not None]
    result["ok_any"] = any(v == DEFAULT_PUBLIC for v in (result["zxing"], result["zxing_pure"], result["pyzbar"]))
    result["ok_zxing"] = result["zxing"] == DEFAULT_PUBLIC
    result["exact"] = all(v == DEFAULT_PUBLIC for v in result.values() if isinstance(v, str))
    result["decoders"] = decoders
    return result


# ── Channel BER ───────────────────────────────────────────────────────────────


def channel_bits(
    img: Image.Image,
    version: int,
    bit_count: int,
) -> Tuple[Dict[Tuple[int, int], int], Dict[str, Any]]:
    """Recover embedded bits from an axis-aligned image, one polarity at a time.

    Mirrors ``qr_harness.sample_channel_bits`` but keeps the two polarity
    classes separate so a light-channel collapse is visible instead of hidden
    inside one aggregate BER.
    """
    dimension = 17 + 4 * version
    ppm = img.size[0] / float(dimension + 2 * H.DEFAULT_BORDER)
    gray = np.asarray(img.convert("L"), dtype=np.float64)
    modules, is_dark = H.module_carrier_map(DEFAULT_PUBLIC, version, bit_count)
    lumas = [
        H._interior_median(gray, ppm, H.DEFAULT_BORDER, r, c) for r, c in modules
    ]

    bits: Dict[Tuple[int, int], int] = {}
    meta: Dict[str, Any] = {"px_per_module": round(ppm, 3), "classes": {}}
    for polarity_dark in (True, False):
        idx = [
            i
            for i, dark in enumerate(is_dark)
            if dark is polarity_dark and lumas[i] is not None
        ]
        label = "dark" if polarity_dark else "light"
        if len(idx) < MIN_CLASS_MEMBERS:
            meta["classes"][label] = {"n": len(idx), "scored": False, "reason": "too_few"}
            continue
        values = np.array([lumas[i] for i in idx], dtype=np.float64)
        spread = float(values.max() - values.min())
        if spread < MIN_CLASS_SEPARATION:
            meta["classes"][label] = {"n": len(idx), "scored": False, "reason": "collapsed"}
            continue
        threshold = H._otsu_split(values)
        if threshold is None:
            meta["classes"][label] = {"n": len(idx), "scored": False, "reason": "no_split"}
            continue
        threshold = float(threshold)
        meta["classes"][label] = {
            "n": len(idx),
            "scored": True,
            "spread": round(spread, 2),
            "low_median": round(float(np.median(values[values < threshold])), 2)
            if np.any(values < threshold)
            else None,
            "high_median": round(float(np.median(values[values >= threshold])), 2)
            if np.any(values >= threshold)
            else None,
        }
        for i in idx:
            high = lumas[i] >= threshold  # type: ignore[operator]
            bits[modules[i]] = (1 if high else 0) if polarity_dark else (0 if high else 1)
    return bits, meta


def _ber(
    reference: Dict[Tuple[int, int], int],
    sampled: Dict[Tuple[int, int], int],
    polarity: Dict[Tuple[int, int], bool],
    want_dark: bool,
) -> Tuple[Optional[float], int]:
    keys = [k for k in reference if polarity[k] is want_dark and k in sampled]
    if not keys:
        return None, 0
    wrong = sum(1 for k in keys if reference[k] != sampled[k])
    return round(wrong / len(keys), 6), len(keys)


# ── Case execution ────────────────────────────────────────────────────────────


@dataclass
class RenderedCase:
    image: Image.Image
    version: int
    bits: Dict[Tuple[int, int], int]
    meta: Dict[str, Any]
    bit_count: int
    polarity: Dict[Tuple[int, int], bool]
    render_ms: float


def _prepare_render(
    config: ModConfig,
    render: H.RenderSpec,
    workdir: str,
    out_name: str,
) -> RenderedCase:
    started = time.perf_counter()
    image, version = _render(config, render, os.path.join(workdir, out_name))
    render_ms = (time.perf_counter() - started) * 1000.0
    secret = H.build_secret(render.payload_class)
    bit_count = H.carrier_bit_count(secret, render.password)
    modules, is_dark = H.module_carrier_map(DEFAULT_PUBLIC, version, bit_count)
    polarity = {m: dark for m, dark in zip(modules, is_dark)}
    bits, meta = channel_bits(image, version, bit_count)
    return RenderedCase(
        image=image,
        version=version,
        bits=bits,
        meta=meta,
        bit_count=bit_count,
        polarity=polarity,
        render_ms=render_ms,
    )


def run_case(
    config: ModConfig,
    render: H.RenderSpec,
    condition: H.DegradationSpec,
    prepared: RenderedCase,
) -> Dict[str, Any]:
    degraded = _apply_channel(prepared.image, condition, float(render.scale))
    result = H.run_extract(degraded, password=render.password)
    expected = H.build_secret(render.payload_class)
    public = public_decode(degraded)

    record: Dict[str, Any] = {
        "config": config.id,
        "render": render.id,
        "version": prepared.version,
        "export_scale": render.scale,
        "payload_class": render.payload_class,
        "password": bool(render.password),
        "condition": condition.id,
        "split": condition.split,
        "px_per_module": condition.px_per_module,
        "outcome": result.outcome,
        "error_code": result.error_code,
        "stage": result.diagnostics.get("stage"),
        "failure_stage": result.diagnostics.get("failure_stage"),
        "exact_payload": bool(result.secret_text) and result.secret_text == expected,
        "extract_ms": round(result.elapsed_ms, 2),
        "render_ms": round(prepared.render_ms, 2),
        "public": public,
        "ber": None,
        "ber_dark": None,
        "ber_light": None,
        "ber_coverage": None,
        "channel": None,
    }

    if condition.rotation_deg or condition.perspective:
        # Grid alignment is destroyed by design here; the channel probe is not
        # meaningful and is deliberately not reported (same rule as Phase 0).
        return record

    sampled, meta = channel_bits(degraded, prepared.version, prepared.bit_count)
    common = set(prepared.bits) & set(sampled)
    record["channel"] = meta
    if common:
        record["ber"] = round(
            H.bit_error_rate(
                {k: prepared.bits[k] for k in common},
                {k: sampled[k] for k in common},
            ),
            6,
        )
        record["ber_coverage"] = round(len(common) / len(prepared.bits), 4)
        dark_ber, dark_n = _ber(prepared.bits, sampled, prepared.polarity, True)
        light_ber, light_n = _ber(prepared.bits, sampled, prepared.polarity, False)
        record["ber_dark"] = dark_ber
        record["ber_light"] = light_ber
        record["ber_dark_n"] = dark_n
        record["ber_light_n"] = light_n
    return record


# ── Aggregation ───────────────────────────────────────────────────────────────


def _wilson(successes: int, n: int) -> List[float]:
    return [round(v, 4) for v in H.wilson_interval(successes, n)]


def aggregate(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    def _bucket(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(items)
        successes = sum(1 for r in items if r["outcome"] == "success")
        exact = sum(1 for r in items if r["exact_payload"])
        public_ok = sum(1 for r in items if r["public"]["ok_any"])
        public_zxing = sum(1 for r in items if r["public"]["ok_zxing"])
        clash = sum(1 for r in items if r["public"]["ok_any"] and not r["public"]["exact"])
        bers = [r["ber"] for r in items if isinstance(r["ber"], (int, float))]
        dark = [r["ber_dark"] for r in items if isinstance(r["ber_dark"], (int, float))]
        light = [r["ber_light"] for r in items if isinstance(r["ber_light"], (int, float))]
        times = [r["extract_ms"] for r in items if isinstance(r["extract_ms"], (int, float))]
        stages: Dict[str, int] = {}
        for r in items:
            if r["outcome"] != "success":
                stages[str(r["stage"])] = stages.get(str(r["stage"]), 0) + 1
        return {
            "n": n,
            "successes": successes,
            "success_rate": round(successes / n, 4) if n else None,
            "wilson95": _wilson(successes, n),
            "exact_payload": exact,
            "public_ok_any": public_ok,
            "public_ok_zxing": public_zxing,
            "public_rate": round(public_ok / n, 4) if n else None,
            "public_wrong_text": clash,
            "mean_ber": round(float(np.mean(bers)), 6) if bers else None,
            "mean_ber_dark": round(float(np.mean(dark)), 6) if dark else None,
            "mean_ber_light": round(float(np.mean(light)), 6) if light else None,
            "mean_ms": round(float(np.mean(times)), 2) if times else None,
            "p95_ms": round(float(np.percentile(times, 95)), 2) if times else None,
            "failure_stages": stages,
        }

    by_condition: Dict[str, Dict[str, Any]] = {}
    for name in sorted({r["condition"] for r in records}):
        by_condition[name] = _bucket([r for r in records if r["condition"] == name])

    by_ppm: Dict[str, Dict[str, Any]] = {}
    for r in records:
        key = "native" if r["px_per_module"] is None else str(r["px_per_module"])
        by_ppm.setdefault(key, []).append(r)
    by_version: Dict[str, Dict[str, Any]] = {}
    for r in records:
        by_version.setdefault(str(r["version"]), []).append(r)

    return {
        "all": _bucket(records),
        "by_condition": by_condition,
        "by_px_per_module": {k: _bucket(v) for k, v in sorted(by_ppm.items())},
        "by_version": {k: _bucket(v) for k, v in sorted(by_version.items())},
    }


def _print_summary(config_id: str, agg: Dict[str, Any]) -> None:
    print(f"\n=== {config_id} ===")
    header = (
        f"{'condition':>20} {'n':>3} {'ok':>3} {'rate':>6} {'public':>6} "
        f"{'BER':>8} {'BERdark':>8} {'BERlight':>8} {'p95 ms':>8}"
    )
    print(header)
    for name, cell in agg["by_condition"].items():
        def _fmt(value, spec="%.4f"):
            return "-" if value is None else spec % value

        print(
            f"{name:>20} {cell['n']:>3} {cell['successes']:>3} "
            f"{_fmt(cell['success_rate'], '%.3f'):>6} {_fmt(cell['public_rate'], '%.2f'):>6} "
            f"{_fmt(cell['mean_ber']):>8} {_fmt(cell['mean_ber_dark']):>8} "
            f"{_fmt(cell['mean_ber_light']):>8} {_fmt(cell['p95_ms'], '%.1f'):>8}"
        )
    total = agg["all"]
    print(
        f"{'TOTAL':>20} {total['n']:>3} {total['successes']:>3} "
        f"{total['success_rate']:>6} {total['public_rate']:>6}"
    )


# ── Memory ────────────────────────────────────────────────────────────────────


def measure_memory(config: ModConfig, render: H.RenderSpec, workdir: str) -> Dict[str, Any]:
    """Traced peak memory for one generation and one extraction (desktop only)."""
    from concurrent.futures import ThreadPoolExecutor

    gc.collect()
    tracemalloc.start()
    path = os.path.join(workdir, f"mem_{config.id}_{render.id}.png")
    started = time.perf_counter()
    _render(config, render, path)
    gen_ms = (time.perf_counter() - started) * 1000.0
    _, gen_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    with Image.open(path) as handle:
        image = handle.convert("RGB")
        image.load()
    degraded = _apply_channel(image, TRAIN_CONDITIONS[2], float(render.scale))

    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    H.run_extract(degraded, password=render.password)
    extract_ms = (time.perf_counter() - started) * 1000.0
    _, extract_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    def _one(_: int) -> float:
        out = os.path.join(workdir, f"conc_{config.id}_{render.id}_{_}.png")
        began = time.perf_counter()
        _render(config, render, out)
        return (time.perf_counter() - began) * 1000.0

    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as pool:
        timings = list(pool.map(_one, range(4)))
    wall_ms = (time.perf_counter() - started) * 1000.0
    _, conc_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "config": config.id,
        "render": render.id,
        "generate_ms": round(gen_ms, 2),
        "generate_peak_kb": round(gen_peak / 1024.0, 1),
        "extract_ms": round(extract_ms, 2),
        "extract_peak_kb": round(extract_peak / 1024.0, 1),
        "concurrent_generate_wall_ms": round(wall_ms, 2),
        "concurrent_generate_peak_kb": round(conc_peak / 1024.0, 1),
        "concurrent_per_job_ms": [round(t, 2) for t in timings],
        "note": "Desktop tracemalloc; not Render/512MB-cgroup evidence.",
    }


# ── CLI ───────────────────────────────────────────────────────────────────────


def _resolve_renders(ids: Optional[Sequence[str]]) -> List[H.RenderSpec]:
    if not ids:
        return [r for r in H.RENDERS if r.id in TRAIN_RENDER_IDS]
    wanted = set(ids)
    renders = [r for r in H.RENDERS if r.id in wanted]
    missing = wanted - {r.id for r in renders}
    if missing:
        raise SystemExit(f"unknown render id(s): {sorted(missing)}")
    return renders


def _resolve_conditions(split: str) -> List[H.DegradationSpec]:
    if split == "train":
        return list(TRAIN_CONDITIONS)
    if split == "heldout":
        return list(HELDOUT_CONDITIONS)
    if split == "all":
        return list(TRAIN_CONDITIONS) + list(HELDOUT_CONDITIONS)
    raise SystemExit(f"unknown split: {split}")


def run(
    configs: Sequence[ModConfig],
    renders: Sequence[H.RenderSpec],
    conditions: Sequence[H.DegradationSpec],
    out_path: Optional[str],
    memory: bool = False,
) -> Dict[str, Any]:
    os.environ["QR_SELF_CHECK"] = "false"  # the harness verifies extraction itself
    workdir = tempfile.mkdtemp(prefix="iv_qr_phase3_")
    started = time.perf_counter()
    evidence: Dict[str, Any] = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "public_data": DEFAULT_PUBLIC,
        "renders": [r.id for r in renders],
        "conditions": [c.id for c in conditions],
        "configs": {c.id: c.__dict__ for c in configs},
        "results": {},
        "memory": [],
        "environment": H._environment(),
        "note": (
            "Phase 3 desktop benchmark. Trained/tuned on 'train' conditions only; "
            "'heldout' conditions are release evidence. Not a Render measurement."
        ),
    }
    try:
        for config in configs:
            prepared = {
                r.id: _prepare_render(config, r, workdir, f"{config.id}_{r.id}.png")
                for r in renders
            }
            records: List[Dict[str, Any]] = []
            for render in renders:
                for condition in conditions:
                    records.append(
                        run_case(config, render, condition, prepared[render.id])
                    )
            agg = aggregate(records)
            evidence["results"][config.id] = {
                "config": config.__dict__,
                "aggregate": agg,
                "cases": records,
            }
            _print_summary(config.id, agg)
            if memory:
                for render in renders[:2]:
                    evidence["memory"].append(measure_memory(config, render, workdir))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    evidence["wall_seconds"] = round(time.perf_counter() - started, 2)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(evidence, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"\nwrote {out_path} ({evidence['wall_seconds']} s)")
    return evidence


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 3 modulation benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="print configs and conditions")

    run_cmd = sub.add_parser("run", help="run a candidate set")
    run_cmd.add_argument("--configs", default="A_fixed_50_40")
    run_cmd.add_argument("--renders", default=None, help="comma-separated render ids")
    run_cmd.add_argument("--split", default="train", choices=("train", "heldout", "all"))
    run_cmd.add_argument("--out", default=None)
    run_cmd.add_argument("--memory", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "list":
        for config in CONFIGS.values():
            print(config.describe())
        print("\ntrain:", ", ".join(c.id for c in TRAIN_CONDITIONS))
        print("heldout:", ", ".join(c.id for c in HELDOUT_CONDITIONS))
        print("train renders:", ", ".join(TRAIN_RENDER_IDS))
        return 0

    names = [name.strip() for name in args.configs.split(",") if name.strip()]
    unknown = [name for name in names if name not in CONFIGS]
    if unknown:
        raise SystemExit(f"unknown config(s): {unknown}")
    render_ids = (
        [name.strip() for name in args.renders.split(",") if name.strip()]
        if args.renders
        else None
    )
    run(
        configs=[CONFIGS[name] for name in names],
        renders=_resolve_renders(render_ids),
        conditions=_resolve_conditions(args.split),
        out_path=args.out,
        memory=args.memory,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
