"""QR Module Mapping and Spatial Distribution Utilities.

This module enforces ISO/IEC 18004 structural module isolation.
It maps and protects:
  - Finder patterns (7x7) + Separators (1 module white border)
  - Timing patterns (row 6, column 6)
  - Alignment patterns (5x5 patterns according to version table)
  - Format information areas (15 bits around finders)
  - Version information blocks (for version >= 7)
  - Dark module at (4*version + 9, 8)
  - Quiet zone (>= 4 modules)

It extracts the exact set of non-structural "safe data modules" eligible for
steganographic embedding, and provides deterministic pseudo-random permutation
to distribute modifications uniformly across the QR matrix, avoiding clusters
or runs.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
from typing import Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
from PIL import Image
import segno.consts as consts


def get_qr_dimension(version: int) -> int:
    """Return width/height in modules for standard QR version (1 <= version <= 40)."""
    if not (1 <= version <= 40):
        raise ValueError(f"QR version must be between 1 and 40, got {version}")
    return 17 + 4 * version


def get_structural_modules(version: int) -> Set[Tuple[int, int]]:
    """Return the set of (row, col) coordinates for all structural QR modules.

    Args:
        version: QR version (1 to 40).

    Returns:
        Set of (r, c) module coordinates that must NOT be modified.
    """
    size = get_qr_dimension(version)
    structural: Set[Tuple[int, int]] = set()

    # 1. Finder patterns (7x7) + Separators (1 module border) -> 8x8 corner regions
    # Top-left corner: rows 0..8, cols 0..8
    for r in range(9):
        for c in range(9):
            structural.add((r, c))

    # Top-right corner: rows 0..8, cols (size - 8)..size - 1
    for r in range(9):
        for c in range(size - 8, size):
            structural.add((r, c))

    # Bottom-left corner: rows (size - 8)..size - 1, cols 0..8
    for r in range(size - 8, size):
        for c in range(9):
            structural.add((r, c))

    # 2. Timing patterns: row 6 and column 6
    for i in range(size):
        structural.add((6, i))
        structural.add((i, 6))

    # 3. Alignment patterns (version >= 2)
    if version >= 2:
        positions = consts.ALIGNMENT_POS[version - 2]
        min_pos = positions[0]
        max_pos = positions[-1]
        finder_centers = {(min_pos, min_pos), (min_pos, max_pos), (max_pos, min_pos)}
        for x in positions:
            for y in positions:
                if (x, y) in finder_centers:
                    continue
                # Alignment pattern is 5x5 centered at (x, y)
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        structural.add((x + dr, y + dc))

    # 4. Version information areas (version >= 7)
    # Two 3x6 rectangles:
    #   - Upper-right: rows 0..5, cols (size - 11)..(size - 9)
    #   - Lower-left: rows (size - 11)..(size - 9), cols 0..5
    if version >= 7:
        for r in range(6):
            for c in range(size - 11, size - 8):
                structural.add((r, c))
        for r in range(size - 11, size - 8):
            for c in range(6):
                structural.add((r, c))

    # 5. Required Dark Module: always at row (4*version + 9), col 8
    dark_row = 4 * version + 9
    structural.add((dark_row, 8))

    # 6. Center reservation (protects center area up to 15% width from data modulation,
    # ensuring that centered logos do not overwrite or corrupt steganographic bits)
    center = size // 2
    logo_mod_radius = math.ceil((size + 8) * 0.15 / 2) + 1
    for r in range(max(0, center - logo_mod_radius), min(size, center + logo_mod_radius + 1)):
        for c in range(max(0, center - logo_mod_radius), min(size, center + logo_mod_radius + 1)):
            structural.add((r, c))

    return structural


def get_safe_data_modules(version: int) -> List[Tuple[int, int]]:
    """Return an ordered list of safe data module coordinates (row, col).

    Args:
        version: QR version (1 to 40).

    Returns:
        List of safe (r, c) tuples that are free for steganographic embedding.
    """
    size = get_qr_dimension(version)
    structural = get_structural_modules(version)
    safe: List[Tuple[int, int]] = []
    for r in range(size):
        for c in range(size):
            if (r, c) not in structural:
                safe.append((r, c))
    return safe


def deterministic_permute(items: list, seed: bytes) -> list:
    """Deterministically permute a list using an HMAC-SHA256 Fisher-Yates shuffle.

    Args:
        items: List of items to shuffle.
        seed:  Cryptographic seed (e.g., hash of public payload + matrix params).

    Returns:
        New list with items permuted deterministically.
    """
    n = len(items)
    result = list(items)
    counter = 0
    for i in range(n - 1, 0, -1):
        h = hmac.new(seed, struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
        rand_val = struct.unpack(">I", h[:4])[0]
        j = rand_val % (i + 1)
        result[i], result[j] = result[j], result[i]
    return result


def _get_pixel_luma(img: Image.Image, x: int, y: int) -> float:
    """Safely sample pixel luminance from image, handling tuple, scalar, and None."""
    px = img.getpixel((x, y))
    if isinstance(px, tuple):
        return float(px[0])
    if px is not None:
        return float(px)
    return 0.0


def verify_finder_pattern(
    rect: Image.Image,
    r0: int,
    c0: int,
    scale: int = 10,
    min_contrast: float = 10.0,
) -> Tuple[bool, float]:
    """Verify standard 7x7 concentric finder pattern at (r0, c0) using relative contrast.

    Returns:
        (is_valid, threshold) where threshold is the estimated dark/light midpoint.
    """
    # Center 3x3 must be dark: (r0+2..r0+4, c0+2..c0+4)
    center_samples: List[float] = []
    for dr in range(2, 5):
        for dc in range(2, 5):
            center_samples.append(
                _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
            )

    # Ring around center must be light: (r0+1, c0+1..5), (r0+5, c0+1..5) and vertical edges
    ring_samples: List[float] = []
    for dc in range(1, 6):
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + 1) * scale + scale // 2)
        )
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + 5) * scale + scale // 2)
        )
    for dr in range(2, 5):
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + 1) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
        )
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + 5) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
        )

    avg_center = sum(center_samples) / len(center_samples)
    avg_ring = sum(ring_samples) / len(ring_samples)

    # Ring must be lighter than dark center (relative contrast >= min_contrast)
    if avg_ring - avg_center < min_contrast:
        fallback_th = (avg_center + avg_ring) / 2.0 if avg_ring > avg_center else 128.0
        return False, fallback_th

    return True, (avg_center + avg_ring) / 2.0


_verify_finder_pattern = verify_finder_pattern


def find_perspective_coeffs(
    src_pts: Sequence[Tuple[float, float]],
    dst_pts: Sequence[Tuple[float, float]],
) -> np.ndarray:
    """Compute 8-element perspective transform coefficients for Pillow.

    Maps destination coordinates (xd, yd) to source image coordinates (xs, ys):
        xs = (a * xd + b * yd + c) / (g * xd + h * yd + 1)
        ys = (d * xd + e * yd + f) / (g * xd + h * yd + 1)

    Args:
        src_pts: 4 source points [TL, BL, BR, TR] in the input image.
        dst_pts: 4 destination points [TL, BL, BR, TR] in canonical rectangle.

    Returns:
        8-element 1D numpy array (a, b, c, d, e, f, g, h).
    """
    matrix = []
    for (xd, yd), (xs, ys) in zip(dst_pts, src_pts):
        matrix.append([xd, yd, 1.0, 0.0, 0.0, 0.0, -xs * xd, -xs * yd])
        matrix.append([0.0, 0.0, 0.0, xd, yd, 1.0, -ys * xd, -ys * yd])
    A = np.asarray(matrix, dtype=float)
    B = np.asarray(src_pts, dtype=float).reshape(8)
    coeffs, _, _, _ = np.linalg.lstsq(A, B, rcond=None)
    return coeffs.reshape(8)


def get_pattern_centers(version: int) -> Dict[str, Tuple[float, float]]:
    """Return canonical (x, y) coordinates of finder and bottom-right alignment centers in module units."""
    size = get_qr_dimension(version)
    centers = {
        "top_left_finder": (3.5, 3.5),
        "bottom_left_finder": (3.5, size - 3.5),
        "top_right_finder": (size - 3.5, 3.5),
    }
    if version >= 2:
        align_pos = consts.ALIGNMENT_POS[version - 2][-1]
        centers["bottom_right_alignment"] = (align_pos + 0.5, align_pos + 0.5)
    return centers


# ── QR version information (ISO/IEC 18004 §8.9) ──────────────────────────────
#
# Versions 7 and above carry the version number twice as an 18-bit BCH(18, 6)
# codeword. Unlike the timing-pattern heuristic this is error-correcting, so it
# is the authoritative identification when it decodes cleanly. Reimplemented
# here (13-bit generator 0x1F25) and validated against the ZXing known-good
# codewords in the tests; no new dependency.

_VERSION_INFO_GENERATOR = 0x1F25
VERSION_INFO_MIN_VERSION = 7
VERSION_INFO_MAX_ERRORS = 3


def version_info_codeword(version: int) -> int:
    """Return the 18-bit BCH codeword for a QR version (7-40).

    The 6 data bits are the version number; the 12-bit remainder is computed
    with the BCH generator x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1.
    """
    if not VERSION_INFO_MIN_VERSION <= version <= 40:
        raise ValueError(
            f"Version information exists only for versions 7-40, got {version}"
        )
    value = version << 12
    remainder = value
    for bit in range(17, 11, -1):
        if remainder & (1 << bit):
            remainder ^= _VERSION_INFO_GENERATOR << (bit - 12)
    return value | (remainder & 0xFFF)


def decode_version_information(bits: int) -> Tuple[Optional[int], int]:
    """Decode 18 version-information bits.

    Returns ``(version, hamming_distance)``. ``version`` is ``None`` when no
    codeword lies within the 3-bit correction radius, so a damaged block is
    reported as unresolved instead of being silently misread.
    """
    if not isinstance(bits, int) or bits < 0 or bits >= (1 << 18):
        return None, 18
    best_version: Optional[int] = None
    best_distance = 19
    probe = bits
    for version in range(VERSION_INFO_MIN_VERSION, 41):
        distance = bin(probe ^ version_info_codeword(version)).count("1")
        if distance < best_distance:
            best_distance = distance
            best_version = version
            if distance == 0:
                break
    if best_distance > VERSION_INFO_MAX_ERRORS:
        return None, best_distance
    return best_version, best_distance


def _read_version_bits(
    rect: Image.Image,
    size: int,
    block: str,
) -> Optional[int]:
    """Read one 18-bit version block from a rectified module grid.

    Bit order follows the reference implementation: the top-right block is read
    row-major with rows and columns descending; the bottom-left block is read
    column-major with columns and rows descending.
    """
    if size < 45:  # version < 7 has no version information
        return None
    scale = rect.size[0] / float(size)
    gray = np.asarray(rect.convert("L"), dtype=np.float64)
    ij_min = size - 11

    def _sample(module_r: int, module_c: int) -> int:
        x = int(round((module_c + 0.5) * scale))
        y = int(round((module_r + 0.5) * scale))
        x = min(max(x, 0), gray.shape[1] - 1)
        y = min(max(y, 0), gray.shape[0] - 1)
        y0, y1 = max(0, y - 1), min(gray.shape[0], y + 2)
        x0, x1 = max(0, x - 1), min(gray.shape[1], x + 2)
        return int(round(float(np.median(gray[y0:y1, x0:x1]))))

    samples: List[int] = []
    if block == "top_right":
        for row in range(5, -1, -1):
            for col in range(size - 9, ij_min - 1, -1):
                samples.append(_sample(row, col))
    else:
        for col in range(5, -1, -1):
            for row in range(size - 9, ij_min - 1, -1):
                samples.append(_sample(row, col))

    if len(samples) != 18:
        return None

    luma = np.asarray(samples, dtype=np.float64)
    if float(luma.max()) - float(luma.min()) < 8.0:
        return None  # no usable contrast in the version block
    threshold = (float(luma.min()) + float(luma.max())) / 2.0
    bits = 0
    for value in samples:
        bits = (bits << 1) | (1 if value < threshold else 0)
    return bits


def read_version_information(
    rect: Image.Image,
    size: Optional[int] = None,
) -> Tuple[Optional[int], int]:
    """Decode the QR version from a rectified grid.

    Reads both copies and keeps the one with the smallest Hamming distance, so a
    single damaged block does not lose the version. Returns ``(None, 18)`` when
    neither block decodes within the correction radius (or version < 7).
    """
    if size is None:
        size = rect.size[0] // 10
    best_version: Optional[int] = None
    best_distance = 18
    for block in ("top_right", "bottom_left"):
        bits = _read_version_bits(rect, size, block)
        if bits is None:
            continue
        version, distance = decode_version_information(bits)
        if version is not None and distance < best_distance:
            best_version, best_distance = version, distance
    return best_version, best_distance


def detect_qr_version_from_timing(
    img: Image.Image,
    position,
    scale: int = 10,
    min_version: int = 1,
    target_version_hint: Optional[int] = None,
) -> Tuple[Optional[int], Optional[Image.Image]]:
    """Determine the exact QR version by evaluating finder patterns and timing patterns.

    Rectifies candidate version grids using true projective homography (perspective
    transform) from the detected barcode quadrilateral, verifies structural finder
    pattern alignment at top-right and bottom-left, and checks alternating timing
    patterns on row 6 and column 6.

    Args:
        img:                 Pillow image containing the QR code.
        position:            Barcode position object with top_left, bottom_left,
                             bottom_right, and top_right attributes (and optional
                             pattern centroids).
        scale:               Pixel sampling scale factor (default 10).
        min_version:         Minimum candidate QR version based on public data length.
        target_version_hint: Optional candidate version from client detector.

    Returns:
        (best_version, rectified_image) or (None, None) if unresolved.
    """
    src_pts_outer = [
        (float(position.top_left.x), float(position.top_left.y)),
        (float(position.bottom_left.x), float(position.bottom_left.y)),
        (float(position.bottom_right.x), float(position.bottom_right.y)),
        (float(position.top_right.x), float(position.top_right.y)),
    ]
    quad_data = (
        src_pts_outer[0][0], src_pts_outer[0][1],
        src_pts_outer[1][0], src_pts_outer[1][1],
        src_pts_outer[2][0], src_pts_outer[2][1],
        src_pts_outer[3][0], src_pts_outer[3][1],
    )

    best_ver: Optional[int] = None
    best_score = -1.0
    best_rect: Optional[Image.Image] = None

    # Prioritize target_version_hint if provided and valid
    required_score = 0.55 if target_version_hint is not None else 0.60
    candidate_versions: List[int] = []
    if target_version_hint is not None and max(1, min_version) <= target_version_hint <= 40:
        candidate_versions.append(target_version_hint)
    for ver in range(max(1, min_version), 41):
        if ver not in candidate_versions:
            candidate_versions.append(ver)

    for ver in candidate_versions:
        size = get_qr_dimension(ver)
        rect_dim = size * scale

        tl_f = getattr(position, "top_left_finder", None)
        bl_f = getattr(position, "bottom_left_finder", None)
        br_a = getattr(position, "bottom_right_alignment", None)
        tr_f = getattr(position, "top_right_finder", None)

        use_patterns = (
            ver >= 2
            and tl_f is not None
            and bl_f is not None
            and br_a is not None
            and tr_f is not None
        )

        if use_patterns and tl_f is not None and bl_f is not None and br_a is not None and tr_f is not None:
            align_pos = consts.ALIGNMENT_POS[ver - 2][-1]
            src_pts = [
                (float(tl_f.x), float(tl_f.y)),
                (float(bl_f.x), float(bl_f.y)),
                (float(br_a.x), float(br_a.y)),
                (float(tr_f.x), float(tr_f.y)),
            ]
            dst_pts = [
                (3.5 * scale, 3.5 * scale),
                (3.5 * scale, (size - 3.5) * scale),
                ((align_pos + 0.5) * scale, (align_pos + 0.5) * scale),
                ((size - 3.5) * scale, 3.5 * scale),
            ]
        else:
            src_pts = src_pts_outer
            dst_pts = [
                (0.0, 0.0),
                (0.0, float(rect_dim)),
                (float(rect_dim), float(rect_dim)),
                (float(rect_dim), 0.0),
            ]

        # Prepare candidate rectifications:
        # Candidate 1: Bilinear quad mapping (QUAD) — maps straight quadrilateral corners
        # without non-linear perspective homography module compression.
        rect_quad = None
        try:
            rect_quad = img.transform(
                (rect_dim, rect_dim),
                Image.Transform.QUAD,
                quad_data,
                Image.Resampling.BICUBIC,
            )
        except Exception:
            rect_quad = None

        # Candidate 2: Projective homography (PERSPECTIVE)
        coeffs = find_perspective_coeffs(src_pts, dst_pts)
        rect_persp = None
        try:
            rect_persp = img.transform(
                (rect_dim, rect_dim),
                Image.Transform.PERSPECTIVE,
                coeffs.tolist(),
                Image.Resampling.BICUBIC,
            )
        except Exception:
            rect_persp = None

        candidate_rects = [r for r in (rect_quad, rect_persp) if r is not None]

        for rect in candidate_rects:
            # 1. Structural Finder Pattern Verification:
            # Top-right finder is at (0, size - 7); Bottom-left finder is at (size - 7, 0)
            is_hint = (target_version_hint is not None and ver == target_version_hint)
            min_c = 4.0 if is_hint else 10.0
            ok_tr, th_tr = _verify_finder_pattern(rect, 0, size - 7, scale, min_contrast=min_c)
            ok_bl, th_bl = _verify_finder_pattern(rect, size - 7, 0, scale, min_contrast=min_c)
            if not (ok_tr and ok_bl) and not is_hint:
                continue
            # A hint only lowers the contrast bar and orders candidates. It must
            # still earn a plausible timing score below; it is never pre-seeded as
            # the winner, so an invalid hint cannot bypass verification.

            timing_threshold: float = (th_tr + th_bl) / 2.0

            # 2. Timing pattern along row 6 and column 6
            correct = 0
            total = (size - 16) * 2
            if total <= 0:
                best_ver = ver
                best_rect = rect
                break

            for c in range(8, size - 8):
                expected = 1 if (c % 2 == 0) else 0
                luma = _get_pixel_luma(rect, c * scale + scale // 2, 6 * scale + scale // 2)
                detected = 1 if luma < timing_threshold else 0
                if detected == expected:
                    correct += 1

            for r in range(8, size - 8):
                expected = 1 if (r % 2 == 0) else 0
                luma = _get_pixel_luma(rect, 6 * scale + scale // 2, r * scale + scale // 2)
                detected = 1 if luma < timing_threshold else 0
                if detected == expected:
                    correct += 1

            score = correct / total

            # Timing patterns are not error-correcting. At steep perspective or very
            # low capture pitch the score falls below any sane threshold even though
            # the symbol is readable. The BCH version block is error-correcting, so a
            # candidate whose own version information decodes back to itself is
            # eligible on that evidence alone.
            bch_confirmed = False
            if score < required_score:
                try:
                    bch_version_probe, _bch_distance = read_version_information(rect, size)
                except Exception:
                    bch_version_probe = None
                bch_confirmed = bch_version_probe == ver

            if (score >= required_score or bch_confirmed) and score > best_score:
                best_score = score
                best_ver = ver
                best_rect = rect
                if score >= 0.85:  # Confirmed match
                    break

        if best_score >= 0.85:
            break

    # No candidate passed either the timing bar or BCH confirmation: report the
    # grid as unresolved instead of sampling an arbitrary module grid.
    if best_ver is None:
        return None, None

    return best_ver, best_rect
