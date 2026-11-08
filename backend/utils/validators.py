"""File validation utilities.

Security layers for image uploads (C-01 fix):
  1. Extension allowlist           — fast reject of clearly wrong files.
  2. Magic-byte verification       — confirms the raw bytes match the
                                     claimed format (PNG / JPEG / BMP).
  3. Pillow structural validation  — ``Image.open().verify()`` parses
                                     headers and rejects malformed /
                                     truncated / adversarial images.
  4. Pixel-count cap               — prevents decompression-bomb DoS
                                     (e.g. a 1×1 PNG that inflates to
                                     64 000 × 64 000 pixels in RAM).

``PIL.Image.MAX_IMAGE_PIXELS`` is set at *module load time* so it
applies to every ``Image.open()`` call across the whole process —
including calls inside ``steganography.py`` and ``qr_stego.py``.
"""

import logging
import os
import re
from typing import Optional, Tuple

from PIL import Image
from werkzeug.datastructures import FileStorage

logger = logging.getLogger(__name__)

# ── Global Pillow safety cap ─────────────────────────────────────────────────
# Setting this converts Pillow's DecompressionBombWarning into a hard
# DecompressionBombError for *any* image exceeding the limit, regardless
# of which code path opens it. Calibrated for Render 512 MB memory safety:
# 10 megapixels (supports full 4K UHD 3840x2160 = 8.3 MP at ~426 MB peak RSS).
MAX_PIXEL_COUNT = int(os.getenv('MAX_PIXEL_COUNT', '10000000'))  # 10 megapixels safe ceiling for 512 MB RAM
Image.MAX_IMAGE_PIXELS = MAX_PIXEL_COUNT

# ── High-resolution carrier memory guard (Render 512 MB safety) ──────────────
HIGH_RES_PIXEL_THRESHOLD = int(os.getenv('HIGH_RES_PIXEL_THRESHOLD', '4000000'))  # 4 megapixels threshold
MAX_HIGH_RES_PAYLOAD_SIZE = int(os.getenv('MAX_HIGH_RES_PAYLOAD_SIZE', '1048576'))  # 1 MB (1,048,576 bytes) ceiling for carriers > 4 MP

# ── File size limits (bytes) ─────────────────────────────────────────────────
MAX_IMAGE_SIZE = 10 * 1024 * 1024       # 10 MB — carrier images (hide input)
MAX_HIDEABLE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB — files to hide

# Stego images submitted for EXTRACTION are app-generated lossless PNGs of
# the carrier's raw RGB pixels, so they are routinely larger than the carrier
# that was uploaded (a 2 MB JPEG carrier can produce a 12+ MB stego PNG).
# Capping extraction at MAX_IMAGE_SIZE would reject the app's own output.
# The real DoS guards on this path are Flask's MAX_CONTENT_LENGTH (50 MB)
# and the global pixel-count cap above, so we align with the request limit.
MAX_STEGO_IMAGE_SIZE = 50 * 1024 * 1024  # 50 MB — stego images (extract input)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_FILE_EXTENSIONS = {
    'txt', 'pdf', 'mp4', 'apk', 'zip',
    'jpg', 'png', 'doc', 'docx', 'xlsx',
}

# ── Magic-byte signatures ────────────────────────────────────────────────────
# Checked against the first 16 bytes of the uploaded file.  Each key is a
# byte prefix; the value is the set of extensions that signature can appear
# with.  This is deliberately kept tight — we do NOT accept SVG, TIFF, or
# WebP here because the downstream processing (LSB embedding, polyglot
# creation) only supports PNG, JPEG, and BMP.
_IMAGE_MAGIC = {
    b'\x89PNG\r\n\x1a\n': {'png'},            # PNG — full 8-byte signature
    b'\xff\xd8\xff':      {'jpg', 'jpeg'},     # JPEG — SOI + first marker byte
    b'BM':                {'bmp'},             # BMP — "BM" header
}


# ── QR colour validation ──────────────────────────────────────────────────────
#
# A QR symbol needs dark-on-light polarity and enough luminance separation for a
# scanner to binarize it. The functions here are a *cheap pre-filter* only: the
# authority is the post-render zxing decode in the generation self-check, which
# accepts colours that look bad on paper but scan fine (e.g. #00FF00 on white)
# and rejects colours that pass arithmetic but do not binarize (e.g. #AAAAAA on
# white, luma gap ~85).

_HEX_COLOR_RE = re.compile(r'^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$')

# Minimum receiver-side luma separation (0-255) before a colour pair is even
# rendered. Calibrated so #AAAAAA on #FFFFFF passes this filter and must be
# caught by the self-check instead.
MIN_QR_LUMA_DELTA = 64.0


def normalize_hex_color(value: str, default: str) -> str:
    """Expand 3-char hex and upper-case a valid 6-char hex; else return default."""
    if not isinstance(value, str):
        return default
    candidate = value.strip()
    if not _HEX_COLOR_RE.match(candidate):
        return default
    if len(candidate) == 4:
        return '#' + ''.join(ch * 2 for ch in candidate[1:]).upper()
    return candidate.upper()


def hex_to_rgb(value: str) -> Tuple[int, int, int]:
    """Parse ``#RGB``/``#RRGGBB``. Raises ValueError on anything else."""
    if not isinstance(value, str) or not _HEX_COLOR_RE.match(value.strip()):
        raise ValueError(f"Invalid hex colour: {value!r}")
    candidate = value.strip()
    if len(candidate) == 4:
        candidate = '#' + ''.join(ch * 2 for ch in candidate[1:])
    return (
        int(candidate[1:3], 16),
        int(candidate[3:5], 16),
        int(candidate[5:7], 16),
    )


def _srgb_to_linear(channel: int) -> float:
    c = channel / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def qr_relative_luminance(rgb: Tuple[int, int, int]) -> float:
    """WCAG relative luminance (0 = black, 1 = white)."""
    r, g, b = (_srgb_to_linear(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def qr_contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    """WCAG contrast ratio. Advisory only — it is not a QR readability gate."""
    lf = qr_relative_luminance(hex_to_rgb(fg_hex))
    lb = qr_relative_luminance(hex_to_rgb(bg_hex))
    lighter, darker = max(lf, lb), min(lf, lb)
    return (lighter + 0.05) / (darker + 0.05)


def _perceived_luma(rgb: Tuple[int, int, int]) -> float:
    r, g, b = rgb
    return 0.299 * r + 0.587 * g + 0.114 * b


def validate_qr_colors(fg_hex: str, bg_hex: str) -> Tuple[bool, Optional[str]]:
    """Pre-filter a QR colour pair.

    Returns ``(ok, reason)``. Rejects inverted polarity (dark background) and a
    luma gap below :data:`MIN_QR_LUMA_DELTA`. Everything that passes must still
    survive the post-render zxing self-check, which is the real authority.
    """
    try:
        fg = hex_to_rgb(fg_hex)
        bg = hex_to_rgb(bg_hex)
    except ValueError as exc:
        return False, str(exc)

    fg_luma = _perceived_luma(fg)
    bg_luma = _perceived_luma(bg)

    if bg_luma <= fg_luma:
        return False, (
            "The QR foreground must be darker than the background. "
            "Inverted or equal-luminance colours cannot be scanned."
        )

    delta = bg_luma - fg_luma
    if delta < MIN_QR_LUMA_DELTA:
        return False, (
            f"Foreground and background are too similar (luminance gap "
            f"{delta:.0f}, minimum {MIN_QR_LUMA_DELTA:.0f}). "
            "Choose a darker foreground or lighter background."
        )

    return True, None


def validate_file(
    file: FileStorage,
    allowed_extensions: set,
    max_size: int | None = None,
) -> None:
    """Validate an uploaded file's name, extension, and size.

    Args:
        file:               The uploaded file.
        allowed_extensions: Set of allowed lowercase file extensions.
        max_size:           Maximum file size in bytes (optional).

    Raises:
        ValueError: If any check fails.
    """
    if not file:
        raise ValueError("No file provided.")

    if not file.filename:
        raise ValueError("File has no name.")

    if '.' not in file.filename:
        raise ValueError("File has no extension.")

    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in allowed_extensions:
        raise ValueError(
            f"Unsupported file type '.{extension}'. "
            f"Allowed: {', '.join(sorted(allowed_extensions))}"
        )

    # Progressive size validation to prevent memory exhaustion
    if max_size:
        # First check: Use Content-Length header if available
        if file.content_length and file.content_length > max_size:
            raise ValueError(
                f"File too large. Maximum size is {max_size // (1024*1024)} MB"
            )

        # Second check: Determine actual file size by seeking to end
        # This is necessary as content_length may not always be present
        try:
            current_pos = file.stream.tell()
            file.stream.seek(0, 2)  # Seek to end
            size = file.stream.tell()
            file.stream.seek(current_pos)  # Reset to original position

            if size > max_size:
                size_mb = size / (1024 * 1024)
                max_mb = max_size / (1024 * 1024)
                raise ValueError(
                    f"File size ({size_mb:.1f} MB) exceeds maximum of {max_mb:.0f} MB"
                )
        except OSError:
            # If we can't determine size, log warning but allow validation
            # to continue — Flask's MAX_CONTENT_LENGTH still protects us.
            pass


def validate_image(file: FileStorage, max_size: int = MAX_IMAGE_SIZE) -> None:
    """Validate that *file* is a genuine, safe image.

    Performs four checks in order:
      1. Extension + size via :func:`validate_file`.
      2. Magic-byte match against the raw stream bytes.
      3. Pillow structural parse — ``Image.open().verify()`` walks the
         header/chunk tables without fully decompressing pixel data.
      4. Pixel-count cap — rejects images whose decoded dimensions
         exceed ``MAX_PIXEL_COUNT`` (set globally via
         ``Image.MAX_IMAGE_PIXELS``).

    Args:
        file:     The uploaded image.
        max_size: Byte-size cap.  Defaults to ``MAX_IMAGE_SIZE`` (carrier
                  uploads); pass ``MAX_STEGO_IMAGE_SIZE`` for extraction
                  inputs, which are app-generated lossless PNGs and thus
                  legitimately larger than any carrier we accept.

    Raises:
        ValueError: If any check fails.
    """
    # ── 1. Extension + size ──────────────────────────────────────────────
    validate_file(file, ALLOWED_IMAGE_EXTENSIONS, max_size)

    assert file.filename is not None  # guaranteed: validate_file raises if filename is missing
    extension = file.filename.rsplit('.', 1)[1].lower()

    # ── 2. Magic-byte verification ───────────────────────────────────────
    try:
        header = file.stream.read(16)
        file.stream.seek(0)
    except OSError as exc:
        raise ValueError(f"Could not read file header: {exc}")

    if len(header) < 2:
        raise ValueError("File is too small to be a valid image.")

    matched = False
    for signature, valid_extensions in _IMAGE_MAGIC.items():
        if header.startswith(signature):
            # Ensure the magic bytes agree with the claimed extension.
            # Prevents e.g. a JPEG file submitted as .png from slipping
            # through to code that assumes PNG structure.
            if extension not in valid_extensions:
                raise ValueError(
                    f"File content is not a valid .{extension} image "
                    f"(magic bytes indicate a different format)."
                )
            matched = True
            break

    if not matched:
        raise ValueError(
            "File content does not match any supported image format. "
            "Allowed formats: PNG, JPEG, BMP."
        )

    # ── 3. Pillow structural validation & pixel-count cap ────────────────
    # Image.open() only reads headers; .verify() walks chunk tables
    # without fully decompressing pixel data — fast and safe.
    try:
        file.stream.seek(0)
        with Image.open(file.stream) as img:
            width, height = img.size
            pixel_count = width * height
            if pixel_count > MAX_PIXEL_COUNT:
                raise ValueError(
                    f"Image is too large ({width}×{height} = "
                    f"{pixel_count:,} pixels). Maximum is "
                    f"{MAX_PIXEL_COUNT:,} pixels."
                )
            img.verify()  # raises if the structure is broken / adversarial
    except ValueError:
        raise  # re-raise our own pixel-count ValueError
    except Image.DecompressionBombError:
        raise ValueError(
            f"Image is too large: dimensions exceed the maximum supported size "
            f"({MAX_PIXEL_COUNT // 1_000_000} megapixels). "
            f"Please use a smaller image."
        )
    except (Image.UnidentifiedImageError, SyntaxError, OSError):
        # SyntaxError: malformed headers (e.g. truncated PNG IHDR).
        # OSError: raised by some Pillow parsers when the stream ends
        # prematurely mid-verify (e.g. truncated JPEG with valid SOI).
        raise ValueError(
            "The file could not be parsed as a valid image. "
            "It may be corrupted or not a genuine image file."
        )
    except Exception as exc:
        # Catch-all so that a Pillow bug doesn't bypass validation.
        logger.warning("Unexpected error during image validation: %s", exc)
        raise ValueError(
            "The file could not be validated as a safe image."
        )
    finally:
        file.stream.seek(0)


def validate_carrier_payload_limit(carrier_pixels: int, payload_size: int) -> None:
    """Validate that payload size does not exceed the operational memory ceiling
    for high-resolution carriers (> 4 MP).

    Args:
        carrier_pixels: Total pixel count (width * height) of the carrier image.
        payload_size: Size in bytes of the uploaded payload file or text.

    Raises:
        ValueError: If carrier > 4,000,000 pixels and payload exceeds 1,048,576 bytes.
    """
    if carrier_pixels > HIGH_RES_PIXEL_THRESHOLD and payload_size > MAX_HIGH_RES_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload size ({payload_size / (1024 * 1024):.2f} MB) exceeds maximum operational limit "
            f"of {MAX_HIGH_RES_PAYLOAD_SIZE // (1024 * 1024)} MB ({MAX_HIGH_RES_PAYLOAD_SIZE:,} bytes) "
            f"for high-resolution carriers (> 4 megapixels)."
        )


def validate_hideable_file(file: FileStorage, carrier_pixels: Optional[int] = None) -> None:
    """Validate that file can be hidden in an image with size limit.

    If carrier_pixels is provided and exceeds HIGH_RES_PIXEL_THRESHOLD (4 MP),
    enforces MAX_HIGH_RES_PAYLOAD_SIZE (1 MB).
    """
    effective_max = MAX_HIDEABLE_FILE_SIZE
    if carrier_pixels is not None and carrier_pixels > HIGH_RES_PIXEL_THRESHOLD:
        effective_max = MAX_HIGH_RES_PAYLOAD_SIZE

    try:
        validate_file(file, ALLOWED_FILE_EXTENSIONS, effective_max)
    except ValueError as exc:
        if carrier_pixels is not None and carrier_pixels > HIGH_RES_PIXEL_THRESHOLD and "exceeds maximum of" in str(exc):
            try:
                current_pos = file.stream.tell()
                file.stream.seek(0, 2)
                actual_size = file.stream.tell()
                file.stream.seek(current_pos)
            except OSError:
                actual_size = effective_max
            raise ValueError(
                f"Payload size ({actual_size / (1024 * 1024):.2f} MB) exceeds maximum operational limit "
                f"of {MAX_HIGH_RES_PAYLOAD_SIZE // (1024 * 1024)} MB ({MAX_HIGH_RES_PAYLOAD_SIZE:,} bytes) "
                f"for high-resolution carriers (> 4 megapixels)."
            ) from exc
        raise

