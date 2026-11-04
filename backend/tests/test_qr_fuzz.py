"""Malformed-input and FEC-boundary tests for the QR payload layer (Phase 0).

Scope in Phase 0 is deliberately small: prove that malformed containers fail
closed with a clear error and never with an unexpected exception or a silent
wrong answer. Phases 4 and 7 extend this file for the v2 FEC/container.
"""

from __future__ import annotations

import struct

import pytest
from reedsolo import RSCodec, ReedSolomonError

from utils import qr_stego
from utils.qr_container import (
    HEADER_SIZE,
    QR_CONTAINER_MAGIC,
    QR_CONTAINER_VERSION,
    _crc16,
    is_ivqr_container,
    pack_qr_container,
    unpack_qr_container,
)

PASSWORD = "fixture-correct-horse-battery"
SECRET = "Malformed input must fail closed, never silently."


def _valid_container(password=None) -> bytes:
    return pack_qr_container(SECRET, password)


# ── Container structure ─────────────────────────────────────────────────────


@pytest.mark.parametrize("length", range(0, HEADER_SIZE))
def test_truncated_containers_are_rejected(length):
    with pytest.raises(ValueError):
        unpack_qr_container(b"\x00" * length)


def test_bad_magic_is_rejected():
    container = bytearray(_valid_container())
    container[0:4] = b"XXXX"
    with pytest.raises(ValueError, match="magic"):
        unpack_qr_container(bytes(container))
    assert not is_ivqr_container(bytes(container))


def test_unsupported_version_is_rejected():
    container = bytearray(_valid_container())
    container[4] = QR_CONTAINER_VERSION + 1
    # Repair the header checksum so the version check is what fires.
    container[14:16] = struct.pack(">H", _crc16(bytes(container[:14])))
    with pytest.raises(ValueError, match="version"):
        unpack_qr_container(bytes(container))


def test_header_checksum_mismatch_is_rejected():
    container = bytearray(_valid_container())
    container[8] ^= 0x01
    with pytest.raises(ValueError, match="header checksum"):
        unpack_qr_container(bytes(container))


def test_payload_length_mismatch_is_rejected():
    container = _valid_container()
    with pytest.raises(ValueError, match="length mismatch"):
        unpack_qr_container(container + b"\x00")


def test_oversized_original_length_is_rejected():
    header_fields = struct.pack(
        ">4sBBII", QR_CONTAINER_MAGIC, QR_CONTAINER_VERSION, 0, 2**31, 4
    )
    container = header_fields + struct.pack(">H", _crc16(header_fields)) + b"\x00" * 4
    with pytest.raises(ValueError, match="original length"):
        unpack_qr_container(container)


def test_short_plain_body_is_rejected():
    header_fields = struct.pack(
        ">4sBBII", QR_CONTAINER_MAGIC, QR_CONTAINER_VERSION, 0, 0, 2
    )
    container = header_fields + struct.pack(">H", _crc16(header_fields)) + b"\x00" * 2
    with pytest.raises(ValueError, match="integrity checksum"):
        unpack_qr_container(container)


def test_short_encrypted_body_is_rejected():
    flags = 0x01  # FLAG_ENCRYPTED, body shorter than salt+1
    header_fields = struct.pack(
        ">4sBBII", QR_CONTAINER_MAGIC, QR_CONTAINER_VERSION, flags, 4, 4
    )
    container = header_fields + struct.pack(">H", _crc16(header_fields)) + b"\x00" * 4
    with pytest.raises(ValueError):
        unpack_qr_container(container, password=PASSWORD)


def test_encrypted_container_requires_a_password():
    container = _valid_container(PASSWORD)
    with pytest.raises(ValueError, match="password"):
        unpack_qr_container(container, password=None)


# ── Tampering ───────────────────────────────────────────────────────────────


def test_every_single_byte_flip_fails_closed():
    """A one-byte change must raise ValueError/QRStegoError, never crash."""
    container = _valid_container(PASSWORD)
    unexpected = []
    for index in range(len(container)):
        mutated = bytearray(container)
        mutated[index] ^= 0xFF
        try:
            unpack_qr_container(bytes(mutated), password=PASSWORD)
        except ValueError:
            continue
        except Exception as exc:  # noqa: BLE001 - the point is to catch surprises
            unexpected.append((index, type(exc).__name__, str(exc)))
            continue
        unexpected.append((index, "accepted", "tampered container decoded"))
    assert not unexpected, unexpected


def test_plaintext_tamper_is_detected_by_crc_not_by_mac():
    """CRC-32 is an accidental-corruption check only, not authentication."""
    container = bytearray(_valid_container())
    # Flip a payload byte; CRC-32 must reject it.
    container[-1] ^= 0xFF
    with pytest.raises(ValueError):
        unpack_qr_container(bytes(container))


# ── FEC boundaries (pinned reedsolo semantics) ──────────────────────────────


def test_reedsolo_signature_supports_erasure_positions():
    """Phase 2 depends on this exact signature; verify it before relying on it."""
    codec = RSCodec(32)
    original = bytes(range(50))
    encoded = bytes(codec.encode(original))

    decoded, _, _ = codec.decode(bytearray(encoded), erase_pos=[])
    assert decoded == original

    # 32 erasures (== parity) must be recoverable.
    damaged = bytearray(encoded)
    positions = list(range(0, 32))
    for pos in positions:
        damaged[pos] = 0x00
    decoded, _, _ = codec.decode(damaged, erase_pos=positions)
    assert decoded == original


def test_error_correction_budget_matches_parity_over_two():
    codec = RSCodec(32)
    original = bytes(range(50))
    encoded = bytearray(codec.encode(original))

    # 16 symbol errors is the correction limit for parity 32.
    damaged = bytearray(encoded)
    for pos in range(16):
        damaged[pos] ^= 0x5A
    decoded, _, _ = codec.decode(damaged)
    assert decoded == original

    # 17 errors is beyond budget: it must not silently return the original.
    beyond = bytearray(encoded)
    for pos in range(17):
        beyond[pos] ^= 0x5A
    try:
        decoded, _, _ = codec.decode(beyond)
    except ReedSolomonError:
        return
    assert decoded != original, "decoder silently reported success beyond parity budget"


def test_erasure_budget_is_parity_not_twice_parity():
    """The review corrected an earlier claim: p parity corrects at most p erasures."""
    codec = RSCodec(32)
    original = bytes(range(50))
    encoded = bytearray(codec.encode(original))

    too_many = bytearray(encoded)
    positions = list(range(0, 33))
    for pos in positions:
        too_many[pos] = 0x00
    try:
        decoded, _, _ = codec.decode(too_many, erase_pos=positions)
    except ReedSolomonError:
        return
    assert decoded != original, "33 erasures unexpectedly recovered: re-check erasure semantics"


# ── Payload decode path ─────────────────────────────────────────────────────


def test_decode_payload_empty_is_rejected():
    with pytest.raises(qr_stego.QRStegoError) as ctx:
        qr_stego._decode_payload("", None)
    assert ctx.value.error_code is qr_stego.QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED


def test_decode_payload_never_raises_unexpected_exceptions():
    """Garbage input may be rejected or (legacy formats) misread, but must not
    escape as a non-QRStegoError exception: the route maps only QRStegoError."""
    import base64
    import random

    rnd = random.Random(4242)
    samples = ["", "!!!not-base64!!!", "AAAA", "a" * 64]
    samples += [
        base64.urlsafe_b64encode(bytes(rnd.getrandbits(8) for _ in range(n))).decode()
        for n in (1, 4, 15, 16, 17, 40, 128)
    ]
    for payload in samples:
        try:
            qr_stego._decode_payload(payload, None)
        except qr_stego.QRStegoError:
            continue
        except Exception as exc:  # noqa: BLE001 - the point is to catch surprises
            pytest.fail(f"payload {payload!r} raised {type(exc).__name__}: {exc}")
