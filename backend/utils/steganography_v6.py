"""InvisioVault V6 — Production Steganography Engine.

Authoritative Implementation based on:
docs/V6_SPECIFICATION.md

Core Features:
1. Matrix (3, 2) Coset Encoding (0.75 flips per 2 bits, 25% change-rate reduction)
2. Interleaved Reed-Solomon RS(255, 223) with Dynamic Group Interleaving (K=4)
3. 10-Round Balanced Feistel Network with AES-256-CTR Round Tables (160 KiB L2 cache fit)
4. Cycle Walking domain restriction onto arbitrary channel domains with runtime guard
5. Two-Tier HKDF-SHA256 key separation from PBKDF2 (600,000 iterations)
6. 57-byte authenticated header with mode-downgrade prevention
7. Exact unpadded payload length preservation and trimming
"""

from __future__ import annotations

import array
import base64
import hashlib
import hmac
import json
import math
import os
import struct
import zlib
from typing import Optional, Union

import numpy as np
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from reedsolo import RSCodec, ReedSolomonError


# ==============================================================================
# 1. Constants & Protocol Identifiers
# ==============================================================================

MAGIC_V6: bytes = b"\xFF\x06"
MODE_PLAIN: int = 0x40
MODE_ENC: int = 0x41

DEFAULT_INTERLEAVE_K: int = 4
SUPPORTED_INTERLEAVE_K: tuple[int, ...] = (1, 2, 4, 8, 16)

HEADER_LEN: int = 57
HEADER_BODY_LEN: int = 25
HEADER_TAG_LEN: int = 32
HEADER_CHANNELS: int = HEADER_LEN * 8  # 456 channels

PBKDF2_ITERATIONS: int = 600_000
SALT_LEN: int = 16

FEISTEL_ROUNDS: int = 10
MAX_CYCLE_WALK_ITERATIONS: int = 100

PLAIN_PUBLIC_SEED: bytes = b"InvisioVault-v6-PlainMode-PublicSeed-2026"

RS_N: int = 255
RS_K: int = 223
RS_PARITY: int = 32
RS_CORRECTION_RADIUS: int = 16

# Module-level Reed-Solomon Codec instance
_RS_CODEC = RSCodec(RS_PARITY)


# ==============================================================================
# 2. Typed Exceptions
# ==============================================================================

class V6SteganographyError(Exception):
    """Base exception for all V6 steganography operations."""


class DowngradeAttackError(V6SteganographyError):
    """Raised when an active mode downgrade attempt is detected."""


class HeaderAuthenticationError(V6SteganographyError):
    """Raised when encrypted header HMAC-SHA256 authentication fails."""


class HeaderIntegrityError(V6SteganographyError):
    """Raised when plain header SHA-256 integrity check fails."""


class CapacityExceededError(V6SteganographyError):
    """Raised when payload exceeds carrier capacity."""


class CycleWalkingExceededError(V6SteganographyError):
    """Raised when permutation cycle walking exceeds iteration limit."""


class ReedSolomonDecodingError(V6SteganographyError):
    """Raised when uncorrectable noise corrupts a Reed-Solomon codeword."""


class ChecksumMismatchError(V6SteganographyError):
    """Raised when plain mode CRC-32 checksum verification fails."""


class DecryptionError(V6SteganographyError):
    """Raised when payload decryption or authentication fails."""


# ==============================================================================
# 3. Cryptographic Key Derivation Schedule
# ==============================================================================

def derive_v6_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive master and subkeys for V6 encrypted mode.

    Returns:
        (k_auth, fernet_key, k_perm_root)
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    k_master = kdf.derive(password)

    k_auth = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"InvisioVault-v6-Header-Auth",
        backend=default_backend(),
    ).derive(k_master)

    k_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"InvisioVault-v6-Payload-Encryption",
        backend=default_backend(),
    ).derive(k_master)
    fernet_key = base64.urlsafe_b64encode(k_enc)

    k_perm_root = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"InvisioVault-v6-Permutation-Root" + salt,
        backend=default_backend(),
    ).derive(k_master)

    return k_auth, fernet_key, k_perm_root


def derive_v6_plain_perm_root(salt: bytes) -> bytes:
    """Derive deterministic permutation root key for V6 plain mode.

    Uses a fixed public seed combined with the header salt so permutation
    is 100% reproducible between embedding and extraction without a password.
    """
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be exactly {SALT_LEN} bytes")

    k_plain_fixed = hashlib.sha256(PLAIN_PUBLIC_SEED).digest()
    k_perm_root = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"InvisioVault-v6-Plain-Permutation-Root" + salt,
        backend=default_backend(),
    ).derive(k_plain_fixed)
    return k_perm_root


def derive_round_keys_and_ivs(k_perm_root: bytes) -> tuple[list[bytes], list[bytes]]:
    """Derive 10 independent round keys (32 bytes) and IVs (16 bytes) via HKDF."""
    round_keys: list[bytes] = []
    round_ivs: list[bytes] = []

    for i in range(FEISTEL_ROUNDS):
        idx_byte = bytes([i])
        k_i = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"InvisioVault-v6-RoundKey-" + idx_byte,
            backend=default_backend(),
        ).derive(k_perm_root)
        iv_i = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"InvisioVault-v6-RoundIV-" + idx_byte,
            backend=default_backend(),
        ).derive(k_perm_root)
        round_keys.append(k_i)
        round_ivs.append(iv_i)

    return round_keys, round_ivs


# ==============================================================================
# 4. Header Serialization and Downgrade Defense
# ==============================================================================

def build_v6_header(
    mode: int,
    salt: bytes,
    raw_payload_len: int,
    k_auth: Optional[bytes] = None,
    interleave_k: int = DEFAULT_INTERLEAVE_K,
) -> bytes:
    """Construct an authenticated 57-byte V6 header.

    Byte Layout:
        0x00 - 0x01: Magic (0xFF 0x06)
        0x02:        Mode (0x40 Plain, 0x41 Encrypted)
        0x03:        Interleave K (default: 4)
        0x04:        Reserved (0x00)
        0x05 - 0x14: Salt (16 bytes)
        0x15 - 0x18: Raw Payload Length (uint32_be)
        0x19 - 0x38: Authentication / Integrity Tag (32 bytes)
    """
    if mode not in (MODE_PLAIN, MODE_ENC):
        raise ValueError(f"Invalid V6 mode: {hex(mode)}")
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes")
    if raw_payload_len <= 0 or raw_payload_len > 0xFFFFFFFF:
        raise ValueError(f"Invalid raw payload length: {raw_payload_len}")
    if interleave_k not in SUPPORTED_INTERLEAVE_K:
        raise ValueError(f"Unsupported interleave K: {interleave_k}")

    body = (
        MAGIC_V6
        + bytes([mode, interleave_k, 0x00])
        + salt
        + struct.pack(">I", raw_payload_len)
    )
    assert len(body) == HEADER_BODY_LEN

    if mode == MODE_ENC:
        if k_auth is None or len(k_auth) != 32:
            raise ValueError("32-byte k_auth required to authenticate encrypted header")
        tag = hmac.new(k_auth, body, hashlib.sha256).digest()
    else:
        tag = hashlib.sha256(body).digest()

    assert len(tag) == HEADER_TAG_LEN
    header = body + tag
    assert len(header) == HEADER_LEN
    return header


def parse_v6_header(
    header_bytes: bytes,
    password: Optional[Union[str, bytes]] = None,
    expected_mode: str = "auto",
) -> tuple[int, int, bytes, int]:
    """Parse and authenticate a 57-byte V6 header.

    Enforces strict mode validation and credential-presence checks to
    prevent silent mode-downgrade attacks.

    Returns:
        (mode, interleave_k, salt, raw_payload_len)
    """
    if len(header_bytes) < HEADER_LEN:
        raise V6SteganographyError(f"Header too short ({len(header_bytes)} bytes < {HEADER_LEN})")

    magic = header_bytes[:2]
    if magic != MAGIC_V6:
        raise V6SteganographyError(f"Invalid magic bytes: expected {MAGIC_V6!r}, got {magic!r}")

    mode = header_bytes[2]
    interleave_k = header_bytes[3]
    reserved = header_bytes[4]
    salt = header_bytes[5:21]
    raw_payload_len = struct.unpack(">I", header_bytes[21:25])[0]
    tag = header_bytes[25:57]
    body = header_bytes[:25]

    if reserved != 0x00:
        raise V6SteganographyError(f"Invalid reserved byte: {hex(reserved)}")
    if mode not in (MODE_PLAIN, MODE_ENC):
        raise V6SteganographyError(f"Unsupported V6 mode: {hex(mode)}")
    if interleave_k not in SUPPORTED_INTERLEAVE_K:
        raise V6SteganographyError(f"Unsupported interleaving depth: {interleave_k}")
    if raw_payload_len <= 0:
        raise V6SteganographyError(f"Invalid raw payload length: {raw_payload_len}")

    # --- Mode Downgrade Defense ---
    has_password = password is not None and (
        (isinstance(password, str) and len(password) > 0)
        or (isinstance(password, bytes) and len(password) > 0)
    )

    if has_password and mode == MODE_PLAIN:
        raise DowngradeAttackError(
            "Carrier claims plain mode (0x40), but a password was provided. "
            "Rejected potential downgrade attack."
        )

    if expected_mode == "encrypted" and mode == MODE_PLAIN:
        raise DowngradeAttackError(
            "Expected encrypted mode, but carrier header specifies plain mode (0x40). "
            "Rejected potential downgrade attack."
        )

    if expected_mode == "plain" and mode == MODE_ENC:
        raise ValueError("Expected plain mode, but carrier is password-encrypted (0x41).")

    # --- Authentication & Integrity Tag Verification ---
    if mode == MODE_ENC:
        if not has_password:
            raise ValueError("Password required to extract encrypted carrier (0x41).")
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        k_auth, _, _ = derive_v6_keys(pw_bytes, salt)
        expected_tag = hmac.new(k_auth, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise HeaderAuthenticationError(
                "Header authentication failed: invalid password or corrupted carrier."
            )
    else:
        expected_tag = hashlib.sha256(body).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise HeaderIntegrityError("Plain header integrity check failed: corrupted carrier.")

    return mode, interleave_k, salt, raw_payload_len


# ==============================================================================
# 5. Ten-Round Feistel Permutation with Cycle Walking
# ==============================================================================

def precompute_feistel_tables(
    k: int, round_keys: list[bytes], round_ivs: list[bytes]
) -> list[array.array]:
    """Precompute 10 Feistel round function lookup tables.

    Uses AES-256-CTR keystream generation. Each table entry is a 16-bit
    unsigned integer masked to k bits. Stored in packed array.array('H').
    Total memory footprint: 10 * 2^k * 2 bytes (160 KiB at k=13).
    """
    if k < 1 or k > 16:
        raise ValueError(f"Unsupported half-block size k={k}")
    if len(round_keys) != FEISTEL_ROUNDS or len(round_ivs) != FEISTEL_ROUNDS:
        raise ValueError(f"Expected {FEISTEL_ROUNDS} round keys and IVs")

    num_entries = 1 << k
    num_bytes = num_entries * 2
    bitmask = num_entries - 1
    tables: list[array.array] = []

    for i in range(FEISTEL_ROUNDS):
        cipher = Cipher(
            algorithms.AES(round_keys[i]),
            modes.CTR(round_ivs[i]),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b"\x00" * num_bytes) + encryptor.finalize()

        # Unpack as little-endian uint16 array
        raw_words = struct.unpack(f"<{num_entries}H", keystream)
        # Apply mask and pack into array('H')
        tbl = array.array("H", (w & bitmask for w in raw_words))
        tables.append(tbl)

    return tables


def feistel_forward_step(x: int, k: int, tables: list[array.array]) -> int:
    """Execute 10-round balanced Feistel forward permutation on 2k-bit integer."""
    mask = (1 << k) - 1
    L = x >> k
    R = x & mask
    for i in range(FEISTEL_ROUNDS):
        L, R = R, L ^ tables[i][R]
    return (R << k) | L


def feistel_inverse_step(y: int, k: int, tables: list[array.array]) -> int:
    """Execute 10-round balanced Feistel inverse permutation on 2k-bit integer."""
    mask = (1 << k) - 1
    R = y >> k
    L = y & mask
    for i in range(FEISTEL_ROUNDS - 1, -1, -1):
        L, R = R ^ tables[i][L], L
    return (L << k) | R


def permute_forward(slot_idx: int, M: int, k: int, tables: list[array.array]) -> int:
    """Permute slot_idx over {0, ..., M-1} using forward cycle walking."""
    if M <= 1:
        return 0
    candidate = slot_idx
    for _ in range(MAX_CYCLE_WALK_ITERATIONS):
        candidate = feistel_forward_step(candidate, k, tables)
        if candidate < M:
            return candidate
    raise CycleWalkingExceededError(
        f"Forward cycle walking exceeded {MAX_CYCLE_WALK_ITERATIONS} iterations for M={M}"
    )


def permute_inverse(slot_idx: int, M: int, k: int, tables: list[array.array]) -> int:
    """Invert permutation over {0, ..., M-1} using inverse cycle walking."""
    if M <= 1:
        return 0
    candidate = slot_idx
    for _ in range(MAX_CYCLE_WALK_ITERATIONS):
        candidate = feistel_inverse_step(candidate, k, tables)
        if candidate < M:
            return candidate
    raise CycleWalkingExceededError(
        f"Inverse cycle walking exceeded {MAX_CYCLE_WALK_ITERATIONS} iterations for M={M}"
    )


# ==============================================================================
# 6. Matrix (3, 2) Coset Embedding
# ==============================================================================

def matrix_3_2_embed(
    c1: int, c2: int, c3: int, m1: int, m2: int
) -> tuple[int, int, int, int]:
    """Embed 2 message bits (m1, m2) into 3 channel bytes (c1, c2, c3).

    Parity check matrix:
        H = [ 1  0  1 ]
            [ 0  1  1 ]
    Modifies at most 1 channel LSB. Preserves all higher channel bits.

    Returns:
        (new_c1, new_c2, new_c3, num_flips)
    """
    b1 = c1 & 1
    b2 = c2 & 1
    b3 = c3 & 1

    s1 = b1 ^ b3
    s2 = b2 ^ b3

    d1 = m1 ^ s1
    d2 = m2 ^ s2

    e1, e2, e3 = 0, 0, 0
    if d1 == 1 and d2 == 0:
        e1 = 1
    elif d1 == 0 and d2 == 1:
        e2 = 1
    elif d1 == 1 and d2 == 1:
        e3 = 1

    new_c1 = c1 ^ e1
    new_c2 = c2 ^ e2
    new_c3 = c3 ^ e3
    flips = e1 + e2 + e3
    return new_c1, new_c2, new_c3, flips


def matrix_3_2_extract(c1: int, c2: int, c3: int) -> tuple[int, int]:
    """Extract 2 message bits (m1, m2) from 3 channel bytes (c1, c2, c3)."""
    b1 = c1 & 1
    b2 = c2 & 1
    b3 = c3 & 1
    m1 = b1 ^ b3
    m2 = b2 ^ b3
    return m1, m2


# ==============================================================================
# 7. Reed-Solomon RS(255, 223) & Dynamic Group Interleaving
# ==============================================================================

def interleave_stream(codewords: list[bytes], K: int = DEFAULT_INTERLEAVE_K) -> bytearray:
    """Interleave N Reed-Solomon codewords of 255 bytes each using dynamic groups.

    Zero padding overhead: operates strictly over N * 255 bytes.
    """
    N = len(codewords)
    interleaved = bytearray(N * RS_N)
    for g in range(0, N, K):
        k_curr = min(K, N - g)
        base = g * RS_N
        for j in range(RS_N):
            for k in range(k_curr):
                interleaved[base + j * k_curr + k] = codewords[g + k][j]
    return interleaved


def deinterleave_stream(
    interleaved: bytes | bytearray, N: int, K: int = DEFAULT_INTERLEAVE_K
) -> list[bytearray]:
    """Deinterleave N * 255 bytes back into N Reed-Solomon codewords."""
    if len(interleaved) != N * RS_N:
        raise ValueError(f"Interleaved stream length {len(interleaved)} != {N * RS_N}")

    codewords = [bytearray(RS_N) for _ in range(N)]
    for g in range(0, N, K):
        k_curr = min(K, N - g)
        base = g * RS_N
        for j in range(RS_N):
            for k in range(k_curr):
                codewords[g + k][j] = interleaved[base + j * k_curr + k]
    return codewords


def rs_encode_stream(pre_rs_stream: bytes, N: int) -> list[bytes]:
    """Encode pre-RS stream (N * 223 bytes) into N RS(255, 223) codewords."""
    if len(pre_rs_stream) != N * RS_K:
        raise ValueError(f"Pre-RS stream length {len(pre_rs_stream)} != {N * RS_K}")

    codewords: list[bytes] = []
    for i in range(N):
        block = pre_rs_stream[i * RS_K : (i + 1) * RS_K]
        cw = _RS_CODEC.encode(block)
        codewords.append(bytes(cw))
    return codewords


def rs_decode_stream(codewords: list[bytearray]) -> bytes:
    """Decode N RS(255, 223) codewords to recover N * 223 bytes."""
    decoded_blocks: list[bytes] = []
    for idx, cw in enumerate(codewords):
        try:
            # RSCodec.decode returns (decoded_message, decoded_message_with_ecc, errata_pos)
            res = _RS_CODEC.decode(cw)
            decoded_blocks.append(bytes(res[0]))
        except ReedSolomonError as e:
            raise ReedSolomonDecodingError(
                f"Reed-Solomon decoding failed on codeword {idx}: uncorrectable corruption"
            ) from e
    return b"".join(decoded_blocks)


# ==============================================================================
# 8. Capacity Calculations
# ==============================================================================

def calculate_v6_capacity(width: int, height: int) -> dict[str, int]:
    """Calculate exact channel, block, and payload capacity for an RGB carrier."""
    total_pixels = width * height
    total_channels = total_pixels * 3
    if total_channels < HEADER_CHANNELS + 3:
        return {
            "total_pixels": total_pixels,
            "total_channels": total_channels,
            "header_channels": HEADER_CHANNELS,
            "payload_channels": 0,
            "available_triplets": 0,
            "max_rs_blocks": 0,
            "max_pre_rs_capacity": 0,
            "max_raw_payload_capacity": 0,
        }

    payload_channels = total_channels - HEADER_CHANNELS
    available_triplets = payload_channels // 3
    # Each triplet holds 2 bits = 0.25 bytes
    max_encoded_bytes = available_triplets // 4
    max_rs_blocks = max_encoded_bytes // RS_N
    max_pre_rs_capacity = max_rs_blocks * RS_K

    return {
        "total_pixels": total_pixels,
        "total_channels": total_channels,
        "header_channels": HEADER_CHANNELS,
        "payload_channels": payload_channels,
        "available_triplets": available_triplets,
        "max_rs_blocks": max_rs_blocks,
        "max_pre_rs_capacity": max_pre_rs_capacity,
        "max_raw_payload_capacity": max_pre_rs_capacity,
    }


# ==============================================================================
# 9. Payload Serialization & Trimming
# ==============================================================================

def serialize_v6_payload(
    payload_data: bytes,
    filename: str,
    is_text: bool,
    compress: bool,
    password: Optional[Union[str, bytes]],
    salt: bytes,
) -> tuple[bytes, int, int]:
    """Prepare, frame, encrypt (or checksum), pad, and serialize payload.

    Returns:
        (pre_rs_stream, raw_payload_len, N)
    """
    # 1. Metadata framing
    metadata = {
        "filename": filename,
        "file_type": "text" if is_text else "file",
        "file_size": len(payload_data),
        "compressed": False,
    }

    body_to_embed = payload_data
    if compress and len(payload_data) > 0:
        compressed_body = zlib.compress(payload_data, level=9)
        if len(compressed_body) < len(payload_data):
            body_to_embed = compressed_body
            metadata["compressed"] = True

    meta_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    if len(meta_bytes) > 0xFFFF:
        raise ValueError(f"Metadata exceeds 65535 bytes: {len(meta_bytes)}")

    framed_plain = struct.pack(">H", len(meta_bytes)) + meta_bytes + body_to_embed

    # 2. Encrypted vs Plain stream framing
    has_password = password is not None and (
        (isinstance(password, str) and len(password) > 0)
        or (isinstance(password, bytes) and len(password) > 0)
    )

    if has_password:
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        _, fernet_key, _ = derive_v6_keys(pw_bytes, salt)
        fernet = Fernet(fernet_key)
        token_b64 = fernet.encrypt(framed_plain)
        raw_payload_stream = base64.urlsafe_b64decode(token_b64)
    else:
        crc = struct.pack(">I", zlib.crc32(framed_plain) & 0xFFFFFFFF)
        raw_payload_stream = crc + framed_plain

    raw_payload_len = len(raw_payload_stream)
    N = (raw_payload_len + (RS_K - 1)) // RS_K
    pre_rs_len = N * RS_K
    padding_len = pre_rs_len - raw_payload_len
    pre_rs_stream = raw_payload_stream + (b"\x00" * padding_len)

    return pre_rs_stream, raw_payload_len, N


def deserialize_v6_payload(
    recovered_pre_rs: bytes,
    raw_payload_len: int,
    mode: int,
    password: Optional[Union[str, bytes]],
    salt: bytes,
) -> tuple[bytes, dict]:
    """Trim padding, decrypt (or verify CRC), unpack metadata, and decompress.

    Returns:
        (original_payload_bytes, metadata_dict)
    """
    if len(recovered_pre_rs) < raw_payload_len:
        raise V6SteganographyError(
            f"Recovered pre-RS stream ({len(recovered_pre_rs)} B) shorter than raw_payload_len ({raw_payload_len} B)"
        )

    # Exact deterministic trimming: zero guessing
    raw_payload_stream = recovered_pre_rs[:raw_payload_len]

    if mode == MODE_ENC:
        if not password:
            raise ValueError("Password required to decrypt encrypted payload")
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        _, fernet_key, _ = derive_v6_keys(pw_bytes, salt)
        fernet = Fernet(fernet_key)
        token_b64 = base64.urlsafe_b64encode(raw_payload_stream)
        try:
            framed_plain = fernet.decrypt(token_b64)
        except Exception as e:
            raise DecryptionError("Payload decryption failed: invalid key or corrupted ciphertext") from e
    else:
        if len(raw_payload_stream) < 4:
            raise V6SteganographyError("Plain payload stream too short to contain CRC-32")
        expected_crc = struct.unpack(">I", raw_payload_stream[:4])[0]
        framed_plain = raw_payload_stream[4:]
        actual_crc = zlib.crc32(framed_plain) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ChecksumMismatchError(
                f"Plain mode CRC-32 mismatch: expected {hex(expected_crc)}, got {hex(actual_crc)}"
            )

    # Parse metadata framing
    if len(framed_plain) < 2:
        raise V6SteganographyError("Corrupted payload: missing metadata length prefix")

    meta_len = struct.unpack(">H", framed_plain[:2])[0]
    if len(framed_plain) < 2 + meta_len:
        raise V6SteganographyError("Corrupted payload: metadata length exceeds available stream")

    meta_json = framed_plain[2 : 2 + meta_len]
    body_data = framed_plain[2 + meta_len :]

    try:
        metadata = json.loads(meta_json.decode("utf-8"))
    except Exception as e:
        raise V6SteganographyError("Failed to parse JSON metadata envelope") from e

    if metadata.get("compressed", False):
        try:
            body_data = zlib.decompress(body_data)
        except Exception as e:
            raise V6SteganographyError("Failed to decompress zlib payload") from e

    metadata["mode"] = "encrypted" if mode == MODE_ENC else "plain"
    return body_data, metadata


# ==============================================================================
# 10. Complete Carrier Image Embedding & Extraction
# ==============================================================================

def embed_v6_into_array(
    rgb_arr: np.ndarray,
    payload_data: bytes,
    password: Optional[Union[str, bytes]] = None,
    filename: str = "secret.bin",
    is_text: bool = False,
    compress: bool = True,
    interleave_k: int = DEFAULT_INTERLEAVE_K,
) -> tuple[np.ndarray, dict]:
    """Embed payload into an RGB NumPy array (H, W, 3) using V6 protocol.

    Modifies rgb_arr in place or returns a modified copy.
    """
    if rgb_arr.ndim != 3 or rgb_arr.shape[2] < 3:
        raise ValueError("Carrier image must be a 3D array with at least 3 channels (RGB)")

    height, width = rgb_arr.shape[:2]
    capacity = calculate_v6_capacity(width, height)
    max_payload_cap = capacity["max_pre_rs_capacity"]

    if max_payload_cap <= 0:
        raise CapacityExceededError(f"Carrier too small ({width}x{height}) to hold V6 header and payload")

    has_password = password is not None and (
        (isinstance(password, str) and len(password) > 0)
        or (isinstance(password, bytes) and len(password) > 0)
    )
    mode = MODE_ENC if has_password else MODE_PLAIN
    pw_bytes = (
        password.encode("utf-8") if isinstance(password, str) else password
    ) if has_password else None

    # Setup permutation parameters based on carrier capacity
    M_triplets = capacity["available_triplets"]
    k_bits = math.ceil(0.5 * math.ceil(math.log2(M_triplets))) if M_triplets > 1 else 1

    MAX_CYCLE_WALK_RETRIES = 5
    for attempt in range(MAX_CYCLE_WALK_RETRIES):
        salt = os.urandom(SALT_LEN)
        try:
            # 1. Serialize and prepare payload with fresh salt
            pre_rs_stream, raw_payload_len, N = serialize_v6_payload(
                payload_data, filename, is_text, compress, pw_bytes, salt
            )

            if len(pre_rs_stream) > max_payload_cap:
                raise CapacityExceededError(
                    f"Payload requiring {len(pre_rs_stream)} B exceeds carrier capacity of {max_payload_cap} B"
                )

            # 2. Derive salt-dependent keys
            if mode == MODE_ENC:
                assert pw_bytes is not None
                k_auth, _, k_perm_root = derive_v6_keys(pw_bytes, salt)
            else:
                k_auth = None
                k_perm_root = derive_v6_plain_perm_root(salt)

            # 3. Build 57-byte authenticated header
            header = build_v6_header(mode, salt, raw_payload_len, k_auth, interleave_k)

            # 4. RS Encode & Interleave
            codewords = rs_encode_stream(pre_rs_stream, N)
            interleaved = interleave_stream(codewords, K=interleave_k)
            total_interleaved_bytes = len(interleaved)
            total_symbols = total_interleaved_bytes * 4

            if total_symbols > M_triplets:
                raise CapacityExceededError(
                    f"Encoded symbols ({total_symbols}) exceeds available carrier triplets ({M_triplets})"
                )

            # 5. Precompute Feistel tables for this attempt
            round_keys, round_ivs = derive_round_keys_and_ivs(k_perm_root)
            tables = precompute_feistel_tables(k_bits, round_keys, round_ivs)

            # 6. Prepare fresh pristine carrier copy for this attempt
            # Ensuring no partial modifications leak from any prior failed attempts
            stego_arr = np.ascontiguousarray(rgb_arr, dtype=np.uint8).copy()
            flat_channels = stego_arr.reshape(-1)

            # 7. Embed Header (sequential in channels 0..455)
            for i in range(HEADER_LEN):
                b = header[i]
                for bit_idx in range(8):
                    ch_idx = i * 8 + bit_idx
                    bit_val = (b >> (7 - bit_idx)) & 1
                    flat_channels[ch_idx] = (flat_channels[ch_idx] & 0xFE) | bit_val

            # 8. Embed Payload using Matrix (3,2) over Feistel-permuted triplets
            total_flips = 0
            for sym_idx in range(total_symbols):
                byte_val = interleaved[sym_idx >> 2]
                shift = (3 - (sym_idx & 3)) << 1
                m1 = (byte_val >> (shift + 1)) & 1
                m2 = (byte_val >> shift) & 1

                # permute_forward may raise CycleWalkingExceededError
                slot = permute_forward(sym_idx, M_triplets, k_bits, tables)
                base_ch = HEADER_CHANNELS + slot * 3

                c1 = int(flat_channels[base_ch])
                c2 = int(flat_channels[base_ch + 1])
                c3 = int(flat_channels[base_ch + 2])

                nc1, nc2, nc3, flips = matrix_3_2_embed(c1, c2, c3, m1, m2)
                flat_channels[base_ch] = nc1
                flat_channels[base_ch + 1] = nc2
                flat_channels[base_ch + 2] = nc3
                total_flips += flips

            metadata_info = {
                "mode": "encrypted" if mode == MODE_ENC else "plain",
                "raw_payload_len": raw_payload_len,
                "rs_blocks": N,
                "interleave_k": interleave_k,
                "total_symbols": total_symbols,
                "total_flips": total_flips,
                "flip_rate": total_flips / (total_symbols * 2) if total_symbols > 0 else 0.0,
                "attempts": attempt + 1,
            }
            return stego_arr, metadata_info

        except CycleWalkingExceededError as err:
            if attempt == MAX_CYCLE_WALK_RETRIES - 1:
                raise CycleWalkingExceededError(
                    f"V6 embedding failed: cycle walking exceeded cutoff across {MAX_CYCLE_WALK_RETRIES} attempts with distinct salts."
                ) from err
            continue

    raise CycleWalkingExceededError(
        f"V6 embedding failed: cycle walking exceeded cutoff across {MAX_CYCLE_WALK_RETRIES} attempts with distinct salts."
    )


def extract_v6_from_array(
    rgb_arr: np.ndarray,
    password: Optional[Union[str, bytes]] = None,
    expected_mode: str = "auto",
) -> tuple[bytes, dict]:
    """Extract payload from an RGB NumPy array (H, W, 3) using V6 protocol.

    Returns:
        (extracted_payload_bytes, metadata_dict)
    """
    if rgb_arr.ndim != 3 or rgb_arr.shape[2] < 3:
        raise ValueError("Carrier image must be a 3D array with at least 3 channels (RGB)")

    height, width = rgb_arr.shape[:2]
    capacity = calculate_v6_capacity(width, height)
    total_channels = capacity["total_channels"]

    if total_channels < HEADER_CHANNELS:
        raise V6SteganographyError("Carrier image too small to contain V6 header")

    flat_channels = np.ascontiguousarray(rgb_arr, dtype=np.uint8).reshape(-1)

    # 1. Extract 57-byte header from channels 0..455
    header_buf = bytearray(HEADER_LEN)
    for i in range(HEADER_LEN):
        val = 0
        for bit_idx in range(8):
            ch_idx = i * 8 + bit_idx
            val = (val << 1) | (int(flat_channels[ch_idx]) & 1)
        header_buf[i] = val

    mode, interleave_k, salt, raw_payload_len = parse_v6_header(
        bytes(header_buf), password=password, expected_mode=expected_mode
    )

    # 2. Derive RS parameters
    N = (raw_payload_len + (RS_K - 1)) // RS_K
    total_interleaved_bytes = N * RS_N
    total_symbols = total_interleaved_bytes * 4

    M_triplets = capacity["available_triplets"]
    if total_symbols > M_triplets:
        raise V6SteganographyError(
            f"Carrier triplets ({M_triplets}) insufficient for header payload length ({total_symbols})"
        )

    # 3. Setup Permutation
    k_bits = math.ceil(0.5 * math.ceil(math.log2(M_triplets))) if M_triplets > 1 else 1
    if mode == MODE_ENC:
        if password is None:
            raise ValueError("Password required to extract encrypted carrier (0x41).")
        pw_bytes = password.encode("utf-8") if isinstance(password, str) else password
        assert pw_bytes is not None
        _, _, k_perm_root = derive_v6_keys(pw_bytes, salt)
    else:
        k_perm_root = derive_v6_plain_perm_root(salt)

    round_keys, round_ivs = derive_round_keys_and_ivs(k_perm_root)
    tables = precompute_feistel_tables(k_bits, round_keys, round_ivs)

    # 4. Extract Interleaved Stream via Matrix (3,2)
    interleaved = bytearray(total_interleaved_bytes)
    for sym_idx in range(total_symbols):
        slot = permute_forward(sym_idx, M_triplets, k_bits, tables)
        base_ch = HEADER_CHANNELS + slot * 3

        c1 = int(flat_channels[base_ch])
        c2 = int(flat_channels[base_ch + 1])
        c3 = int(flat_channels[base_ch + 2])

        m1, m2 = matrix_3_2_extract(c1, c2, c3)
        byte_idx = sym_idx >> 2
        shift = (3 - (sym_idx & 3)) << 1
        interleaved[byte_idx] |= (m1 << (shift + 1)) | (m2 << shift)

    # 5. Deinterleave & RS Decode
    codewords = deinterleave_stream(bytes(interleaved), N, K=interleave_k)
    recovered_pre_rs = rs_decode_stream(codewords)

    # 6. Deserialize, verify CRC / decrypt, unpack metadata
    payload_data, metadata = deserialize_v6_payload(
        recovered_pre_rs, raw_payload_len, mode, password, salt
    )
    return payload_data, metadata


# ==============================================================================
# 11. High-Level File & Text Steganography API
# ==============================================================================

def hide_file_v6(
    image_path: str,
    file_path: str,
    output_path: str,
    password: Optional[str] = None,
    original_filename: Optional[str] = None,
    compress: bool = True,
) -> dict:
    """Hide a file in a PNG image using InvisioVault V6."""
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Host image not found: {image_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Payload file not found: {file_path}")

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    fname = original_filename or os.path.basename(file_path)

    with Image.open(image_path) as img:
        has_alpha = img.mode in ("RGBA", "LA", "PA") or (
            img.mode == "P" and "transparency" in img.info
        )
        if has_alpha:
            rgba = img.convert("RGBA")
            arr = np.array(rgba, dtype=np.uint8)
            rgb_arr = arr[:, :, :3]
            alpha_arr = arr[:, :, 3]
        else:
            img_rgb = img.convert("RGB")
            rgb_arr = np.array(img_rgb, dtype=np.uint8)
            alpha_arr = None

    stego_rgb, info = embed_v6_into_array(
        rgb_arr, file_bytes, password=password, filename=fname, is_text=False, compress=compress
    )

    if has_alpha:
        assert alpha_arr is not None
        stego_arr = np.dstack([stego_rgb, alpha_arr])
        stego_img = Image.fromarray(stego_arr, mode="RGBA")
    else:
        stego_img = Image.fromarray(stego_rgb, mode="RGB")

    stego_img.save(output_path, format="PNG", optimize=False)
    info["output_path"] = output_path
    return info


def extract_file_v6(
    image_path: str,
    output_dir: Optional[str] = None,
    password: Optional[str] = None,
    expected_mode: str = "auto",
) -> tuple[bytes, dict]:
    """Extract a file from a PNG image using InvisioVault V6."""
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Stego image not found: {image_path}")

    with Image.open(image_path) as img:
        if img.mode in ("RGBA", "LA", "PA") or (
            img.mode == "P" and "transparency" in img.info
        ):
            rgba = img.convert("RGBA")
            rgb_arr = np.array(rgba, dtype=np.uint8)[:, :, :3]
        else:
            img_rgb = img.convert("RGB")
            rgb_arr = np.array(img_rgb, dtype=np.uint8)

    payload_bytes, metadata = extract_v6_from_array(
        rgb_arr, password=password, expected_mode=expected_mode
    )

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        out_filename = metadata.get("filename", "extracted_payload.bin")
        out_path = os.path.join(output_dir, out_filename)
        with open(out_path, "wb") as f:
            f.write(payload_bytes)
        metadata["saved_to"] = out_path

    return payload_bytes, metadata


def hide_text_v6(
    image_path: str,
    text: str,
    output_path: str,
    password: Optional[str] = None,
    compress: bool = True,
) -> dict:
    """Hide UTF-8 text in a PNG image using InvisioVault V6."""
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Host image not found: {image_path}")

    text_bytes = text.encode("utf-8")
    with Image.open(image_path) as img:
        has_alpha = img.mode in ("RGBA", "LA", "PA") or (
            img.mode == "P" and "transparency" in img.info
        )
        if has_alpha:
            rgba = img.convert("RGBA")
            arr = np.array(rgba, dtype=np.uint8)
            rgb_arr = arr[:, :, :3]
            alpha_arr = arr[:, :, 3]
        else:
            img_rgb = img.convert("RGB")
            rgb_arr = np.array(img_rgb, dtype=np.uint8)
            alpha_arr = None

    stego_rgb, info = embed_v6_into_array(
        rgb_arr, text_bytes, password=password, filename="text_payload.txt", is_text=True, compress=compress
    )

    if has_alpha:
        assert alpha_arr is not None
        stego_arr = np.dstack([stego_rgb, alpha_arr])
        stego_img = Image.fromarray(stego_arr, mode="RGBA")
    else:
        stego_img = Image.fromarray(stego_rgb, mode="RGB")

    stego_img.save(output_path, format="PNG", optimize=False)
    info["output_path"] = output_path
    return info


def extract_text_v6(
    image_path: str,
    password: Optional[str] = None,
    expected_mode: str = "auto",
) -> tuple[str, dict]:
    """Extract UTF-8 text from a PNG image using InvisioVault V6."""
    payload_bytes, metadata = extract_file_v6(
        image_path, output_dir=None, password=password, expected_mode=expected_mode
    )
    return payload_bytes.decode("utf-8", errors="replace"), metadata

