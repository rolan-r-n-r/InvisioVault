"""Comprehensive unit and integration test suite for InvisioVault V6.

Tests all specified modules in backend/utils/steganography_v6.py:
1. Cryptographic Key Derivation & AEAD (Fernet + PBKDF2 + HKDF)
2. 57-Byte Header Serialization & Downgrade Attack Defense
3. 10-Round Balanced Feistel Permutation with Cycle Walking
4. Matrix (3, 2) Coset Embedding & Syndrome Extraction
5. Reed-Solomon RS(255, 223) & Dynamic Group Interleaving
6. Deterministic Test Vectors
7. End-to-End Image Embedding & Extraction (Plain & Encrypted)
"""

import array
import hashlib
import hmac
import io
import math
import os
import struct
import sys
import tempfile
import zlib
import pytest
import numpy as np
from PIL import Image

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from utils.steganography_v6 import (
    MAGIC_V6,
    MODE_PLAIN,
    MODE_ENC,
    HEADER_LEN,
    HEADER_CHANNELS,
    RS_N,
    RS_K,
    RS_PARITY,
    FEISTEL_ROUNDS,
    V6SteganographyError,
    DowngradeAttackError,
    HeaderAuthenticationError,
    HeaderIntegrityError,
    CapacityExceededError,
    CycleWalkingExceededError,
    ReedSolomonDecodingError,
    ChecksumMismatchError,
    DecryptionError,
    derive_v6_keys,
    derive_v6_plain_perm_root,
    derive_round_keys_and_ivs,
    build_v6_header,
    parse_v6_header,
    precompute_feistel_tables,
    feistel_forward_step,
    feistel_inverse_step,
    permute_forward,
    permute_inverse,
    matrix_3_2_embed,
    matrix_3_2_extract,
    interleave_stream,
    deinterleave_stream,
    rs_encode_stream,
    rs_decode_stream,
    calculate_v6_capacity,
    serialize_v6_payload,
    deserialize_v6_payload,
    embed_v6_into_array,
    extract_v6_from_array,
    hide_file_v6,
    extract_file_v6,
    hide_text_v6,
    extract_text_v6,
)


# ==============================================================================
# 1. Cryptography Tests
# ==============================================================================

def test_key_derivation_reproducibility():
    """Verify that identical password + salt yields identical derived keys."""
    password = b"TestPassword-V6"
    salt = b"\x01" * 16

    k_auth1, fernet_key1, k_perm1 = derive_v6_keys(password, salt)
    k_auth2, fernet_key2, k_perm2 = derive_v6_keys(password, salt)

    assert k_auth1 == k_auth2
    assert fernet_key1 == fernet_key2
    assert k_perm1 == k_perm2
    assert len(k_auth1) == 32
    assert len(fernet_key1) == 44  # Base64url encoded 32 bytes
    assert len(k_perm1) == 32


def test_key_derivation_salt_sensitivity():
    """Different salts must produce cryptographically uncorrelated keys."""
    password = b"TestPassword-V6"
    salt1 = b"\x01" * 16
    salt2 = b"\x02" * 16

    k_auth1, _, k_perm1 = derive_v6_keys(password, salt1)
    k_auth2, _, k_perm2 = derive_v6_keys(password, salt2)

    assert k_auth1 != k_auth2
    assert k_perm1 != k_perm2


def test_plain_mode_perm_root_deterministic():
    """Plain mode permutation root must be deterministic across calls with same salt."""
    salt = b"\xAA" * 16
    root1 = derive_v6_plain_perm_root(salt)
    root2 = derive_v6_plain_perm_root(salt)
    assert root1 == root2
    assert len(root1) == 32


def test_round_keys_and_ivs_count_and_uniqueness():
    """10 rounds must each have a unique 32-byte key and 16-byte IV."""
    root = b"\x55" * 32
    keys, ivs = derive_round_keys_and_ivs(root)

    assert len(keys) == FEISTEL_ROUNDS
    assert len(ivs) == FEISTEL_ROUNDS
    assert len(set(keys)) == FEISTEL_ROUNDS
    assert len(set(ivs)) == FEISTEL_ROUNDS
    for k, iv in zip(keys, ivs):
        assert len(k) == 32
        assert len(iv) == 16


# ==============================================================================
# 2. Header Serialization & Downgrade Attack Defense Tests
# ==============================================================================

def test_header_serialization_layout():
    """Verify exact 57-byte layout and field placement."""
    salt = b"\x33" * 16
    raw_payload_len = 1000
    k_auth = b"\x44" * 32

    header = build_v6_header(MODE_ENC, salt, raw_payload_len, k_auth, interleave_k=4)
    assert len(header) == HEADER_LEN

    assert header[:2] == MAGIC_V6
    assert header[2] == MODE_ENC
    assert header[3] == 4
    assert header[4] == 0x00
    assert header[5:21] == salt
    assert struct.unpack(">I", header[21:25])[0] == raw_payload_len

    # Verify HMAC tag over body
    expected_tag = hmac.new(k_auth, header[:25], hashlib.sha256).digest()
    assert header[25:57] == expected_tag


def test_header_parse_encrypted_success():
    salt = b"\x12" * 16
    password = "CorrectPassword123"
    k_auth, _, _ = derive_v6_keys(password.encode("utf-8"), salt)

    header = build_v6_header(MODE_ENC, salt, 500, k_auth, interleave_k=4)
    mode, k, out_salt, length = parse_v6_header(header, password=password, expected_mode="auto")

    assert mode == MODE_ENC
    assert k == 4
    assert out_salt == salt
    assert length == 500


def test_header_parse_plain_success():
    salt = b"\x99" * 16
    header = build_v6_header(MODE_PLAIN, salt, 750, k_auth=None, interleave_k=4)
    mode, k, out_salt, length = parse_v6_header(header, password=None, expected_mode="auto")

    assert mode == MODE_PLAIN
    assert k == 4
    assert out_salt == salt
    assert length == 750


def test_header_parse_wrong_password():
    salt = b"\x12" * 16
    k_auth, _, _ = derive_v6_keys(b"CorrectPass", salt)
    header = build_v6_header(MODE_ENC, salt, 500, k_auth)

    with pytest.raises(HeaderAuthenticationError):
        parse_v6_header(header, password="WrongPassword")


def test_header_parse_corrupted_plain_tag():
    salt = b"\x12" * 16
    header = bytearray(build_v6_header(MODE_PLAIN, salt, 500))
    header[30] ^= 0xFF  # Corrupt tag

    with pytest.raises(HeaderIntegrityError):
        parse_v6_header(bytes(header), password=None)


def test_header_downgrade_attack_with_password_provided():
    """If user provides a password, a plain-mode (0x40) carrier must be rejected immediately."""
    salt = b"\x77" * 16
    plain_header = build_v6_header(MODE_PLAIN, salt, 1200)

    with pytest.raises(DowngradeAttackError):
        parse_v6_header(plain_header, password="AttackerVictimPassword")


def test_header_downgrade_attack_expected_mode_enforcement():
    """If caller expects encrypted mode, plain mode must be rejected as DowngradeAttackError."""
    salt = b"\x77" * 16
    plain_header = build_v6_header(MODE_PLAIN, salt, 1200)

    with pytest.raises(DowngradeAttackError):
        parse_v6_header(plain_header, password=None, expected_mode="encrypted")


def test_header_invalid_magic_or_reserved():
    salt = b"\x00" * 16
    header_bad_magic = b"\xFF\x05" + build_v6_header(MODE_PLAIN, salt, 100)[2:]
    with pytest.raises(V6SteganographyError, match="Invalid magic"):
        parse_v6_header(header_bad_magic)

    header_bad_res = bytearray(build_v6_header(MODE_PLAIN, salt, 100))
    header_bad_res[4] = 0x01
    with pytest.raises(V6SteganographyError, match="reserved"):
        parse_v6_header(bytes(header_bad_res))


# ==============================================================================
# 3. Feistel Permutation and Cycle Walking Tests
# ==============================================================================

def test_feistel_table_generation_and_l2_footprint():
    """Verify table sizes, packed array format, and memory consumption."""
    root = b"\xDE\xAD\xBE\xEF" * 8
    keys, ivs = derive_round_keys_and_ivs(root)

    # For k=13 (10 MP carrier)
    tables = precompute_feistel_tables(13, keys, ivs)
    assert len(tables) == 10
    total_bytes = sum(len(t) * t.itemsize for t in tables)
    assert total_bytes == 160 * 1024  # Exactly 160 KiB
    assert all(isinstance(t, array.array) for t in tables)
    assert all(t.typecode == "H" for t in tables)

    # Check mask: all entries must be < 2^13 = 8192
    for t in tables:
        assert all(entry < 8192 for entry in t)


def test_feistel_forward_inverse_exhaustion_small_domain():
    """Verify complete invertibility E_K^-1(E_K(x)) == x for all elements in small domain."""
    k = 4  # 8-bit domain: 256 elements
    root = b"\x12\x34\x56\x78" * 8
    keys, ivs = derive_round_keys_and_ivs(root)
    tables = precompute_feistel_tables(k, keys, ivs)

    domain_size = 1 << (2 * k)
    outputs = set()
    for x in range(domain_size):
        enc = feistel_forward_step(x, k, tables)
        dec = feistel_inverse_step(enc, k, tables)
        assert dec == x, f"Invertibility failed at x={x}"
        outputs.add(enc)

    assert len(outputs) == domain_size, "Feistel step must be a strict bijection (no collisions)"


def test_cycle_walking_bijectivity_non_power_of_two():
    """Verify that cycle walking over non-power-of-two domain M produces a strict permutation."""
    test_domains = [5, 11, 23, 50, 100, 250, 1000]
    root = b"\xAB\xCD\xEF\x01" * 8
    keys, ivs = derive_round_keys_and_ivs(root)

    for M in test_domains:
        k = math.ceil(0.5 * math.ceil(math.log2(M)))
        tables = precompute_feistel_tables(k, keys, ivs)

        permuted = [permute_forward(x, M, k, tables) for x in range(M)]
        assert len(set(permuted)) == M, f"Cycle walking produced collisions on domain M={M}"
        assert set(permuted) == set(range(M)), f"Cycle walking range does not match {M}"

        # Verify inverse
        for x in range(M):
            fwd = permuted[x]
            inv = permute_inverse(fwd, M, k, tables)
            assert inv == x, f"Inverse cycle walking failed at M={M}, x={x}"


# ==============================================================================
# 4. Matrix (3, 2) Coset Coding Tests
# ==============================================================================

def test_matrix_3_2_exhaustive_all_32_inputs():
    """Verify Matrix (3,2) encoding and extraction across all 32 combinations."""
    total_flips = 0
    total_trials = 0

    for c1 in (0, 1):
        for c2 in (0, 1):
            for c3 in (0, 1):
                for m1 in (0, 1):
                    for m2 in (0, 1):
                        nc1, nc2, nc3, flips = matrix_3_2_embed(c1, c2, c3, m1, m2)
                        ext_m1, ext_m2 = matrix_3_2_extract(nc1, nc2, nc3)

                        assert (ext_m1, ext_m2) == (m1, m2)
                        assert flips in (0, 1), f"More than 1 flip: {flips}"
                        total_flips += flips
                        total_trials += 1

    avg_flips_per_2bits = total_flips / total_trials
    avg_flips_per_bit = avg_flips_per_2bits / 2.0
    reduction = (0.50 - avg_flips_per_bit) / 0.50

    assert avg_flips_per_2bits == 0.75
    assert avg_flips_per_bit == 0.375
    assert abs(reduction - 0.25) < 1e-7, "Carrier modification reduction must be strictly 25.00%"


def test_matrix_3_2_preserves_higher_bits():
    """Verify non-LSB channel bits are untouched."""
    c1, c2, c3 = 200, 155, 76
    m1, m2 = 1, 0

    nc1, nc2, nc3, _ = matrix_3_2_embed(c1, c2, c3, m1, m2)
    assert (nc1 & 0xFE) == (c1 & 0xFE)
    assert (nc2 & 0xFE) == (c2 & 0xFE)
    assert (nc3 & 0xFE) == (c3 & 0xFE)


# ==============================================================================
# 5. Reed-Solomon & Dynamic Interleaving Tests
# ==============================================================================

def test_rs_encode_decode_clean_stream():
    """Verify RS encode and decode roundtrip for multi-block streams."""
    N = 3
    pre_rs = bytes([(i * 17) % 256 for i in range(N * RS_K)])
    codewords = rs_encode_stream(pre_rs, N)
    assert len(codewords) == N
    assert all(len(c) == RS_N for c in codewords)

    recovered = rs_decode_stream([bytearray(c) for c in codewords])
    assert recovered == pre_rs


def test_rs_error_correction_up_to_16_symbols():
    """Each codeword must correct up to 16 byte corruptions."""
    data = b"B" * RS_K
    codewords = rs_encode_stream(data, 1)
    cw = bytearray(codewords[0])

    # Corrupt 16 bytes
    for i in range(16):
        cw[i * 5] ^= 0xFF

    recovered = rs_decode_stream([cw])
    assert recovered == data


def test_rs_error_correction_outside_guaranteed_radius_detected():
    """17 symbol errors (spaced across cw[i*5] ^= 0xFF) exceed the guaranteed radius t=16.

    In this specific tested corruption pattern, the error vector is detected as uncorrectable
    and raises ReedSolomonDecodingError. Note: In coding theory, errors exceeding t=16 fall
    outside the guaranteed correction radius, where decoders may either detect uncorrectable
    corruption or risk undetected miscorrection.
    """
    data = b"C" * RS_K
    codewords = rs_encode_stream(data, 1)
    cw = bytearray(codewords[0])

    # Corrupt 17 bytes at deterministic positions
    for i in range(17):
        cw[i * 5] ^= 0xFF

    with pytest.raises(ReedSolomonDecodingError):
        rs_decode_stream([cw])


def test_dynamic_interleaving_burst_guarantees():
    """Test documented burst bounds across K=4, 3, 2, 1 configurations."""
    test_cases = [
        (4, 64, 65),  # Complete group
        (3, 48, 49),  # Partial group of 3
        (2, 32, 33),  # Partial group of 2
        (1, 16, 17),  # Single codeword
    ]

    for num_cw, pass_len, fail_len in test_cases:
        test_data = bytes([(i * 3 + j) % 256 for i in range(num_cw) for j in range(RS_K)])
        codewords = rs_encode_stream(test_data, num_cw)
        interleaved = interleave_stream(codewords, K=4)

        # 1. Test passing burst
        corrupted_pass = bytearray(interleaved)
        for b in range(pass_len):
            corrupted_pass[40 + b] ^= 0xFF
        deint_pass = deinterleave_stream(bytes(corrupted_pass), num_cw, K=4)
        rec_pass = rs_decode_stream(deint_pass)
        assert rec_pass == test_data, f"Failed to recover {pass_len}-byte burst on K={num_cw}"

        # 2. Test failing burst
        corrupted_fail = bytearray(interleaved)
        for b in range(fail_len):
            corrupted_fail[40 + b] ^= 0xFF
        deint_fail = deinterleave_stream(bytes(corrupted_fail), num_cw, K=4)
        with pytest.raises(ReedSolomonDecodingError):
            rs_decode_stream(deint_fail)


# ==============================================================================
# 6. Payload Serialization & Trimming Roundtrip Tests
# ==============================================================================

@pytest.mark.parametrize("payload_len", [1, 5, 222, 223, 224, 445, 446, 447, 1000])
def test_payload_serialization_trimming_encrypted(payload_len):
    """Verify non-aligned payloads are trimmed cleanly without trailing zeros corruption."""
    pattern = b"\x00\xFF\x00\xAA"
    payload = (pattern * (payload_len // len(pattern) + 1))[:payload_len]
    assert len(payload) == payload_len

    salt = b"\x22" * 16
    password = "StrongPassword99"

    pre_rs, raw_len, N = serialize_v6_payload(
        payload, "test.bin", is_text=False, compress=False, password=password, salt=salt
    )
    assert len(pre_rs) == N * RS_K
    assert len(pre_rs) >= raw_len

    # Simulate RS roundtrip
    cws = rs_encode_stream(pre_rs, N)
    rec_pre_rs = rs_decode_stream([bytearray(c) for c in cws])

    recovered_payload, meta = deserialize_v6_payload(
        rec_pre_rs, raw_len, MODE_ENC, password, salt
    )
    assert recovered_payload == payload
    assert meta["filename"] == "test.bin"
    assert meta["file_size"] == payload_len


@pytest.mark.parametrize("payload_len", [1, 15, 222, 223, 224, 500])
def test_payload_serialization_trimming_plain_crc(payload_len):
    """Verify plain mode CRC-32 succeeds on non-aligned lengths with exact trimming."""
    payload = b"PlainTextData-" * (payload_len // 14 + 1)
    payload = payload[:payload_len]

    salt = b"\x88" * 16
    pre_rs, raw_len, N = serialize_v6_payload(
        payload, "plain.txt", is_text=True, compress=False, password=None, salt=salt
    )

    cws = rs_encode_stream(pre_rs, N)
    rec_pre_rs = rs_decode_stream([bytearray(c) for c in cws])

    recovered_payload, meta = deserialize_v6_payload(
        rec_pre_rs, raw_len, MODE_PLAIN, password=None, salt=salt
    )
    assert recovered_payload == payload
    assert meta["file_type"] == "text"


# ==============================================================================
# 7. End-to-End Image Steganography Tests
# ==============================================================================

def test_e2e_text_plain_mode(tmp_path):
    """Embed and extract UTF-8 text in plain mode."""
    # Create small host image (150x150 = 22,500 pixels = 67,500 channels)
    host_path = str(tmp_path / "host.png")
    stego_path = str(tmp_path / "stego.png")

    img = Image.new("RGB", (150, 150), color=(128, 64, 32))
    img.save(host_path, format="PNG")

    message = "Hello, InvisioVault V6! Plain mode text hiding with Matrix (3,2)."
    info = hide_text_v6(host_path, message, stego_path, password=None)
    assert info["mode"] == "plain"
    assert info["flip_rate"] <= 0.375 + 0.05

    extracted_text, meta = extract_text_v6(stego_path, password=None, expected_mode="plain")
    assert extracted_text == message
    assert meta["file_type"] == "text"


def test_e2e_file_encrypted_mode_with_trailing_zeros(tmp_path):
    """Embed and extract binary file containing trailing zeros in encrypted mode."""
    host_path = str(tmp_path / "host_enc.png")
    stego_path = str(tmp_path / "stego_enc.png")
    payload_path = str(tmp_path / "secret.bin")
    out_dir = str(tmp_path / "extracted")

    img = Image.new("RGB", (200, 200), color=(50, 100, 150))
    img.save(host_path, format="PNG")

    # Payload with deliberately tricky trailing zero bytes
    secret_bytes = b"\xDE\xAD\xBE\xEF" + (b"\x00" * 350)
    with open(payload_path, "wb") as f:
        f.write(secret_bytes)

    password = "V6-Strong-Password-2026!"
    info = hide_file_v6(host_path, payload_path, stego_path, password=password)
    assert info["mode"] == "encrypted"

    extracted_bytes, meta = extract_file_v6(
        stego_path, output_dir=out_dir, password=password, expected_mode="encrypted"
    )
    assert extracted_bytes == secret_bytes
    assert meta["filename"] == "secret.bin"
    assert meta["file_size"] == len(secret_bytes)


def test_e2e_wrong_password_rejection(tmp_path):
    """Wrong password must be rejected at header authentication before decoding."""
    host_path = str(tmp_path / "host_pw.png")
    stego_path = str(tmp_path / "stego_pw.png")

    img = Image.new("RGB", (100, 100), color=(200, 200, 200))
    img.save(host_path, format="PNG")

    hide_text_v6(host_path, "Secret Text", stego_path, password="RightPassword")

    with pytest.raises(HeaderAuthenticationError):
        extract_text_v6(stego_path, password="WrongPassword")


def test_e2e_capacity_exceeded(tmp_path):
    """Carrier smaller than required RS payload must raise CapacityExceededError."""
    host_path = str(tmp_path / "tiny.png")
    stego_path = str(tmp_path / "tiny_stego.png")

    # 15x15 = 225 pixels = 675 channels (Header needs 456, remaining 219 channels < 1 RS block)
    img = Image.new("RGB", (15, 15), color=(0, 0, 0))
    img.save(host_path, format="PNG")

    large_payload = "A" * 5000
    with pytest.raises(CapacityExceededError):
        hide_text_v6(host_path, large_payload, stego_path)


# ==============================================================================
# 8. Deterministic Test Vectors
# ==============================================================================

def test_deterministic_vector_key_derivation():
    """Validate exact known cryptographic outputs for fixed inputs."""
    password = b"InvisioVault-V6-Deterministic-Password"
    salt = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

    k_auth, fernet_key, k_perm_root = derive_v6_keys(password, salt)

    # Expected SHA256 fingerprints of derived secrets
    auth_hash = hashlib.sha256(k_auth).hexdigest()
    perm_hash = hashlib.sha256(k_perm_root).hexdigest()

    assert len(k_auth) == 32
    assert len(k_perm_root) == 32
    assert len(fernet_key) == 44

    # Exact known-answer test vectors derived from frozen specification
    assert auth_hash == "7ebbd48f59de107958ed15552bebf525a100f0d6d85a5683e686fc365cb6cf36"
    assert perm_hash == "c61acea571494ebabbd41217d96bf6df0e1a33c629e2c1259eba4e9eb45f346c"
    assert fernet_key == b"wKhWZVSLspeimf2TjH9qdYoWwTid_rpf15dUV4vbFJ8="


def test_deterministic_vector_feistel_step():
    """Verify fixed Feistel step output for fixed keys."""
    root = b"\x42" * 32
    keys, ivs = derive_round_keys_and_ivs(root)
    tables = precompute_feistel_tables(4, keys, ivs)

    # Evaluate fixed inputs
    out_0 = feistel_forward_step(0, 4, tables)
    out_1 = feistel_forward_step(1, 4, tables)
    out_255 = feistel_forward_step(255, 4, tables)

    # Must be deterministic and within 8-bit domain [0, 255]
    assert 0 <= out_0 <= 255
    assert 0 <= out_1 <= 255
    assert 0 <= out_255 <= 255
    assert len({out_0, out_1, out_255}) == 3

    # Inverses must match exactly
    assert feistel_inverse_step(out_0, 4, tables) == 0
    assert feistel_inverse_step(out_1, 4, tables) == 1
    assert feistel_inverse_step(out_255, 4, tables) == 255


# ==============================================================================
# 9. Cycle-Walking Retry Tests
# ==============================================================================

def test_cycle_walking_retry_first_fails_second_succeeds(monkeypatch):
    """Test that if attempt 1 encounters CycleWalkingExceededError, attempt 2 retries and succeeds."""
    import utils.steganography_v6 as v6

    carrier = np.full((150, 150, 3), 128, dtype=np.uint8)
    payload = b"CycleWalkRetryTestPayload"

    original_permute = v6.permute_forward
    call_counts = {"permute_calls": 0, "failures_injected": 0}

    def flaky_permute(slot_idx, M, k, tables):
        call_counts["permute_calls"] += 1
        # On the very first attempt, fail on slot_idx == 10
        if call_counts["failures_injected"] == 0 and slot_idx == 10:
            call_counts["failures_injected"] += 1
            raise v6.CycleWalkingExceededError("Injected simulated cycle walk cutoff")
        return original_permute(slot_idx, M, k, tables)

    monkeypatch.setattr(v6, "permute_forward", flaky_permute)

    stego_arr, info = v6.embed_v6_into_array(carrier, payload, password="RetryPassword123")

    assert info["attempts"] == 2
    assert call_counts["failures_injected"] == 1

    # Verify extracted payload matches original
    ext_payload, _ = v6.extract_v6_from_array(stego_arr, password="RetryPassword123")
    assert ext_payload == payload


def test_cycle_walking_retry_five_consecutive_failures(monkeypatch):
    """Five consecutive cycle-walking failures must raise an explicit CycleWalkingExceededError."""
    import utils.steganography_v6 as v6

    carrier = np.full((150, 150, 3), 128, dtype=np.uint8)
    payload = b"PermanentFailurePayload"

    def always_fail_permute(slot_idx, M, k, tables):
        raise v6.CycleWalkingExceededError("Simulated permanent cycle walk cutoff")

    monkeypatch.setattr(v6, "permute_forward", always_fail_permute)

    with pytest.raises(v6.CycleWalkingExceededError, match="across 5 attempts"):
        v6.embed_v6_into_array(carrier, payload, password="TestPassword")


def test_cycle_walking_retry_unrelated_exception_not_retried(monkeypatch):
    """Unrelated exceptions (e.g. ValueError, CapacityExceededError) must NOT trigger a retry."""
    import utils.steganography_v6 as v6

    carrier = np.full((150, 150, 3), 128, dtype=np.uint8)
    payload = b"UnrelatedExceptionPayload"

    attempts_seen = [0]

    def faulty_serialize(*args, **kwargs):
        attempts_seen[0] += 1
        raise ValueError("Simulated unrelated business logic validation failure")

    monkeypatch.setattr(v6, "serialize_v6_payload", faulty_serialize)

    with pytest.raises(ValueError, match="Simulated unrelated business logic"):
        v6.embed_v6_into_array(carrier, payload, password="TestPassword")

    assert attempts_seen[0] == 1, "Unrelated exception must fail immediately on attempt 1 without retry"


def test_cycle_walking_retry_pristine_carrier_no_leaked_modifications(monkeypatch):
    """Verify that every retry starts from the pristine carrier with zero leaked modifications."""
    import utils.steganography_v6 as v6

    carrier = np.full((150, 150, 3), 100, dtype=np.uint8)
    carrier_copy = carrier.copy()
    payload = b"PristineCarrierIsolationTest"

    original_permute = v6.permute_forward
    failed_once = [False]

    def fail_after_modifying_header(slot_idx, M, k, tables):
        if not failed_once[0] and slot_idx == 5:
            failed_once[0] = True
            raise v6.CycleWalkingExceededError("Simulated cycle walk failure after partial modification")
        return original_permute(slot_idx, M, k, tables)

    monkeypatch.setattr(v6, "permute_forward", fail_after_modifying_header)

    stego_arr, info = v6.embed_v6_into_array(carrier, payload, password="SafePassword")

    assert info["attempts"] == 2
    # Verify input carrier array was not permanently corrupted in place
    assert np.array_equal(carrier, carrier_copy)

    # Verify extraction succeeds cleanly
    ext_payload, _ = v6.extract_v6_from_array(stego_arr, password="SafePassword")
    assert ext_payload == payload


def test_cycle_walking_retry_generates_fresh_salt_per_attempt(monkeypatch):
    """Each retry attempt must generate a fresh cryptographically random salt."""
    import utils.steganography_v6 as v6

    carrier = np.full((150, 150, 3), 128, dtype=np.uint8)
    payload = b"FreshSaltTest"

    salts_generated = []
    original_urandom = os.urandom

    def intercept_urandom(n):
        res = original_urandom(n)
        if n == v6.SALT_LEN:
            salts_generated.append(res)
        return res

    original_permute = v6.permute_forward
    failures = [0]

    def fail_first_two(slot_idx, M, k, tables):
        if failures[0] < 2 and slot_idx == 0:
            failures[0] += 1
            raise v6.CycleWalkingExceededError("Simulated failure")
        return original_permute(slot_idx, M, k, tables)

    monkeypatch.setattr(os, "urandom", intercept_urandom)
    monkeypatch.setattr(v6, "permute_forward", fail_first_two)

    stego_arr, info = v6.embed_v6_into_array(carrier, payload, password="FreshSaltPassword")

    assert info["attempts"] == 3
    assert len(salts_generated) >= 3
    # Assert all salts in the attempts were unique
    assert len(set(salts_generated[:3])) == 3


# ==============================================================================
# 10. Alpha-Channel & Transparency Preservation Tests
# ==============================================================================

def test_e2e_rgba_image_alpha_preservation(tmp_path):
    """RGBA images must retain exact alpha values and save as RGBA PNG."""
    host_path = str(tmp_path / "host_rgba.png")
    stego_path = str(tmp_path / "stego_rgba.png")

    w, h = 160, 160
    rgba_arr = np.zeros((h, w, 4), dtype=np.uint8)
    rgba_arr[:, :, 0] = 80
    rgba_arr[:, :, 1] = 120
    rgba_arr[:, :, 2] = 160
    for y in range(h):
        rgba_arr[y, :, 3] = int((y / (h - 1)) * 255)

    host_img = Image.fromarray(rgba_arr, mode="RGBA")
    host_img.save(host_path, format="PNG")

    message = "RGBA transparency preservation secret message in V6!"
    info = hide_text_v6(host_path, message, stego_path, password="TransparencyPassword")

    assert os.path.exists(stego_path)

    with Image.open(stego_path) as stego_img:
        assert stego_img.mode == "RGBA"
        assert stego_img.size == (w, h)
        stego_rgba = np.array(stego_img, dtype=np.uint8)

    # Alpha channel must be byte-for-byte identical to host
    assert np.array_equal(stego_rgba[:, :, 3], rgba_arr[:, :, 3])

    # Extract text from the RGBA stego image
    extracted_text, meta = extract_text_v6(stego_path, password="TransparencyPassword")
    assert extracted_text == message


def test_e2e_la_image_transparency_preservation(tmp_path):
    """LA (Luminance + Alpha) images must retain transparency and save as RGBA PNG."""
    host_path = str(tmp_path / "host_la.png")
    stego_path = str(tmp_path / "stego_la.png")

    w, h = 150, 150
    la_arr = np.zeros((h, w, 2), dtype=np.uint8)
    la_arr[:, :, 0] = 128  # Luminance
    la_arr[:, :, 1] = 200  # Alpha

    host_img = Image.fromarray(la_arr, mode="LA")
    host_img.save(host_path, format="PNG")

    secret_file = str(tmp_path / "payload.bin")
    out_dir = str(tmp_path / "extracted")
    payload_data = b"LA-Transparency-Payload-12345" * 10
    with open(secret_file, "wb") as f:
        f.write(payload_data)

    hide_file_v6(host_path, secret_file, stego_path, password=None)

    with Image.open(stego_path) as stego_img:
        assert stego_img.mode == "RGBA"
        assert stego_img.size == (w, h)
        stego_arr = np.array(stego_img, dtype=np.uint8)

    # Alpha channel must match original LA alpha channel
    assert np.array_equal(stego_arr[:, :, 3], la_arr[:, :, 1])

    # Extract file
    recovered, meta = extract_file_v6(stego_path, output_dir=out_dir, password=None)
    assert recovered == payload_data


def test_e2e_palette_png_transparency_preservation(tmp_path):
    """Palette PNG with transparency metadata must retain transparency and save as RGBA PNG."""
    host_path = str(tmp_path / "host_pal.png")
    stego_path = str(tmp_path / "stego_pal.png")

    w, h = 150, 150
    pal_img = Image.new("P", (w, h), color=1)
    palette = []
    palette.extend([0, 0, 0])       # color 0 (transparent)
    palette.extend([100, 150, 200]) # color 1 (opaque blue)
    palette.extend([0] * (256 * 3 - len(palette)))
    pal_img.putpalette(palette)
    pal_img.info["transparency"] = 0

    pal_arr = np.array(pal_img)
    pal_arr[50:100, :] = 0
    pal_img = Image.fromarray(pal_arr, mode="P")
    pal_img.putpalette(palette)
    pal_img.info["transparency"] = 0
    pal_img.save(host_path, format="PNG", transparency=0)

    # Reference alpha after RGBA conversion
    with Image.open(host_path) as ref_img:
        ref_rgba = np.array(ref_img.convert("RGBA"))
        ref_alpha = ref_rgba[:, :, 3]

    hide_text_v6(host_path, "PaletteTransparencyV6Test", stego_path, password="PalPassword")

    with Image.open(stego_path) as stego_img:
        assert stego_img.mode == "RGBA"
        assert stego_img.size == (w, h)
        stego_arr = np.array(stego_img, dtype=np.uint8)

    # Compare normalized alpha values
    assert np.array_equal(stego_arr[:, :, 3], ref_alpha)

    # Extract
    extracted, _ = extract_text_v6(stego_path, password="PalPassword")
    assert extracted == "PaletteTransparencyV6Test"


def test_e2e_pure_rgb_image_mode_preserved(tmp_path):
    """Pure RGB images (no transparency) must save as RGB mode without extra alpha channel."""
    host_path = str(tmp_path / "host_pure_rgb.png")
    stego_path = str(tmp_path / "stego_pure_rgb.png")

    img = Image.new("RGB", (120, 120), color=(60, 70, 80))
    img.save(host_path, format="PNG")

    hide_text_v6(host_path, "RGB-Only-Payload", stego_path, password=None)

    with Image.open(stego_path) as stego_img:
        assert stego_img.mode == "RGB"
        assert stego_img.size == (120, 120)

    extracted, _ = extract_text_v6(stego_path, password=None)
    assert extracted == "RGB-Only-Payload"
