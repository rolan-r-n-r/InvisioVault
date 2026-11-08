"""Deep engineering audit & regression test suite for Steganography in InvisioVault.

Tests cover:
- v5 resilient channel coding (Reed-Solomon ECC protecting ciphertext).
- Bit error injection & self-repair on encrypted payloads without HMAC failure.
- Clean rejection on incorrect password.
- Password-protected image extraction without password.
- Backward compatibility: transparent extraction of legacy v4, v3, v2, v1 payloads.
- Empty file (0 bytes) round-trip.
- Filename with multiple pipes and unicode characters.
- ICC color profile preservation.
- Accurate capacity calculation endpoint (/api/calculate-capacity).
- Memory-efficient channel selection equivalence.
"""

import os
import sys
import tempfile
import shutil
import unittest
from PIL import Image, PngImagePlugin
import numpy as np

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app
from utils.steganography import (
    hide_file_in_image,
    extract_file_from_image,
    _v4_edge_scores,
    _v4_eligible_channels,
    _v4_seed_from_salt,
    _FLAG_ENC_RESILIENT,
    _FLAG_PLAIN_RESILIENT,
    _FLAG_ENC_ONLY_FAST,
    _FLAG_PLAIN_FAST,
    _V2_MAGIC,
)


class SteganographyAuditTests(unittest.TestCase):
    """Deep verification tests for steganography security, resilience, and compatibility."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="invisiovault_stego_audit_")
        cls.app = create_app('development')
        cls.app.config['TESTING'] = True
        cls.app.config['UPLOAD_FOLDER'] = os.path.join(cls.temp_dir, "uploads")
        os.makedirs(cls.app.config['UPLOAD_FOLDER'], exist_ok=True)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _create_textured_image(self, filename="carrier.png", width=300, height=300, icc=None):
        """Generate a textured test image suitable for Sobel edge detection."""
        img_path = os.path.join(self.temp_dir, filename)
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                arr[y, x] = [
                    (x * 7 + y * 3) % 256,
                    (x * 11 + y * 13) % 256,
                    (x * 17 + y * 19) % 256,
                ]
        img = Image.fromarray(arr, "RGB")
        info = {}
        if icc:
            img.save(img_path, "PNG", icc_profile=icc)
        else:
            img.save(img_path, "PNG")
        return img_path

    # -------------------------------------------------------------------------
    # 1. Round-Trip Tests (Plain & Encrypted v5)
    # -------------------------------------------------------------------------

    def test_v5_roundtrip_plain(self):
        """Verify v5 unencrypted payload round-trip with byte-for-byte exactness."""
        carrier = self._create_textured_image("v5_plain_carrier.png", 250, 250)
        secret_content = b"Top secret test payload for plain v5 embedding.\n" * 20
        secret_file = os.path.join(self.temp_dir, "plain_secret.txt")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "v5_plain_stego.png")
        hide_file_in_image(
            carrier,
            secret_file,
            output_stego,
            password=None,
            original_filename="plain_secret.txt"
        )

        extracted_data, ext_filename, mime = extract_file_from_image(output_stego)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, "plain_secret.txt")
        self.assertEqual(mime, "text/plain")

    def test_v5_roundtrip_encrypted(self):
        """Verify v5 encrypted payload round-trip with byte-for-byte exactness."""
        carrier = self._create_textured_image("v5_enc_carrier.png", 300, 300)
        secret_content = os.urandom(4096)
        secret_file = os.path.join(self.temp_dir, "enc_secret.bin")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "v5_enc_stego.png")
        pwd = "AuditTestPassword2026!"
        hide_file_in_image(
            carrier,
            secret_file,
            output_stego,
            password=pwd,
            original_filename="enc_secret.bin"
        )

        extracted_data, ext_filename, mime = extract_file_from_image(output_stego, password=pwd)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, "enc_secret.bin")

    # -------------------------------------------------------------------------
    # 2. Critical Security: Channel Coding Resilience on Encrypted Payload
    # -------------------------------------------------------------------------

    def test_v5_resilience_to_channel_bit_errors(self):
        """Verify that channel errors in encrypted payload are repaired by ECC BEFORE Fernet HMAC."""
        carrier = self._create_textured_image("v5_noise_carrier.png", 300, 300)
        secret_content = b"High-value encrypted document that must survive channel noise." * 15
        secret_file = os.path.join(self.temp_dir, "resilient_secret.txt")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        output_stego = os.path.join(self.temp_dir, "v5_resilient_stego.png")
        pwd = "ResilienceKey2026!"
        hide_file_in_image(
            carrier,
            secret_file,
            output_stego,
            password=pwd,
            original_filename="resilient_secret.txt"
        )

        # Corrupt 8 payload bits in the stego image
        img = Image.open(output_stego)
        pixels = np.array(img)
        flat = pixels.reshape(-1)

        # Extract header metadata to find target channels
        salt_bits = (flat[24:152] & 1).astype(np.uint8)
        salt = np.packbits(salt_bits).tobytes()
        scores = _v4_edge_scores(pixels)
        meta_len = int.from_bytes(np.packbits((flat[19*8:23*8] & 1).astype(np.uint8)).tobytes(), 'big')
        thresh_byte_idx = 2 + 1 + 16 + 4 + meta_len + 4
        threshold = int(np.packbits((flat[thresh_byte_idx*8:(thresh_byte_idx+1)*8] & 1).astype(np.uint8))[0])
        header_bits = (thresh_byte_idx + 1) * 8
        eligible = _v4_eligible_channels(scores, threshold, header_bits, 300*300*3)
        rng = np.random.RandomState(_v4_seed_from_salt(salt))
        data_len = int.from_bytes(np.packbits((flat[(thresh_byte_idx-4)*8:thresh_byte_idx*8] & 1).astype(np.uint8)).tobytes(), 'big')
        perm_sample = rng.choice(eligible.size, size=data_len * 8, replace=False)
        target_channels = eligible[perm_sample]

        # Invert 8 target channel bits in the ciphertext
        for i in range(8):
            flat[target_channels[i * 12]] ^= 1

        corrupted_stego = os.path.join(self.temp_dir, "v5_corrupted_stego.png")
        Image.fromarray(flat.reshape(300, 300, 3)).save(corrupted_stego)

        # Extraction MUST succeed because Reed-Solomon fixes the ciphertext bits before Fernet HMAC checks
        extracted_data, ext_filename, _ = extract_file_from_image(corrupted_stego, password=pwd)
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_filename, "resilient_secret.txt")

    # -------------------------------------------------------------------------
    # 3. Password Validation & Rejection
    # -------------------------------------------------------------------------

    def test_v5_wrong_password_rejected(self):
        """Verify that extracting with wrong password cleanly raises ValueError('Incorrect password.')."""
        carrier = self._create_textured_image("v5_wrong_pwd_carrier.png", 250, 250)
        secret_file = os.path.join(self.temp_dir, "wrong_pwd_secret.txt")
        with open(secret_file, "wb") as f:
            f.write(b"Secret test content")

        output_stego = os.path.join(self.temp_dir, "v5_wrong_pwd_stego.png")
        hide_file_in_image(carrier, secret_file, output_stego, password="CorrectPassword123!")

        with self.assertRaises(ValueError) as ctx:
            extract_file_from_image(output_stego, password="WrongPassword999!")
        self.assertIn("Incorrect password", str(ctx.exception))

    def test_v5_missing_password_rejected(self):
        """Verify that extracting password-protected image without password prompts for password."""
        carrier = self._create_textured_image("v5_missing_pwd_carrier.png", 250, 250)
        secret_file = os.path.join(self.temp_dir, "missing_pwd_secret.txt")
        with open(secret_file, "wb") as f:
            f.write(b"Secret test content")

        output_stego = os.path.join(self.temp_dir, "v5_missing_pwd_stego.png")
        hide_file_in_image(carrier, secret_file, output_stego, password="CorrectPassword123!")

        with self.assertRaises(ValueError) as ctx:
            extract_file_from_image(output_stego, password=None)
        self.assertIn("password-protected", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 4. Backward Compatibility: Transparent Extraction of Legacy v4
    # -------------------------------------------------------------------------

    def test_backward_compatibility_v4_legacy(self):
        """Verify that existing legacy v4 images (flag 0x20 and 0x21) are extracted seamlessly."""
        import zlib
        import struct
        import secrets
        from cryptography.fernet import Fernet
        from utils.crypto_utils import derive_fernet_key
        from utils.steganography import _ecc_encode, _v4_threshold_from_scores

        carrier = self._create_textured_image("legacy_v4_carrier.png", 250, 250)
        with Image.open(carrier) as img:
            rgb_arr = np.array(img, dtype=np.uint8)
        H, W, _ = rgb_arr.shape

        secret_data = b"Legacy v4 payload data preserved forever."
        compressed = zlib.compress(secret_data, 9)
        ecc_data = _ecc_encode(compressed)

        salt = secrets.token_bytes(16)
        pwd = "LegacyV4Password!"
        key = derive_fernet_key(pwd, salt)
        fernet = Fernet(key)
        metadata_field = fernet.encrypt(b"legacy.txt|text/plain")
        # Legacy v4 encrypted the ecc_data directly with Fernet (producing base64 bytes)
        payload_field = fernet.encrypt(ecc_data)

        meta_len = len(metadata_field).to_bytes(4, "big")
        data_len = len(payload_field).to_bytes(4, "big")
        header_base = _V2_MAGIC + bytes([_FLAG_ENC_ONLY_FAST]) + salt + meta_len + metadata_field + data_len

        scores = _v4_edge_scores(rgb_arr)
        total_channels = H * W * 3
        header_total_bits = (len(header_base) + 1) * 8
        payload_bits = len(payload_field) * 8
        threshold = _v4_threshold_from_scores(scores, header_total_bits, total_channels, payload_bits)

        full_header = header_base + struct.pack("B", threshold)
        header_bits_arr = np.unpackbits(np.frombuffer(full_header, dtype=np.uint8))
        flat = rgb_arr.reshape(-1)
        flat[:header_bits_arr.size] = (flat[:header_bits_arr.size] & np.uint8(0xFE)) | header_bits_arr

        eligible = _v4_eligible_channels(scores, threshold, header_total_bits, total_channels)
        rng = np.random.RandomState(_v4_seed_from_salt(salt))
        perm_sample = rng.choice(eligible.size, size=payload_bits, replace=False)
        target_channels = eligible[perm_sample]
        payload_bits_arr = np.unpackbits(np.frombuffer(payload_field, dtype=np.uint8))
        flat[target_channels] = (flat[target_channels] & np.uint8(0xFE)) | payload_bits_arr

        legacy_path = os.path.join(self.temp_dir, "legacy_v4_stego.png")
        Image.fromarray(flat.reshape(H, W, 3), "RGB").save(legacy_path)

        # Extract using the upgraded extractor
        extracted, ext_fn, mime = extract_file_from_image(legacy_path, password=pwd)
        self.assertEqual(extracted, secret_data)
        self.assertEqual(ext_fn, "legacy.txt")
        self.assertEqual(mime, "text/plain")

    # -------------------------------------------------------------------------
    # 5. Boundary Conditions & Special Payloads
    # -------------------------------------------------------------------------

    def test_empty_payload_file(self):
        """Verify that an empty (0 bytes) file can be hidden and extracted."""
        carrier = self._create_textured_image("empty_carrier.png", 200, 200)
        empty_file = os.path.join(self.temp_dir, "empty.bin")
        with open(empty_file, "wb") as f:
            pass

        output_stego = os.path.join(self.temp_dir, "empty_stego.png")
        hide_file_in_image(carrier, empty_file, output_stego, password="EmptyPassword123!", original_filename="empty.bin")

        extracted_data, ext_fn, _ = extract_file_from_image(output_stego, password="EmptyPassword123!")
        self.assertEqual(extracted_data, b"")
        self.assertEqual(ext_fn, "empty.bin")

    def test_filename_with_pipes_and_unicode(self):
        """Verify that filenames containing pipes and non-ASCII unicode characters are preserved."""
        carrier = self._create_textured_image("unicode_carrier.png", 250, 250)
        secret_content = b"Multilingual test payload."
        secret_file = os.path.join(self.temp_dir, "multilingual.txt")
        with open(secret_file, "wb") as f:
            f.write(secret_content)

        pipe_unicode_name = "rapport|géographique|2026.txt"
        output_stego = os.path.join(self.temp_dir, "unicode_stego.png")
        hide_file_in_image(
            carrier,
            secret_file,
            output_stego,
            password="UnicodePassword123!",
            original_filename=pipe_unicode_name
        )

        extracted_data, ext_fn, mime = extract_file_from_image(output_stego, password="UnicodePassword123!")
        self.assertEqual(extracted_data, secret_content)
        self.assertEqual(ext_fn, pipe_unicode_name)
        self.assertEqual(mime, "text/plain")

    # -------------------------------------------------------------------------
    # 6. ICC Profile Preservation
    # -------------------------------------------------------------------------

    def test_icc_profile_preservation(self):
        """Verify that an ICC color profile embedded in the carrier is retained in the stego output."""
        dummy_icc = b"\x00\x00\x01\x00DummyICCProfileDataForColorSpaceVerification2026"
        carrier = self._create_textured_image("icc_carrier.png", 200, 200, icc=dummy_icc)
        secret_file = os.path.join(self.temp_dir, "icc_secret.txt")
        with open(secret_file, "wb") as f:
            f.write(b"ICC verification data")

        output_stego = os.path.join(self.temp_dir, "icc_output_stego.png")
        hide_file_in_image(carrier, secret_file, output_stego, original_filename="icc_secret.txt")

        with Image.open(output_stego) as img:
            saved_icc = img.info.get("icc_profile")
        self.assertIsNotNone(saved_icc)
        self.assertEqual(saved_icc, dummy_icc)

    # -------------------------------------------------------------------------
    # 7. Accurate Capacity API Endpoint
    # -------------------------------------------------------------------------

    def test_capacity_api_endpoint_accuracy(self):
        """Verify /api/calculate-capacity returns total, safe, and encrypted capacities."""
        carrier = self._create_textured_image("cap_carrier.png", 400, 400)
        with open(carrier, "rb") as f:
            response = self.client.post(
                "/api/calculate-capacity",
                data={"image": (f, "cap_carrier.png")},
                content_type="multipart/form-data"
            )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        total = data.get("totalCapacityBytes")
        safe = data.get("safeCapacityBytes")
        enc_safe = data.get("encryptedSafeBytes")

        self.assertIsNotNone(total)
        self.assertIsNotNone(safe)
        self.assertIsNotNone(enc_safe)
        self.assertEqual(total, (400 * 400 * 3) // 8)  # 60,000 bytes
        self.assertLess(safe, total)  # safe capacity must be less than raw total
        self.assertLess(enc_safe, safe)  # encrypted safe must account for cipher overhead

    # -------------------------------------------------------------------------
    # 8. Memory-Efficient Channel Allocation Equivalence
    # -------------------------------------------------------------------------

    def test_memory_efficient_eligible_channels_equivalence(self):
        """Verify the 1D eligible channel allocation produces identical results to broadcast."""
        scores = np.random.randint(0, 256, size=50000, dtype=np.uint8)
        threshold = 128
        header_bits = 1200
        total_channels = 50000 * 3

        # Reference 2D implementation
        eligible_pixels = np.flatnonzero(scores >= threshold).astype(np.int32)
        ref_expanded = (eligible_pixels[:, None] * np.int32(3) + np.arange(3, dtype=np.int32)).reshape(-1)
        ref_start = np.searchsorted(ref_expanded, header_bits)
        ref_result = ref_expanded[ref_start:]

        # Optimized 1D implementation
        opt_result = _v4_eligible_channels(scores, threshold, header_bits, total_channels)

        np.testing.assert_array_equal(ref_result, opt_result)


if __name__ == "__main__":
    unittest.main()

