"""Integration test suite for InvisioVault V6 steganography API endpoints.

Covers:
1. Hide Endpoints:
   - Encrypted text hiding
   - Plain text hiding
   - Encrypted file hiding
   - Plain file hiding
   - Missing image validation
   - Missing payload validation
   - Invalid mode validation
   - Invalid image file validation
   - Oversized payload validation
   - Missing password for encrypted mode

2. Extraction Endpoints:
   - Successful encrypted text extraction
   - Successful plain text extraction
   - Successful encrypted file extraction
   - Successful plain file extraction
   - Incorrect password handling
   - Corrupted stego image handling
   - Invalid V6 header handling
   - Unsupported image format handling

3. Capacity Calculations:
   - POST /api/calculate-capacity-v6
   - POST /api/calculate-capacity?engine=v6

4. Compatibility & Non-Fallback:
   - Legacy /api/hide and /api/extract functionality preserved
   - V6 extraction failures never fall back to legacy engines
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from PIL import Image
import numpy as np

import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app
from extensions import limiter
from api.routes import SAFE_ERROR_MESSAGES


class SteganographyV6ApiIntegrationTests(unittest.TestCase):
    """End-to-end integration tests for V6 API routes."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="invisiovault_v6_api_test_")
        cls.app = create_app('testing')
        cls.app.config['TESTING'] = True
        cls.app.config['RATELIMIT_ENABLED'] = False
        limiter.enabled = False
        cls.app.config['UPLOAD_FOLDER'] = os.path.join(cls.temp_dir, "uploads")
        os.makedirs(cls.app.config['UPLOAD_FOLDER'], exist_ok=True)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        limiter.enabled = True
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _create_test_image(self, filename="carrier.png", width=300, height=300, mode="RGB"):
        """Create a deterministic test image."""
        img_path = os.path.join(self.temp_dir, filename)
        num_channels = len(mode)
        arr = np.zeros((height, width, num_channels), dtype=np.uint8)
        for y in range(height):
            for x in range(width):
                if mode == "RGB":
                    arr[y, x] = [(x * 3 + y * 2) % 256, (x * 5 + y * 7) % 256, (x * 11 + y * 13) % 256]
                elif mode == "RGBA":
                    arr[y, x] = [(x * 3 + y * 2) % 256, (x * 5 + y * 7) % 256, (x * 11 + y * 13) % 256, 255]
        img = Image.fromarray(arr, mode)
        img.save(img_path, "PNG")
        return img_path

    # =========================================================================
    # 1. Capacity Endpoint Tests
    # =========================================================================

    def test_calculate_capacity_v6_endpoint(self):
        """Verify dedicated /api/calculate-capacity-v6 returns valid V6 capacity structure."""
        carrier_path = self._create_test_image("v6_cap_carrier.png", 200, 200)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/calculate-capacity-v6",
                data={"image": (f, "carrier.png")},
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["engine"], "v6")
        self.assertIn("totalCapacityBytes", data)
        self.assertIn("safeCapacityBytes", data)
        self.assertIn("encryptedSafeBytes", data)
        self.assertIn("availableTriplets", data)
        self.assertIn("maxRsBlocks", data)
        self.assertGreater(data["totalCapacityBytes"], 0)
        self.assertGreater(data["availableTriplets"], 0)

    def test_calculate_capacity_with_engine_v6_param(self):
        """Verify /api/calculate-capacity forwards to V6 calculation when engine=v6 is passed."""
        carrier_path = self._create_test_image("v6_cap_forward.png", 200, 200)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/calculate-capacity",
                data={"image": (f, "carrier.png"), "engine": "v6"},
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("engine"), "v6")

    # =========================================================================
    # 2. V6 Hide Endpoint Tests
    # =========================================================================

    def test_hide_v6_encrypted_text(self):
        """Verify /api/hide-v6 successfully hides encrypted text and returns download_id."""
        carrier_path = self._create_test_image("hide_enc_text.png", 200, 200)
        secret_text = "V6 Top Secret Text Message with 10-Round Feistel!"
        password = "V6StrongPassword2026!"

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": secret_text,
                    "password": password,
                    "mode": "encrypted"
                },
                content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("mode"), "encrypted")
        download_id = data.get("download_id")
        self.assertTrue(download_id.endswith(".png"))

        # Verify stego image is retrievable via /api/download/<id>
        dl_resp = self.client.get(f"/api/download/{download_id}")
        self.assertEqual(dl_resp.status_code, 200)
        stego_bytes = dl_resp.data

        # Verify extraction via /api/extract-v6
        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data.decode("utf-8"), secret_text)
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Engine"), "v6")

    def test_hide_v6_plain_text(self):
        """Verify /api/hide-v6 successfully hides plain text without password and extracts cleanly."""
        carrier_path = self._create_test_image("hide_plain_text.png", 200, 200)
        secret_text = "Plain V6 public announcements with CRC-32 integrity."

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": secret_text,
                    "mode": "plain"
                },
                content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("mode"), "plain")
        download_id = data.get("download_id")

        # Download stego image
        dl_resp = self.client.get(f"/api/download/{download_id}")
        self.assertEqual(dl_resp.status_code, 200)
        stego_bytes = dl_resp.data

        # Extract plain text without password
        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "expected_mode": "plain"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data.decode("utf-8"), secret_text)

    def test_hide_v6_encrypted_file(self):
        """Verify /api/hide-v6 successfully hides an encrypted binary file."""
        carrier_path = self._create_test_image("hide_enc_file.png", 250, 250)
        secret_bytes = b"BINARY_PAYLOAD_V6_TEST_DATA_\x00\x01\x02\xFF" * 16
        password = "FileEncryptionPassword99!"

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "file": (io.BytesIO(secret_bytes), "secret_doc.pdf"),
                    "password": password,
                    "mode": "encrypted"
                },
                content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 200)
        download_id = resp.get_json()["download_id"]

        # Fetch and extract
        dl_resp = self.client.get(f"/api/download/{download_id}")
        stego_bytes = dl_resp.data

        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, secret_bytes)
        self.assertIn("secret_doc.pdf", ext_resp.headers.get("Content-Disposition", ""))

    def test_hide_v6_plain_file(self):
        """Verify /api/hide-v6 successfully hides a plain binary file."""
        carrier_path = self._create_test_image("hide_plain_file.png", 250, 250)
        secret_bytes = b"OPEN_V6_BINARY_PAYLOAD_TEST_DATA" * 10

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "file": (io.BytesIO(secret_bytes), "plain_doc.pdf"),
                    "mode": "plain"
                },
                content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 200)
        download_id = resp.get_json()["download_id"]

        dl_resp = self.client.get(f"/api/download/{download_id}")
        stego_bytes = dl_resp.data

        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "expected_mode": "plain"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, secret_bytes)

    def test_hide_v6_transparent_png_carrier(self):
        """Verify /api/hide-v6 preserves RGBA transparency channel intact."""
        carrier_path = self._create_test_image("rgba_carrier.png", 200, 200, mode="RGBA")
        secret_text = "Hidden in RGBA with Alpha preserved."
        password = "RGBAPassword2026!"

        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": secret_text,
                    "password": password,
                    "mode": "encrypted"
                },
                content_type="multipart/form-data"
            )

        self.assertEqual(resp.status_code, 200)
        download_id = resp.get_json()["download_id"]

        dl_resp = self.client.get(f"/api/download/{download_id}")
        stego_bytes = dl_resp.data

        # Verify image mode remains RGBA
        with Image.open(io.BytesIO(stego_bytes)) as stego_img:
            self.assertEqual(stego_img.mode, "RGBA")

        # Verify extraction succeeds
        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data.decode("utf-8"), secret_text)

    # =========================================================================
    # 3. V6 Validation & Error Handling Tests
    # =========================================================================

    def test_hide_v6_missing_image(self):
        """Verify /api/hide-v6 returns 400 when image is missing."""
        resp = self.client.post(
            "/api/hide-v6",
            data={"text": "hello"},
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Image is required", resp.get_json()["error"])

    def test_hide_v6_missing_payload(self):
        """Verify /api/hide-v6 returns 400 when neither file nor text is provided."""
        carrier_path = self._create_test_image("no_payload.png", 100, 100)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={"image": (f, "carrier.png")},
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Either file or text is required", resp.get_json()["error"])

    def test_hide_v6_invalid_mode(self):
        """Verify /api/hide-v6 returns 400 when an invalid mode is specified."""
        carrier_path = self._create_test_image("invalid_mode.png", 100, 100)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "test",
                    "mode": "unsupported_mode"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid mode", resp.get_json()["error"])

    def test_hide_v6_missing_password_in_encrypted_mode(self):
        """Verify /api/hide-v6 returns 400 when encrypted mode is selected without a password."""
        carrier_path = self._create_test_image("no_pwd.png", 100, 100)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "test",
                    "mode": "encrypted"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Password is required", resp.get_json()["error"])

    def test_hide_v6_short_password(self):
        """Verify /api/hide-v6 returns 400 when password is shorter than MIN_PASSWORD_LENGTH."""
        carrier_path = self._create_test_image("short_pwd.png", 100, 100)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "test",
                    "password": "short",
                    "mode": "encrypted"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("at least 8 characters", resp.get_json()["error"])

    def test_hide_v6_plain_mode_rejects_password(self):
        """Verify /api/hide-v6 returns 400 if password is provided when mode is explicitly plain."""
        carrier_path = self._create_test_image("plain_with_pwd.png", 100, 100)
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "test",
                    "password": "ValidPassword123!",
                    "mode": "plain"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Password cannot be specified when plain mode", resp.get_json()["error"])

    def test_hide_v6_invalid_image(self):
        """Verify /api/hide-v6 rejects malformed or non-image files."""
        corrupted_bytes = b"NOT_A_VALID_IMAGE_HEADER_AT_ALL"
        resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (io.BytesIO(corrupted_bytes), "fake.png"),
                "text": "test"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)

    def test_hide_v6_oversized_payload(self):
        """Verify /api/hide-v6 returns 400 when payload exceeds carrier capacity."""
        # A tiny 20x20 image has only 400 pixels = 1200 channels (456 header, ~744 payload channels = 248 triplets = ~62 bytes encoded, RS N=0)
        tiny_carrier = self._create_test_image("tiny.png", 20, 20)
        oversized_text = "A" * 5000

        with open(tiny_carrier, "rb") as f:
            resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "tiny.png"),
                    "text": oversized_text,
                    "password": "TestPassword123!"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], SAFE_ERROR_MESSAGES['capacity'])

    # =========================================================================
    # 4. V6 Extraction Error Handling Tests
    # =========================================================================

    def test_extract_v6_incorrect_password(self):
        """Verify /api/extract-v6 rejects wrong password with sanitized error."""
        carrier_path = self._create_test_image("wrong_pwd_test.png", 200, 200)
        with open(carrier_path, "rb") as f:
            hide_resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "Sensitive confidential data",
                    "password": "CorrectPassword123!"
                },
                content_type="multipart/form-data"
            )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Attempt extraction with wrong password
        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "WrongPassword999!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        self.assertEqual(ext_resp.get_json()["error"], SAFE_ERROR_MESSAGES['password'])

    def test_extract_v6_corrupted_stego_image(self):
        """Verify /api/extract-v6 rejects carrier with tampered or corrupted pixels."""
        carrier_path = self._create_test_image("corrupt_carrier.png", 200, 200)
        with open(carrier_path, "rb") as f:
            hide_resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "Data to be corrupted",
                    "mode": "plain"
                },
                content_type="multipart/form-data"
            )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Corrupt pixels in the middle of the image array
        with Image.open(io.BytesIO(stego_bytes)) as img:
            arr = np.array(img, dtype=np.uint8)
            # Flip high number of pixels across multiple blocks
            arr[50:150, 50:150, :] = 0
            corrupted_img = Image.fromarray(arr, img.mode)
            buf = io.BytesIO()
            corrupted_img.save(buf, format="PNG")
            tampered_bytes = buf.getvalue()

        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(tampered_bytes), "corrupt_stego.png"),
                "expected_mode": "plain"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)

    def test_extract_v6_plain_with_password_rejected_as_downgrade(self):
        """Verify /api/extract-v6 detects and rejects downgrade when password provided for plain stego."""
        carrier_path = self._create_test_image("plain_downgrade.png", 200, 200)
        with open(carrier_path, "rb") as f:
            hide_resp = self.client.post(
                "/api/hide-v6",
                data={
                    "image": (f, "carrier.png"),
                    "text": "Public plain data",
                    "mode": "plain"
                },
                content_type="multipart/form-data"
            )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Submit extraction with a password against a plain stego image
        ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "AttackerSuppliedPassword!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        self.assertIn("downgrade", ext_resp.get_json()["error"].lower())

    def test_extract_v6_invalid_header(self):
        """Verify /api/extract-v6 rejects images that do not contain a valid V6 header."""
        normal_image = self._create_test_image("clean_carrier.png", 100, 100)
        with open(normal_image, "rb") as f:
            ext_resp = self.client.post(
                "/api/extract-v6",
                data={
                    "image": (f, "clean.png"),
                    "password": "SomePassword123!"
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(ext_resp.status_code, 400)

    # =========================================================================
    # 5. Compatibility & Non-Fallback Tests
    # =========================================================================

    def test_legacy_hide_and_extract_unaffected(self):
        """Verify legacy /api/hide and /api/extract continue working normally."""
        carrier_path = self._create_test_image("legacy_carrier.png", 200, 200)
        secret_content = b"Legacy v5 test secret message content."
        pwd = "LegacyPassword123!"

        # 1. Legacy hide
        with open(carrier_path, "rb") as f:
            resp = self.client.post(
                "/api/hide",
                data={
                    "image": (f, "carrier.png"),
                    "file": (io.BytesIO(secret_content), "legacy_file.txt"),
                    "password": pwd
                },
                content_type="multipart/form-data"
            )
        self.assertEqual(resp.status_code, 200)
        download_id = resp.get_json()["download_id"]

        # 2. Legacy extract
        stego_bytes = self.client.get(f"/api/download/{download_id}").data
        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": pwd
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, secret_content)

    def test_v6_failure_does_not_fallback_to_legacy(self):
        """Verify that when V6 extraction fails, it never falls back to legacy V1–V5."""
        # Embed data using legacy engine
        carrier_path = self._create_test_image("legacy_stego.png", 200, 200)
        with open(carrier_path, "rb") as f:
            hide_resp = self.client.post(
                "/api/hide",
                data={
                    "image": (f, "carrier.png"),
                    "text": "Hidden with legacy engine",
                    "password": "Password123!"
                },
                content_type="multipart/form-data"
            )
        download_id = hide_resp.get_json()["download_id"]
        legacy_stego = self.client.get(f"/api/download/{download_id}").data

        # Attempt to extract legacy stego using /api/extract-v6: MUST fail with 400, never silently fall back
        v6_ext_resp = self.client.post(
            "/api/extract-v6",
            data={
                "image": (io.BytesIO(legacy_stego), "stego.png"),
                "password": "Password123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(v6_ext_resp.status_code, 400)
        # Verify it did not return the legacy text
        self.assertNotEqual(v6_ext_resp.data, b"Hidden with legacy engine")


if __name__ == "__main__":
    unittest.main()
