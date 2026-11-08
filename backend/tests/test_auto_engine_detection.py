"""Tests for automatic steganography engine detection in /api/extract."""

import io
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
from utils.steganography import detect_stego_engine
from utils.steganography_v6 import hide_file_v6, hide_text_v6
from utils.steganography import hide_file_in_image


class AutoEngineDetectionTests(unittest.TestCase):
    """Test suite for automatic engine detection and extraction routing."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="invisiovault_auto_detect_test_")
        cls.app = create_app('testing')
        cls.app.config['UPLOAD_FOLDER'] = cls.temp_dir
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        limiter.reset()

    def _create_carrier(self, width: int = 120, height: int = 120) -> io.BytesIO:
        """Create a textured PNG carrier in memory."""
        # Use structured noise so compression and edge detection are stable
        np.random.seed(42)
        arr = np.random.randint(40, 220, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return buf

    def test_detect_stego_engine_utility(self):
        """Verify detect_stego_engine returns correct version string."""
        # 1. Plain image (no stego) -> v1 (legacy fallback)
        carrier = self._create_carrier(100, 100)
        carrier_path = os.path.join(self.temp_dir, "plain.png")
        with open(carrier_path, "wb") as f:
            f.write(carrier.getvalue())
        self.assertEqual(detect_stego_engine(carrier_path), "v1")

        # 2. V6 stego carrier -> v6
        v6_out = os.path.join(self.temp_dir, "v6_stego.png")
        hide_text_v6(carrier_path, "Secret text payload", v6_out, password=None)
        self.assertEqual(detect_stego_engine(v6_out), "v6")

        # 3. Legacy (v4/v5) stego carrier -> v5
        secret_file = os.path.join(self.temp_dir, "secret.txt")
        with open(secret_file, "w") as f:
            f.write("Legacy payload")
        legacy_out = os.path.join(self.temp_dir, "legacy_stego.png")
        hide_file_in_image(carrier_path, secret_file, legacy_out, password="Password123!")
        detected = detect_stego_engine(legacy_out)
        self.assertIn(detected, ("v4", "v5"))

    def test_extract_v6_encrypted_automatically(self):
        """Verify /api/extract detects V6 encrypted carrier and extracts correctly."""
        carrier = self._create_carrier(150, 150)
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "text": "TopSecretV6Payload",
                "password": "Password123!",
                "mode": "encrypted"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(hide_resp.status_code, 200)
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Post to /api/extract (NOT /api/extract-v6)
        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "Password123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, b"TopSecretV6Payload")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Engine"), "v6")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Mode"), "encrypted")

    def test_extract_v6_plain_automatically(self):
        """Verify /api/extract detects V6 plain carrier and extracts without password."""
        carrier = self._create_carrier(150, 150)
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "text": "V6PlainTextPayload",
                "mode": "plain"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(hide_resp.status_code, 200)
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Post to /api/extract with no password
        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, b"V6PlainTextPayload")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Engine"), "v6")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Mode"), "plain")

    def test_extract_v6_wrong_password_no_fallback(self):
        """Verify /api/extract on V6 stego with wrong password returns 400 and never falls back."""
        carrier = self._create_carrier(150, 150)
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "text": "GuardedV6Secret",
                "password": "CorrectPassword123!",
                "mode": "encrypted"
            },
            content_type="multipart/form-data"
        )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Post to /api/extract with wrong password
        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "WrongPassword999!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        data = ext_resp.get_json()
        self.assertIn("error", data)
        self.assertIn("password", data["error"].lower())

    def test_extract_v6_downgrade_rejected(self):
        """Verify /api/extract on plain V6 with password returns 400 downgrade rejection."""
        carrier = self._create_carrier(150, 150)
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "text": "PlainPayload",
                "mode": "plain"
            },
            content_type="multipart/form-data"
        )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "UnexpectedPassword123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        data = ext_resp.get_json()
        self.assertIn("error", data)
        self.assertIn("downgrade", data["error"].lower())

    def test_extract_v6_encrypted_file_automatically(self):
        """Verify /api/extract detects V6 encrypted file and extracts with filename."""
        carrier = self._create_carrier(180, 180)
        file_payload = b"BinarySecretData\x00\x01\x02\xFF\xFE\xFD"
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "file": (io.BytesIO(file_payload), "payload.txt"),
                "password": "Password123!",
                "mode": "encrypted"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(hide_resp.status_code, 200)
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "Password123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, file_payload)
        self.assertIn("payload.txt", ext_resp.headers.get("Content-Disposition", ""))
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Engine"), "v6")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Mode"), "encrypted")

    def test_extract_v6_plain_file_automatically(self):
        """Verify /api/extract detects V6 plain file and extracts without password."""
        carrier = self._create_carrier(180, 180)
        file_payload = b"PlainBinaryData\xAA\xBB\xCC\xDD"
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "file": (io.BytesIO(file_payload), "plain_data.txt"),
                "mode": "plain"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(hide_resp.status_code, 200)
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, file_payload)
        self.assertIn("plain_data.txt", ext_resp.headers.get("Content-Disposition", ""))
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Engine"), "v6")
        self.assertEqual(ext_resp.headers.get("X-InvisioVault-Mode"), "plain")

    def test_extract_v6_corrupted_carrier_rejected(self):
        """Verify /api/extract rejects corrupted V6 carrier without fallback."""
        carrier = self._create_carrier(200, 200)
        hide_resp = self.client.post(
            "/api/hide-v6",
            data={
                "image": (carrier, "carrier.png"),
                "text": "PayloadToCorrupt",
                "password": "Password123!",
                "mode": "encrypted"
            },
            content_type="multipart/form-data"
        )
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        # Corrupt pixels in the middle (50:150, 50:150)
        img = Image.open(io.BytesIO(stego_bytes)).convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        arr[50:150, 50:150, :] = 0
        corrupted_buf = io.BytesIO()
        Image.fromarray(arr).save(corrupted_buf, format="PNG")
        corrupted_buf.seek(0)

        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (corrupted_buf, "corrupted.png"),
                "password": "Password123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        data = ext_resp.get_json()
        self.assertIn("error", data)

    def test_extract_non_stego_image_rejected(self):
        """Verify /api/extract on an ordinary non-stego image returns 400."""
        carrier = self._create_carrier(120, 120)
        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (carrier, "plain.png"),
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 400)
        data = ext_resp.get_json()
        self.assertIn("error", data)

    def test_extract_legacy_carrier_automatically(self):
        """Verify /api/extract detects legacy carrier and extracts successfully."""
        carrier = self._create_carrier(150, 150)
        hide_resp = self.client.post(
            "/api/hide",
            data={
                "image": (carrier, "carrier.png"),
                "text": "LegacyHiddenMessage",
                "password": "LegacyPassword123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(hide_resp.status_code, 200)
        download_id = hide_resp.get_json()["download_id"]
        stego_bytes = self.client.get(f"/api/download/{download_id}").data

        ext_resp = self.client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "LegacyPassword123!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(ext_resp.status_code, 200)
        self.assertEqual(ext_resp.data, b"LegacyHiddenMessage")
        engine_hdr = ext_resp.headers.get("X-InvisioVault-Engine")
        self.assertIn(engine_hdr, ("v4", "v5", "legacy"))


if __name__ == "__main__":
    unittest.main()
