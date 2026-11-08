# Changelog

All notable changes to InvisioVault are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **V6 Advanced Steganography Engine:** Introduced the V6 steganography engine as the canonical primary writer for all new image hiding operations (`/api/hide-v6`).
- **Matrix (3, 2) Coset Syndrome Coding:** Embeds 2 payload bits into 3 carrier channels with at most 1 bit modification, achieving a 25.00% reduction in carrier modifications compared to standard LSB replacement.
- **10-Round Balanced Feistel Channel Permutation:** Pseudorandom channel coordinate dispersion using an in-memory 10-round Feistel network with precomputed AES-256-CTR tables (160 KiB L2 cache footprint).
- **Cycle Walking Domain Restriction:** Restricts the Feistel cipher onto arbitrary carrier triplet universes with a 100-iteration defensive runtime guard and fresh-salt retry loop.
- **Dynamic-Group Interleaved Reed-Solomon RS(255, 223):** Channel coding with depth $K=4$ over $\text{GF}(2^8)$, tolerating up to 16 symbol errors per 255-byte block and up to 64 contiguous burst bytes.
- **Dual Operational Modes:** Added password-protected Encrypted Mode (PBKDF2-HMAC-SHA256 with 600,000 iterations, HKDF-SHA256 key separation, Fernet AES-128-CBC encryption, and HMAC-SHA256 header authentication) and Plain Mode (CRC-32 payload framing with SHA-256 integrity tag).
- **Canonical 57-Byte Authenticated Header:** Structured header wire format (`0xFF 0x06`) with anti-downgrade enforcement binding mode flags, salt, and length parameters.
- **Automatic Multi-Engine Extraction:** Enhanced `POST /api/extract` with automatic engine detection (`detect_stego_engine`), transparently recovering V6 carriers alongside legacy V1–V5 carriers without manual version selection.
- **Dedicated V6 API Endpoints:** Added `POST /api/hide-v6`, `POST /api/extract-v6`, and `POST /api/calculate-capacity-v6`.

### Changed
- **Default Engine Promotion:** V6 is now the default and primary embedding engine across both the frontend web client and the backend REST API.
- **Simplified User Interfaces:** Removed manual engine selectors from both Hide and Extract interfaces. Extraction now automatically identifies the carrier format.
- **Key Stretching Elevation:** Upgraded PBKDF2 iteration count to 600,000 iterations for V6 key derivation.
- **Backward Compatibility:** Maintained internal support for extracting legacy V1–V5 carrier formats without behavioral regression.

### Security
- **Anti-Downgrade Invariant:** Strictly rejects passphrases when presented with Plain Mode carriers, and aborts upon header HMAC authentication mismatch prior to payload processing.
- **Zero-Fallback Guarantee:** Prohibited automatic fallback from V6 extraction to legacy decoders upon failure, ensuring error fidelity.

---

## [2.0.1] - 2026-09-18

### Added
- **QR Code Steganography Suite:** Visual Module Mode generation (structural isolation) with dual-mode scanning (supporting Visual Module Mode and legacy Stream Mode `#IVDATA:` scheme).
- **Live Camera QR Scanner:** Real-time WebRTC camera scanner with dual-canvas contrast enhancement, 5-tier progressive hardware fallback, and in-memory zxing-cpp decoding.
- **Deduplication Frame Cache:** In-memory SHA-256 frame cache reducing repeated frame extraction overhead during camera scans by 60–80%.
- **Render Memory Envelope Hardening:** Deterministic concurrency semaphore (`_heavy_operation_semaphore`) and Gunicorn `post_fork` cleanup scheduler hook to eliminate OOM spikes on Render free-tier (512 MB).
- **Formal Documentation Suite:** Added comprehensive `docs/ARCHITECTURE.md`, `docs/API.md`, `SECURITY.md` (with Threat Model), and `CONTRIBUTING.md`.

### Changed
- **Rate Limiting Refinement:** Upgraded to Flask-Limiter 3.5 with route-specific decorators registered directly on application Blueprint factory.
- **Sanitized Production Error Messaging:** Integrated centralized `sanitize_error()` to prevent internal path and exception leakage.

### Fixed
- Fixed central directory offset recalculation in polyglot ZIPs exceeding 4 GB using 64-bit EOCD record locator patching.
- Resolved camera permission policy conflicts on Vercel preview environments.

---

## [2.0.0] - 2026-01-15

### Added
- **Cryptographic Ground-Up Rebuild:** Completely restructured architecture from the early prototype.
- **Authenticated Encryption:** Upgraded to Fernet (AES-128-CBC + HMAC-SHA256) with 480,000-iteration PBKDF2-HMAC-SHA256 key stretching.
- **Universal Polyglot Engine:** Concatenation and in-memory offset patching for images (PNG, JPG, BMP), PDFs, audio (MP3), and video (MP4) dual-format files.
- **Detection-Resistant LSB Matching:** Replaced basic LSB substitution with ±1 randomized matching and Sobel edge detection texture guidance to resist statistical chi-square steganalysis.
- **Wire Formats v2 & v3:** Introduced magic byte header detection (`0xFF 0x02`), dynamic salt allocation, and differential Reed-Solomon Error Correction Code (RSCodec).

---

## [1.0.0] - 2024-05-10

### Initial Prototype
- Basic Least-Significant-Bit (LSB) image steganography implementation.
- Proof-of-concept file hiding in uncompressed BMP and PNG images.
