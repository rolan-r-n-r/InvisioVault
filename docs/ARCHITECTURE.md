# InvisioVault Technical Architecture & Cryptographic Specification

This document provides a comprehensive technical breakdown of the algorithms, binary wire formats, mathematical models, and operational architecture powering **InvisioVault**.

---

## 1. High-Level System Architecture

InvisioVault is engineered as a zero-retention, decoupled system consisting of a client-side interface and an ephemeral cryptographic backend.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                 Client Layer (React 19 / Vite / Vercel)                 │
│  ├─ UI & Deep Route Manager (App.jsx, BrowserRouter)                    │
│  └─ WebRTC Camera Scanner & Dual-Canvas 2x Preprocessing                │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTPS / TLS 1.3
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Vercel Edge Distribution Layer                       │
│  └─ Edge Middleware (Bot Detection & Pre-rendered HTML Redirection)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Proxy Routed Requests
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                Stateless Backend Service (Render 512 MB)                │
│  ├─ Gunicorn Master + Sync Worker + post_fork Cleanup Thread            │
│  ├─ Global Concurrency Semaphore (_heavy_operation_semaphore: 1)       │
│  └─ Flask REST API Router (17 Endpoints)                                │
└───────────────────┬───────────────────┬───────────────────┬─────────────┘
                    │                   │                   │
                    ▼                   ▼                   ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌─────────────────────┐
│ Steganography Engine  │ │Universal Polyglot Eng.│ │  QR Stego Engine    │
│├─ V6 Matrix (3,2)     │ │├─ Dual-Parser Verify  │ │├─ Visual Masking    │
│├─ 10-Round Feistel    │ │├─ ZIP CDFH/EOCD Parse │ │├─ Stream Fragment   │
│├─ Interleaved RS ECC  │ │└─ Binary mmap Patch   │ │└─ zxing-cpp Decode  │
│├─ Auto-Detection V1-V6│ └───────────┬───────────┘ └──────────┬──────────┘
│└─ Legacy V1-V5 Decoders             │                        │
└───────────┬───────────┘             │                        │
            │                         │                        │
            └─────────────────────────┼────────────────────────┘
                                      ▼
                    ┌───────────────────────────────────┐
                    │       Crypto Core Subsystem       │
                    │  ├─ PBKDF2-HMAC-SHA256 (600k/480k)│
                    │  ├─ Two-Tier HKDF Key Separation  │
                    │  ├─ Fernet (AES-128-CBC + HMAC)   │
                    │  └─ SHA-256 / CRC-32 Integrity    │
                    └───────────────────────────────────┘
```

---

## 2. Steganography Engine: V6 Advanced Architecture & Multi-Engine Dispatch

InvisioVault features a multi-generational steganographic engine architecture:
1. **V6 Advanced Engine (Primary Writer):** The default and exclusive embedding engine for all new hiding operations. Employs Matrix (3,2) coset syndrome coding, 10-round balanced Feistel permutation, interleaved Reed-Solomon RS(255, 223), and 57-byte authenticated headers.
2. **Legacy Engines (V1–V5 Extraction Support):** Fully preserved decoders enabling automatic backward-compatible recovery of legacy carrier files without requiring manual engine selection.

---

### 2.1 InvisioVault V6 Engine Architecture (Primary Writer)

InvisioVault V6 is engineered for maximum detection resistance, robust channel error correction, and cryptographic authentication in lossless raster images (PNG).

```text
[Plaintext Payload]
        │
        ▼ (Optional zlib Level 9)
[Compressed Payload]
        │
        ▼ (Metadata JSON Framing)
[Serialized Message Stream]
        │
        ├──► Encrypted Mode: Fernet AEAD (AES-128-CBC + HMAC-SHA256) ──► Raw Binary Token
        └──► Plain Mode: Prefix 4-byte CRC-32 Checksum ────────────────► Raw Plain Stream
        │
        ▼ (Pad to multiple of 223 bytes)
[Pre-RS Byte Stream]
        │
        ▼ (Reed-Solomon RS(255, 223) Encoding)
[Codeword Stream: N x 255 bytes]
        │
        ▼ (Dynamic Group Interleaving, K=4)
[Interleaved Byte Stream]
        │
        ▼ (Bit Serialization: 2 bits per symbol)
[Matrix (3,2) Coset Encoder] ◄─── Channel Coordinates from 10-Round Feistel Permutation
        │
        ▼ (LSB Modification on 3-channel groups)
[Lossless Stego PNG]
```

#### Core Technological Pillars:

1. **Matrix (3, 2) Coset Syndrome Coding:**
   Embeds 2 message bits into every 3 carrier channels with at most 1 bit modification using the linear parity-check matrix:
   $$H = \begin{pmatrix} 1 & 0 & 1 \\ 0 & 1 & 1 \end{pmatrix}$$
   For carrier channel LSBs $(c_1, c_2, c_3)$ and target bits $m = (m_1, m_2)^T$, the syndrome difference $d = m \oplus Hc$ maps deterministically to a minimal coset leader with at most 1 bit flip:
   - $d = (0, 0)^T \implies$ no flips
   - $d = (1, 0)^T \implies$ flip $c_1$
   - $d = (0, 1)^T \implies$ flip $c_2$
   - $d = (1, 1)^T \implies$ flip $c_3$

   Average bit flips per 2 bits: $\frac{0 + 1 + 1 + 1}{4} = 0.75$ flips ($0.375$ flips/bit). This achieves a strict **25.00% reduction in carrier modifications** compared to standard LSB replacement ($0.50$ flips/bit), substantially diminishing statistical detectability.

2. **10-Round Balanced Feistel Channel Permutation:**
   Disperses payload bits pseudorandomly across carrier pixel coordinates using an in-memory 10-round Feistel network with precomputed AES-256-CTR round tables. The table lookup requires only 160 KiB of RAM (at maximum block size $k=13$), residing entirely within the host CPU's L2 cache for microsecond-level coordinate mapping.

3. **Cycle Walking Domain Restriction & Runtime Guard:**
   Restricts the power-of-two Feistel block cipher onto arbitrary carrier channel triplet domains $\{0, \dots, M_{\text{triplets}}-1\}$ with proven bijectivity and zero collisions. While cycle walking on a finite bijection terminates with probability 1, the engine enforces a defensive runtime guard of `MAX_CYCLE_WALK_ITERATIONS = 100` to prevent latency anomalies. If any coordinate slot exceeds 100 iterations during embedding, the engine draws a fresh 16-byte random salt and retries (up to 5 attempts); during extraction, exceeding the guard safely terminates with `CycleWalkingExceededError`.

4. **Dynamic-Group Interleaved Reed-Solomon RS(255, 223):**
   Employs dynamic-group block interleaving with depth $K = 4$ over $\text{GF}(2^8)$ with primitive polynomial $0\text{x}11\text{D}$. Each 255-byte codeword can correct up to 16 symbol errors, and $K=4$ interleaving tolerates localized burst corruptions of up to 64 contiguous bytes without data loss.

5. **Two-Tier HKDF Key Separation:**
   In Encrypted Mode, user passphrases derive a 32-byte master key using **PBKDF2-HMAC-SHA256** with **600,000 iterations** (OWASP 2023+ recommendation) and a 16-byte cryptographically secure random salt (`os.urandom(16)`). From this master key, independent subkeys are derived via **HKDF-Expand (RFC 5869)**:
   - Header authentication subkey: `K_auth` (HMAC-SHA256)
   - Payload encryption subkey: `K_enc` (Fernet AES-128-CBC)
   - Permutation root subkey: `K_perm_root` (Feistel round keys and IVs)

6. **Canonical 57-Byte Authenticated Header Wire Format:**
   Sequential embedding into carrier channels $0 \dots 455$ using standard LSB replacement:

   | Byte Offset | Field Name | Data Type | Permitted Values | Description |
   | :---: | :--- | :--- | :--- | :--- |
   | `0x00 - 0x01` | `magic` | `bytes[2]` | `b"\xFF\x06"` | InvisioVault V6 protocol identifier |
   | `0x02` | `mode` | `uint8` | `0x40` (Plain), `0x41` (Encrypted) | Operational mode flag |
   | `0x03` | `interleave_k` | `uint8` | `4` (`1, 2, 4, 8, 16` supported) | Dynamic Reed-Solomon interleaving depth |
   | `0x04` | `reserved` | `uint8` | `0x00` | Reserved for future expansion (must be 0) |
   | `0x05 - 0x14` | `salt` | `bytes[16]` | 16 random bytes | Carrier salt from `os.urandom(16)` |
   | `0x15 - 0x18` | `raw_payload_len`| `uint32_be`| $1 \le L_{\text{raw}} \le \text{MaxCapacity}$ | Exact original unpadded raw payload length |
   | `0x19 - 0x38` | `auth_tag` | `bytes[32]` | 32-byte hash / MAC | HMAC-SHA256 (Encrypted) or SHA-256 (Plain) |
   | **Total** | | | | **57 Bytes** ($456\text{ channels}$) |

7. **Dual Operational Modes:**
   - **Encrypted Mode (`0x41`):** Requires password. Payload is encrypted with Fernet (AES-128-CBC + HMAC-SHA256). Header `auth_tag` is an HMAC-SHA256 computed over header fields $0\text{x}00 \dots 0\text{x}18$.
   - **Plain Mode (`0x40`):** No password required. Payload is framed with a 4-byte CRC-32 checksum. Header `auth_tag` is a SHA-256 digest computed over the salt, payload length, and raw payload data for tamper detection.

8. **Anti-Downgrade & Strict Security Validation:**
   The extractor strictly enforces mode consistency: providing a password for a plain-mode carrier is rejected as an intentional downgrade attack (`400 Bad Request`), and header authentication failure immediately aborts processing before parsing payload bytes.

9. **Capacity Equations:**
   - Available payload channels: $M_{\text{payload}} = M - 456$, where $M = H \times W \times 3$.
   - Available channel triplets: $M_{\text{triplets}} = \lfloor M_{\text{payload}} / 3 \rfloor$.
   - Maximum encoded capacity: $C_{\text{encoded}} = \lfloor (M_{\text{triplets}} \times 2) / 8 \rfloor$ bytes.
   - Maximum RS blocks: $N_{\text{blocks}} = \lfloor C_{\text{encoded}} / 255 \rfloor$.
   - Maximum raw payload budget: $C_{\text{raw}} = N_{\text{blocks}} \times 223$ bytes.

*For complete mathematical proofs, encoding tables, and reference implementations, see [docs/V6_SPECIFICATION.md](file:///c:/Users/rolan/Desktop/RNR/InvisioVault/InvisioVault/docs/V6_SPECIFICATION.md).*

---

### 2.2 Universal Extraction Dispatch & Automatic Engine Detection

InvisioVault's unified extraction endpoint (`POST /api/extract`) does not require the user to specify which engine was used to generate the carrier. Instead, the backend automatically detects the embedded format by inspecting the carrier's initial least-significant bits:

```text
                       ┌────────────────────────┐
                       │ Steganographic Carrier │
                       └───────────┬────────────┘
                                   │
                      detect_stego_engine(image)
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
    Header == b"\xFF\x06"                      Legacy Formats (V1–V5)
              │                                         │
              ▼                                         ▼
      extract_file_v6()                       extract_file_from_image()
 (Matrix coset + Feistel)                     (Adaptive LSB / Edge)
              │                                         │
   ┌──────────┴──────────┐                              │
Success               Failure                           │
   │                     │                              │
HTTP 200              HTTP 400                          │
(X-Engine: v6)   (ZERO fallback to legacy)              │
                         │                              │
                         └──────────────┬───────────────┘
                                        ▼
                            Client Response & Download
```

#### Format Detection Mechanism (`detect_stego_engine`):
1. The extractor reads the first 2 bytes from carrier LSBs.
2. If the first 2 bytes equal `0xFF 0x06`, the carrier is identified as **V6**.
3. If the first 2 bytes equal `0xFF 0x02`, the extractor inspects flag bits to identify **V5**, **V4**, or **V3**.
4. If no magic bytes match, legacy header structures determine **V2** or **V1**.
5. **Zero-Fallback Guarantee:** If V6 extraction fails (due to wrong password, corrupted carrier, or altered header), the extractor aborts with a 400 error immediately. It **never falls back to legacy engines**, preventing downgrade attacks and misleading error messages.

---

### 2.3 Legacy Wire Formats (V1–V5 Extraction Compatibility)

InvisioVault preserves full extraction compatibility for carriers generated by earlier versions:

#### Wire Format v4 / v5 (Legacy Fast Adaptive Writer)
```
┌─────────────────┬───────────────────┬───────────────┬───────────────────────────┐
│ MAGIC (2 Bytes) │ Password Flag (1B)│ Salt (16 B)   │ Metadata Length (4B, BE)  │
│   0xFF 0x02     │   0x20 or 0x21    │ CSPRNG Bytes  │ uint32 Big-Endian         │
├─────────────────┴───────────────────┴───────────────┴───────────────────────────┤
│ Metadata (N Bytes): "filename|mime_type" (Encrypted if password enabled)        │
├─────────────────┬───────────────────┬───────────────────────────────────────────┤
│ Data Length (4B)│ Threshold (1 Byte)│ Payload Bitstream (Permuted via Feistel) │
│ uint32 BE       │ 0x00 - 0xFF       │ Compressed + ECC + Encrypted Data         │
└─────────────────┴───────────────────┴───────────────────────────────────────────┘
```

#### Legacy Flag Bitmasks:
- `0x20` (`_FLAG_PLAIN_FAST`): Plain, compressed + Reed-Solomon ECC, fast adaptive embed with stored threshold (v4/v5).
- `0x21` (`_FLAG_ENC_ONLY_FAST`): Password protected (Fernet AES-128-CBC + HMAC, PBKDF2 480k), compressed + ECC (v4/v5).
- `0x10`, `0x11`, `0x12`: Legacy v3 adaptive formats with stored threshold.
- `0x00`, `0x01`, `0x03`, `0x04`, `0x05`, `0x06`: Legacy v1/v2 sequential and random formats.

#### Sobel Edge Guidance & LSB Matching (Legacy Feature):
In legacy v4/v5 engines, a $3 \times 3$ Sobel filter convolution identifies high-frequency luminance edge pixels ($G(x, y) \ge T$), and $\pm 1$ randomized LSB matching avoids parity skew. These algorithms remain fully operational within the extraction subsystem.

---

### 2.4 ⚠️ CRITICAL LIMITATION: Carrier Degradation & Lossy Compression

> [!WARNING]
> **LSB Steganography CANNOT survive lossy image compression!**
> 
> When an image is uploaded to platforms like **WhatsApp, Twitter/X, Instagram, Facebook, Discord, or Telegram (in default photo mode)**, the platform's media pipeline aggressively converts the image into a lossy JPEG or WebP format with high quantization tables.
>
> Lossy compression works by discarding high-frequency spatial components — the exact least significant bits where the hidden data resides. **A single lossy recompression will permanently destroy the steganographic payload.**
>
> **Best Practice:**
> 1. Always transmit carrier images as **uncompressed raw files** (e.g. "Send as File / Document" in messaging apps, ZIP archives, Google Drive, or email attachments).
> 2. Prefer lossless formats: **PNG** or **BMP**. While JPEG can serve as a carrier in InvisioVault, it must remain bit-for-bit unchanged post-embedding.

---

A polyglot file simultaneously satisfies two distinct file format parsers without error.

```
┌─────────────────────────────────────────────────────────────┐
│                    Carrier Header & Data                    │
│    (PNG, JPEG, PDF, MP4, MP3 parsed from file offset 0)     │
├─────────────────────────────────────────────────────────────┤
│                    Appended ZIP Archive                     │
│    • Local File Headers (LFH)                               │
│    • Deflated File Data                                     │
│    • Central Directory File Headers (CDFH) [PATCHED]        │
│    • End of Central Directory Record (EOCD) [PATCHED]       │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 The Offset Problem
Standard archive utilities (WinRAR, 7-Zip, macOS Archive Utility, Linux `unzip`) do **not** read ZIP files from the beginning. Instead, they seek from the **end of the file** backwards to find the **End of Central Directory (EOCD)** signature (`0x06054b50` / `PK\x05\x06`).

The EOCD record contains:
- `offset_to_cd`: The byte offset from the start of the file where the Central Directory begins.
- Each Central Directory header contains `offset_to_lfh`: The byte offset from the start of the file where that file's Local File Header begins.

When a ZIP archive is appended to a carrier file of size $S_{carrier}$, all absolute offsets stored inside the ZIP structures become incorrect by exactly $+S_{carrier}$. Simple concatenation breaks standard unzippers.

---

### 3.2 In-Memory Binary Offset Patching (`_fix_zip_offsets()`)

InvisioVault uses zero-copy memory mapping (`mmap`) to parse and rewrite all offsets in place:

1. Locate the EOCD record within the last 65,557 bytes of the file.
2. Read the 32-bit Central Directory offset at byte offset $+16$ of the EOCD.
3. If the offset is `0xFFFFFFFF` (ZIP64 format):
   - Locate the ZIP64 EOCD locator (`PK\x06\x07`) and ZIP64 EOCD record (`PK\x06\x06`).
   - Patch the 64-bit Central Directory offset at $+48$.
4. Patch the 32-bit EOCD offset:
   $$\text{offset}_{CD}' = \text{offset}_{CD} + S_{carrier}$$
5. Iterate through every Central Directory File Header (`PK\x01\x02`):
   - Patch the 32-bit Local Header relative offset at $+42$:
     $$\text{offset}_{LFH}' = \text{offset}_{LFH} + S_{carrier}$$

The resulting file functions flawlessly:
- Opening it in an image viewer or media player reads from byte 0 and ignores trailing data.
- Opening it in an archive manager or renaming to `.zip` parses from the EOCD and extracts the hidden files cleanly.

---

## 4. QR Code Steganography Engine

InvisioVault generates QR codes **exclusively using Visual Module Steganography (Mode 1)** to guarantee 100% plausible deniability. A secondary legacy scheme, **Stream Mode**, is supported strictly as a read/extract-only decoder for backwards compatibility.

> [!NOTE]
> **Why does the UI only show Visual Mode for QR generation?**  
> The generation interface does not include a mode toggle because **Visual Module Mode is the sole active generation mechanism**. Stream Mode generation was intentionally retired in v2.0+ to prevent URL fragment exposure (`#IVDATA:`) in camera apps and social link-preview crawlers. Stream decoding remains embedded in the scanner pipeline solely to support legacy barcodes without breaking backward compatibility.

### 4.1 Active Generation Mode: Visual Module Mode (Structural Isolation)
Encodes clean public data in the QR matrix while embedding the encrypted secret into non-critical data modules.
- **Structural Module Preservation:** Standard QR decoders fail if functional patterns are modified. InvisioVault builds an explicit bitmask isolating:
  - Finder patterns ($7\times7$ corners) and separators
  - Timing patterns (alternating row/column lines)
  - Alignment patterns (version-dependent $5\times5$ squares)
  - Format info modules and version info blocks
  - Quiet zone padding (4-module border)
- Hidden bits are embedded only into non-structural data modules using Reed-Solomon redundancy parity blocks.
- **Zero Decoded Footprint:** Any standard mobile camera or barcode reader reads only the pristine public text/URL without any fragment or steganographic trace.

---

### 4.2 Legacy Mode: Stream Mode (URL Fragment Transport — Read/Extract Only)
In earlier versions, secret data could be compressed, encrypted, and embedded into the URI Fragment (`#IVDATA:`):

```
https://public-domain.com/landing#IVDATA:eyJhbGciOiJGRVJORVQiLCJzYWx0Ijoi...
```

**Generation Status in v2.0+:**
- **Generation Retired:** Stream QR generation has been permanently retired in production to eliminate URL fragment exposure in modern link-preview apps and ensure generated QR codes are 100% indistinguishable from standard barcodes. Calling `/api/qr/generate` with `method="stream"` explicitly returns an HTTP 400 error. InvisioVault now generates QR codes exclusively using clean **Visual Module Steganography** (Mode 1).
- **Extraction Preserved:** Full Stream Mode decoding and `#IVDATA:` parsing remains active in `useQRScanner.js` and `/api/qr/scan` to preserve backwards compatibility when scanning legacy double-agent barcodes.

---

### 4.3 Real-Time WebRTC Camera Scanner Pipeline

The frontend camera scanner (`useQRScanner.js`) runs a continuous multi-stage pipeline:

```
Camera Video Stream (getUserMedia)
           │
           ▼
Canvas Frame Capture (Native Resolution)
           │
           ├──────────────────────────────────────────────┐
           ▼                                              ▼
   Original Canvas                                Enhanced Canvas
(Color preservation for                        (2x Bilinear Upscale +
  subtle visual modules)                        Grayscale + 50% Contrast)
           │                                              │
           ▼                                              ▼
     jsQR Detection                                 jsQR Detection
           │                                              │
           └──────────────────────┬───────────────────────┘
                                  │
                       QR Code Detected?
                       ├── Yes ──> Parse #IVDATA: locally or query /api/qr/scan
                       └── No  ──> Check SHA-256 Deduplication Cache
                                   └── Forward to Backend /api/qr/detect (zxing-cpp)
```

---

## 5. Memory Safety & Concurrency Control (Render 512 MB Architecture)

InvisioVault is deployed on Render's free tier with a strict **512 MB RAM limit**. High-resolution images (e.g. 24 MP phone photos) decompressed into raw uncompressed RGB arrays consume:

$$6000 \times 4000 \times 3 \text{ bytes} \approx 72 \text{ MB per buffer}$$

Multiple simultaneous uploads would trigger Linux OOM Killer terminations.

### Mitigations:
1. **Bounded Semaphore Concurrency:** All memory-intensive routes (`/api/hide`, `/api/extract`, `/api/polyglot/create`) acquire `_heavy_operation_semaphore = threading.BoundedSemaphore(1)` with a 30-second timeout.
2. **Immediate Temp Unlinking:** Every file write registers in an exception-safe `_remove_quietly()` cleanup list called inside `finally` blocks.
3. **Background Scavenger Thread:** `FileCleanupScheduler` runs independently in each Gunicorn worker (spawned via `post_fork` in `gunicorn.conf.py`) removing files older than 5 minutes.

---

## 6. Known Technical Limitations (v2.0.1)

To ensure cryptographic transparency, the following design boundaries are formally documented:

1. **Lossy Compression Incompatibility:**
   - LSB payloads are **permanently destroyed** by lossy image recompression (WhatsApp, Twitter/X, Instagram, Discord, and photo cloud sync tools). Carriers must be transmitted as uncompressed documents or raw binary files.
2. **QR Code Stream Generation Retired:**
   - Stream Mode (`#IVDATA:`) generation has been retired to eliminate URL fragment exposure in modern browsers and third-party barcode readers. QR code generation exclusively uses clean Visual Module Steganography. Extraction of legacy stream barcodes remains fully operational.
3. **macOS Finder Quick Look Anomaly:**
   - While polyglot PNG+ZIP files open perfectly in preview apps and unarchive cleanly in archive tools, macOS Quick Look may display an error on specific PNG+ZIP combinations if Apple's parser strictly rejects trailing bytes following the `IEND` chunk.
4. **Render Free-Tier Concurrency Serialization:**
   - Under Render's 512 MB memory ceiling, `_heavy_operation_semaphore` serializes heavy LSB image convolutions to 1 concurrent request per worker to eliminate Linux OOM terminations.

