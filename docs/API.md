# InvisioVault REST API Reference

The InvisioVault backend provides a stateless, high-performance REST API for image steganography, universal polyglot creation, and stealth QR code generation.

* **Base URL (Production):** `https://invisiovault-backend.onrender.com/api`
* **Base URL (Local Dev):** `http://localhost:5000/api`
* **Root Host (Health Probe):** `https://invisiovault-backend.onrender.com/`
* **OpenAPI 3.0 Specification:** [docs/openapi.yaml](file:///c:/Users/rolan/Desktop/RNR/InvisioVault/InvisioVault/docs/openapi.yaml)

---

## Global Rate Limits & Security Headers

| Route Category | Default Limit | Strategy | Notes |
|---|---|---|---|
| `GET /` | Exempt | N/A | Infrastructure root probe (always responds 200). |
| `GET /api/health` | Exempt | N/A | Application health check endpoint. |
| `POST /api/calculate-capacity` | 30 / minute | IP Token Bucket | Throttles automated dimension scanning. |
| `POST /api/qr/capacity` | 30 / minute | IP Token Bucket | QR barcode capacity computation. |
| `POST /api/hide` | 10 / hour | IP Token Bucket | Heavy endpoint with LSB pixel convolution. |
| `POST /api/polyglot/create` | 10 / hour | IP Token Bucket | Heavy endpoint with binary file concatenation. |
| `POST /api/qr/detect` | 60 / minute | IP Token Bucket | High-speed camera scanner loop (SHA-256 cached). |
| All other routes | 100/hr, 200/day | Global IP Limit | Standard endpoint protection. |

All responses return strict production security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'none'; script-src 'none'; style-src 'none'; ...`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (when HTTPS)

---

## 1. Hosting & System Endpoints

### `GET /` (Root Service Probe)
Low-level infrastructure health probe hosted directly at the root URL (outside the `/api` prefix). Specifically intended for container orchestrators and cloud uptime monitors (e.g. Render, AWS ALB, Kubernetes) to verify process liveness without triggering rate limiters.

**Curl Example:**
```bash
curl -X GET https://invisiovault-backend.onrender.com/
```

**Response (200 OK):**
```json
{
  "name": "InvisioVault API",
  "status": "running",
  "version": "2.0.1"
}
```

---

### `GET /api/health`
Application-level health check endpoint under the `/api` blueprint. Confirms environment readiness and blueprint registration.

**Curl Example:**
```bash
curl -X GET https://invisiovault-backend.onrender.com/api/health
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "message": "InvisioVault API is running"
}
```

---

### `POST /api/calculate-capacity`
Reads image dimension metadata directly from the upload stream without full RGB memory expansion to report maximum payload capacity in bytes.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Carrier image (PNG, JPG, BMP).

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/calculate-capacity \
  -F "image=@carrier.png"
```

**Response (200 OK):**
```json
{
  "totalCapacityBytes": 2073600,
  "totalCapacityFormatted": "1.9 MB"
}
```

---

## 2. Image Steganography Endpoints

InvisioVault uses **V6** as its canonical primary steganography engine for all new embedding operations. Legacy engines (V1–V5) remain fully supported internally for backward-compatible extraction.

---

### `POST /api/hide-v6` (Primary Embedding Endpoint)
Conceals a secret file or plaintext string into an image carrier using the **InvisioVault V6** steganography engine. Employs Matrix (3,2) coset syndrome coding, 10-round balanced Feistel channel permutation, dynamic-group interleaved Reed-Solomon RS(255, 223), and 57-byte authenticated headers.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Carrier image (PNG, JPG, BMP). Max 10 MB, up to 10 megapixels.
- `file` *(file, optional)*: Secret file to conceal (max 50 MB; 1 MB operational ceiling for carriers > 4 MP).
- `text` *(string, optional)*: Plaintext string to conceal (if `file` not supplied).
- `mode` *(string, optional)*: Operating mode: `encrypted` (default) or `plain`.
- `password` *(string, optional)*: Passphrase for encrypted mode (minimum 8 characters; strictly prohibited in plain mode).

**Curl Example (Encrypted Mode):**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/hide-v6 \
  -F "image=@carrier.png" \
  -F "file=@confidential.pdf" \
  -F "mode=encrypted" \
  -F "password=supersecretpassphrase"
```

**Curl Example (Plain Mode):**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/hide-v6 \
  -F "image=@carrier.png" \
  -F "text=Public verifiable manifesto" \
  -F "mode=plain"
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "File hidden successfully using V6 engine",
  "download_id": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d.png",
  "mode": "encrypted",
  "metadata": {
    "engine": "v6",
    "triplets_used": 15420,
    "rs_blocks": 15,
    "mode": "encrypted"
  }
}
```

---

### `POST /api/extract` (Unified Automatic Extraction Endpoint)
Recovers hidden files from any InvisioVault steganographic carrier. The backend **automatically detects** whether the carrier was embedded using the V6 engine or a legacy version (V1–V5) by inspecting initial channel LSBs (`detect_stego_engine`). No manual engine selection is required.

**Zero-Fallback Invariant:** If V6 extraction fails (e.g. incorrect password, corrupt matrix embedding, or damaged header), an HTTP 400 error is returned immediately. The extractor **never silently falls back** to legacy engines.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Steganographic carrier image (PNG, JPG, BMP). Max 50 MB.
- `password` *(string, optional)*: Passphrase used during embedding (required for encrypted carriers; prohibited for V6 plain carriers).

**Response Headers:**
- `Content-Disposition: attachment; filename="<original_filename>"`
- `X-InvisioVault-Engine: v6` (or `v5`, `v4`, etc.)
- `X-InvisioVault-Mode: encrypted` (or `plain`)

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/extract \
  -F "image=@stego_carrier.png" \
  -F "password=supersecretpassphrase" \
  -O -J
```

---

### `POST /api/extract-v6` (Dedicated V6 Extraction Endpoint)
Directly extracts payloads embedded with the V6 engine. Performs 10-round Feistel permutation inversion on channel coordinates, Reed-Solomon dynamic-group de-interleaving, CRC-32 / Fernet authentication verification, and strict mode-downgrade prevention.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Stego image containing V6 payload.
- `password` *(string, optional)*: Passphrase (required if carrier was embedded in encrypted mode).
- `mode` *(string, optional)*: Expected mode: `auto` (default), `encrypted`, or `plain`.

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/extract-v6 \
  -F "image=@stego_v6.png" \
  -F "password=supersecretpassphrase" \
  -O -J
```

**Response Headers:**
- `Content-Disposition: attachment; filename="confidential.pdf"`
- `X-InvisioVault-Engine: v6`
- `X-InvisioVault-Mode: encrypted`

---

### `POST /api/calculate-capacity-v6` (V6 Exact Capacity Calculation)
Computes exact raw payload capacity, pre-RS stream budget, codeword block count, and recommended maximum file payload under V6 Matrix (3,2) coset coding. Reads image dimension headers directly from the upload stream without full RGB memory expansion.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Carrier image (PNG, JPG, BMP).

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/calculate-capacity-v6 \
  -F "image=@carrier.png"
```

**Response (200 OK):**
```json
{
  "totalCapacityBytes": 1382400,
  "totalCapacityFormatted": "1.32 MB",
  "engine": "v6",
  "v6_details": {
    "carrier_pixels": 2073600,
    "available_channels": 6220344,
    "available_triplets": 2073448,
    "max_raw_payload_capacity": 432360,
    "rs_block_count": 1938,
    "interleave_k": 4
  }
}
```

---

### `GET /api/download/<download_id>`
Retrieves the processed steganographic image. **Zero-Copy Disk Streaming**: Streams directly from temporary disk storage using Werkzeug's `wsgi.file_wrapper` to eliminate RAM buffering.

**Curl Example:**
```bash
curl -O https://invisiovault-backend.onrender.com/api/download/8f3b4a2e5c6d4b7e9f1a2d3e4f5a6b7c.png
```

---

### Legacy Steganography Compatibility Endpoints

The following endpoints remain active on the backend exclusively for backward compatibility with legacy clients and automated regression harnesses. Normal user interfaces use the V6 endpoints above.

#### `POST /api/hide` (Legacy Embedding Endpoint)
Embeds a secret file or text into an image carrier using legacy Sobel edge guidance, Reed-Solomon ECC, and optional Fernet encryption (V4/V5 wire format).

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Carrier image (PNG, JPG, BMP). Max 10 MB.
- `file` *(file, optional)*: Secret file to hide. Max 50 MB.
- `text` *(string, optional)*: Text string to hide.
- `password` *(string, optional)*: Passphrase for PBKDF2 (480k iter) + Fernet encryption.

#### `POST /api/calculate-capacity` (Legacy Capacity Endpoint)
Reads image dimensions to estimate raw byte capacity under the legacy V4/V5 Sobel edge-matching model.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Carrier image (PNG, JPG, BMP).

**Response (200 OK):**
```json
{
  "totalCapacityBytes": 2073600,
  "totalCapacityFormatted": "1.9 MB"
}
```

---

## 3. Universal Polyglot Endpoints

### `POST /api/polyglot/create`
Combines any carrier format (PNG, JPEG, PDF, MP4, MP3) with a hidden payload file, performing in-memory binary ZIP offset patching (`_fix_zip_offsets()`) so both formats execute cleanly.

**Parameters (multipart/form-data):**
- `carrier` *(file, required)*: Visible carrier file. Max 10 MB.
- `file` *(file, required)*: Secret file to embed (accepts alias `payload`). Max 50 MB.
- `password` *(string, optional)*: Optional AES passphrase (min 8 characters).

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/polyglot/create \
  -F "carrier=@cover.pdf" \
  -F "file=@archive.zip" \
  -F "password=optionalpass"
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Polyglot file created successfully",
  "download_id": "e4f5a6b71c2d3e4f5a6b7c8d9e0f1a2b.pdf"
}
```

---

### `GET /api/polyglot/download/<download_id>`
Retrieves the processed polyglot file. Streams directly from filesystem storage without intermediate memory duplication.

**Curl Example:**
```bash
curl -O https://invisiovault-backend.onrender.com/api/polyglot/download/e4f5a6b71c2d3e4f5a6b7c8d9e0f1a2b.pdf
```

---

### `POST /api/polyglot/extract`
Extracts embedded payloads from a polyglot carrier file.

**Parameters (multipart/form-data):**
- `file` *(file, required)*: The polyglot file to extract from.
- `password` *(string, optional)*: Decryption passphrase.

**Curl Example:**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/polyglot/extract \
  -F "file=@polyglot_cover.pdf" \
  -F "password=optionalpass" \
  -O -J
```

---

## 4. QR Steganography Endpoints

### `POST /api/qr/generate`
Creates a stealth QR code containing clean public data and a hidden secret embedded via Visual Module Steganography. Supports both `application/json` and `multipart/form-data`.

**Parameters:**
- `public_data` *(string, required)*: Public text or URL visible to standard smartphone cameras.
- `secret_text` *(string, required)*: Hidden message (accepts legacy alias `secret_message`).
- `password` *(string, optional)*: Passphrase for Fernet encryption (min 8 characters).
- `fg_color` *(string, optional)*: QR module hex color (accepts alias `dark_color`, default `#000000`).
- `bg_color` *(string, optional)*: QR background hex color (accepts alias `light_color`, default `#FFFFFF`).
- `scale` *(integer, optional)*: Pixel scale factor 1–50 (default: 10).
- `method` *(string, optional)*: Steganography mode (`visual` is the default and only valid generation option; `stream` generation was retired in v2.0+ to prevent URL fragment exposure and returns 400). Accepts legacy alias `mode`.
- `logo` *(file, optional, multipart/form-data only)*: Center logo image.

**Curl Example (JSON):**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/qr/generate \
  -H "Content-Type: application/json" \
  -d '{
    "public_data": "https://rolan-rnr.netlify.app/",
    "secret_text": "Master encryption seed: 4a8f9c...",
    "password": "passphrase123",
    "fg_color": "#000000",
    "bg_color": "#FFFFFF"
  }'
```

**Curl Example (Multipart with Logo):**
```bash
curl -X POST https://invisiovault-backend.onrender.com/api/qr/generate \
  -F "public_data=https://example.com" \
  -F "secret_text=Confidential intelligence" \
  -F "logo=@company_logo.png"
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "QR code generated successfully",
  "download_id": "d1c2b3a45e6f7a8b9c0d1e2f3a4b5c6d_qr.png"
}
```

---

### `GET /api/qr/download/<download_id>`
Retrieves the generated QR code PNG. Streams directly from disk storage.

**Curl Example:**
```bash
curl -O https://invisiovault-backend.onrender.com/api/qr/download/d1c2b3a45e6f7a8b9c0d1e2f3a4b5c6d_qr.png
```

---

### `POST /api/qr/capacity`
Calculates the maximum hidden secret capacity (in bytes) for a prospective QR code given the public data length and error correction requirements.

**Request Body (application/json):**
```json
{
  "public_data": "https://rolan-rnr.netlify.app/"
}
```

**Response (200 OK):**
```json
{
  "visual_capacity_bytes": 1200,
  "version": 7,
  "error_correction": "H"
}
```

---

### `POST /api/qr/scan`
Decodes both the visible public layer and hidden steganographic payload from an uploaded QR code image.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: QR barcode image.
- `password` *(string, optional)*: Passphrase if encrypted.

**Response (200 OK):**
```json
{
  "public_data": "https://rolan-rnr.netlify.app/",
  "secret_message": "Master encryption seed: 4a8f9c...",
  "mode": "visual"
}
```

---

### `POST /api/qr/extract`
Manual recovery endpoint for extracting hidden payloads from pre-decoded QR barcode text or raw module sequences.

**Parameters (multipart/form-data or application/json):**
- `image` *(file, optional)*: QR image to extract from.
- `password` *(string, optional)*: Decryption passphrase.

---

### `POST /api/qr/detect`
High-speed camera frame detection endpoint for the real-time webcam scanner. Features in-memory SHA-256 frame deduplication caching to avoid redundant C++ ZXing decodes on identical frames.

**Parameters (multipart/form-data):**
- `image` *(file, required)*: Video frame capture.

**Response (200 OK):**
```json
{
  "detected": true,
  "text": "https://rolan-rnr.netlify.app/"
}
```
