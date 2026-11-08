# InvisioVault V6 — Authoritative Implementation Specification (Frozen Baseline)

**Document ID:** `IV-V6-CANONICAL-SPEC-FROZEN`  
**Classification:** Definitive Technical Specification & Implementation Blueprint  
**Status:** SPECIFICATION FROZEN / AUTHORIZED FOR IMPLEMENTATION  
**Target Release:** InvisioVault v6.0.0 (`backend/utils/steganography_v6.py`)  
**Date:** November 2026  

---

## 1. Architecture Overview

InvisioVault V6 is a resilient, low-distortion, cryptographically structured steganography engine designed for high-assurance data hiding in uncompressed raster carriers (PNG).

### 1.1 Core Technological Pillars

1. **Matrix (3, 2) Coset Encoding:** Embeds 2 payload bits into every 3 carrier channels using at most 1 bit-flip. Achieves an average embedding change rate of 25% (0.375 flips/bit), reducing carrier modifications by 25% compared to standard LSB replacement (0.50 flips/bit).
2. **Interleaved Reed-Solomon RS(255, 223):** Employs dynamic-group block interleaving with depth $K = 4$. Corrects up to 16 symbol errors per 255-byte block and tolerates localized burst corruptions of up to 64 contiguous bytes with zero padding overhead.
3. **10-Round Balanced Feistel Channel Permutation:** Disperses payload bits pseudorandomly across carrier pixel coordinates using an in-memory 10-round Feistel network with precomputed AES-256-CTR round tables (160 KiB total RAM, residing entirely within CPU L2 cache).
4. **Cycle Walking Domain Restriction & Runtime Guard:** Restricts the power-of-two Feistel block cipher onto arbitrary carrier channel domains $\{0, \dots, M-1\}$ with proven bijectivity and zero collisions. A runtime guard (`MAX_CYCLE_WALK_ITERATIONS = 100`) prevents latency spikes, backed by a 5-attempt fresh-salt retry loop during embedding.
5. **Two-Tier HKDF Key Separation:** Uses PBKDF2-HMAC-SHA256 (600,000 iterations) to derive a master secret, from which cryptographically independent keys are derived for header authentication, Fernet payload encryption, and carrier permutation.
6. **Authenticated Header & Downgrade Prevention:** Enforces strict expected-mode binding and credential-presence validation to eliminate silent mode downgrade attacks.

### 1.2 Subsystem Pipeline

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
[Stego Carrier PNG]
```

---

## 2. Encryption and Key Derivation

V6 uses a unified, standard cryptographic stack based on `cryptography` primitives already present in the production environment (`cryptography==50.0.1`).

### 2.1 Cryptographic Primitives

- **KDF:** PBKDF2-HMAC-SHA256 (NIST SP 800-132, OWASP 2023+ recommendation).
- **Subkey Derivation:** HKDF Extract-and-Expand with SHA-256 (RFC 5869).
- **Payload AEAD:** Fernet (AES-128-CBC with PKCS7 padding, HMAC-SHA256 authentication).
- **Header Authentication:** HMAC-SHA256 (RFC 2104).
- **Salt Generation:** `os.urandom(16)` (Cryptographically Secure Pseudo-Random Number Generator).

### 2.2 Key Schedule Equations (Encrypted Mode)

1. **Master Key Derivation (PBKDF2):**
   $$K_{\text{master}} = \text{PBKDF2-HMAC-SHA256}(\text{password}, \text{salt}_{\text{img}}, \text{iterations}=600,000, \text{length}=32)$$
   where $\text{salt}_{\text{img}}$ is the 16-byte random salt stored in the carrier header.

2. **Header Authentication Subkey:**
   $$K_{\text{auth}} = \text{HKDF-Expand}(K_{\text{master}}, \text{info}=b\text{"InvisioVault-v6-Header-Auth"}, \text{length}=32)$$

3. **Payload Encryption Subkey (Fernet):**
   $$K_{\text{enc}} = \text{HKDF-Expand}(K_{\text{master}}, \text{info}=b\text{"InvisioVault-v6-Payload-Encryption"}, \text{length}=32)$$
   $$\text{Key}_{\text{Fernet}} = \text{base64.urlsafe\_b64encode}(K_{\text{enc}})$$

4. **Permutation Root Subkey:**
   $$K_{\text{perm\_root}} = \text{HKDF-Expand}(K_{\text{master}}, \text{info}=b\text{"InvisioVault-v6-Permutation-Root"} \,\|\, \text{salt}_{\text{img}}, \text{length}=32)$$

5. **Feistel Round Keys and IVs (10 Rounds):**
   For each round index $i \in \{0, 1, \dots, 9\}$:
   $$K_i = \text{HKDF-Expand}(K_{\text{perm\_root}}, \text{info}=b\text{"InvisioVault-v6-RoundKey-"} \,\|\, \langle i \rangle_1, \text{length}=32)$$
   $$\text{IV}_i = \text{HKDF-Expand}(K_{\text{perm\_root}}, \text{info}=b\text{"InvisioVault-v6-RoundIV-"} \,\|\, \langle i \rangle_1, \text{length}=16)$$
   where $\langle i \rangle_1$ is a 1-byte big-endian representation of integer $i$.

### 2.3 Raw Binary Fernet Token Format

To eliminate the 33% storage expansion of base64 encoding inside the steganographic carrier, V6 stores the **raw binary Fernet token**:
$$\text{raw\_token} = \text{base64.urlsafe\_b64decode}(\text{Fernet}(\text{Key}_{\text{Fernet}}).\text{encrypt}(\text{data}))$$

Binary Fernet token structure (57 bytes total overhead + ciphertext):
- `Version` (1 byte): `0x80`
- `Timestamp` (8 bytes): 64-bit big-endian integer (seconds since Unix epoch)
- `IV` (16 bytes): 128-bit random initialization vector
- `Ciphertext` (variable): AES-128-CBC encrypted data with PKCS7 padding
- `HMAC` (32 bytes): HMAC-SHA256 over `Version || Timestamp || IV || Ciphertext`

---

## 3. Plain-Mode Behavior and Key Derivation

In Plain Mode (`mode = 0x40`), the user does not supply a password.

### 3.1 Deterministic Permutation Derivation

To ensure the carrier permutation is 100% reproducible between embedding and extraction without a password:
1. The carrier salt $\text{salt}_{\text{img}}$ (16 bytes) is generated randomly via `os.urandom(16)` during embedding and stored in the header.
2. Both embedder and extractor derive $K_{\text{perm\_root}}$ from a public universal constant seed combined with $\text{salt}_{\text{img}}$:
   $$K_{\text{plain\_fixed}} = \text{SHA256}(b\text{"InvisioVault-v6-PlainMode-PublicSeed-2026"})$$
   $$K_{\text{perm\_root}} = \text{HKDF-Expand}(K_{\text{plain\_fixed}}, \text{info}=b\text{"InvisioVault-v6-Plain-Permutation-Root"} \,\|\, \text{salt}_{\text{img}}, \text{length}=32)$$
3. The 10 round keys $K_0 \dots K_9$ and IVs $\text{IV}_0 \dots \text{IV}_9$ are derived from $K_{\text{perm\_root}}$ using the exact same HKDF equations as Encrypted Mode (Section 2.2, Step 5).

### 3.2 Accidental Corruption Checksum

In Plain Mode, no Fernet encryption is performed. To detect transmission errors, channel noise, and Reed-Solomon decoder miscorrections:
- A 4-byte CRC-32 checksum of the serialized payload is prepended to the pre-RS stream:
  $$\text{checksum} = \text{struct.pack}(b\text{">I"}, \text{zlib.crc32}(\text{serialized\_payload}) \ \& \ 0\text{xFFFFFFFF})$$
  $$\text{pre\_rs\_stream} = \text{checksum} \,\|\, \text{serialized\_payload}$$

### 3.3 Honest Plain-Mode Security Notice

> [!WARNING]
> **Plain mode provides ZERO cryptographic confidentiality and ZERO adversarial tamper protection.**
> The carrier permutation is derived entirely from public constants and the unencrypted header salt. Anyone possessing the stego-image can extract and read the payload. The CRC-32 checksum detects only accidental transmission errors and RS miscorrections; an active attacker can alter carrier bits and update the checksum trivially. Users requiring confidentiality or integrity against an adversary must use Encrypted Mode.

---

## 4. Header Structure and Byte Offsets

The V6 header is exactly **57 bytes** ($456\text{ bits}$). It is embedded sequentially into carrier channels $0 \dots 455$ using standard LSB replacement.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic: 0xFF 0x06        |  Mode (0x40/41)| Interleave K |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Reserved (0x00)|               Salt (Bytes 0..11)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Salt (Bytes 12..15)      | Raw Payload Length (uint32_be)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Authentication / Integrity Tag              |
|                             (32 Bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.1 Header Field Definitions

| Byte Offset | Field Name | Data Type | Permitted Values | Description |
| :---: | :--- | :--- | :--- | :--- |
| `0x00 - 0x01` | `magic` | `bytes[2]` | `b"\xFF\x06"` | InvisioVault V6 protocol identifier. |
| `0x02` | `mode` | `uint8` | `0x40` (Plain), `0x41` (Encrypted) | Operational mode. |
| `0x03` | `interleave_k`| `uint8` | `4` (`1, 2, 4, 8, 16` supported) | Interleaving depth. Default: `4`. |
| `0x04` | `reserved` | `uint8` | `0x00` | Reserved for future expansion. Must be 0. |
| `0x05 - 0x14` | `salt` | `bytes[16]`| 16 random bytes | Carrier salt `salt_img` from `os.urandom(16)`. |
| `0x15 - 0x18` | `raw_payload_len` | `uint32_be`| $1 \le L_{\text{raw}} \le \text{MaxCapacity}$ | Exact original unpadded raw payload stream length in bytes. |
| `0x19 - 0x38` | `auth_tag` | `bytes[32]`| 32-byte hash / MAC | Authentication / Integrity tag. |

### 4.2 Stream Length Derivations

By storing the exact unpadded length $L_{\text{raw}} = \text{raw\_payload\_len}$ in the header body, all downstream stream parameters are uniquely and deterministically derived by both embedder and extractor:
- **RS Codeword Count ($N$):**
  $$N = (L_{\text{raw}} + 222) // 223 = \left\lceil \frac{L_{\text{raw}}}{223} \right\rceil$$
- **Padded Pre-RS Stream Length:**
  $$\text{pre\_rs\_len} = N \times 223$$
- **Pre-RS Zero Padding Bytes:**
  $$pad = \text{pre\_rs\_len} - L_{\text{raw}}$$
- **Total Interleaved Encoded Bytes:**
  $$\text{encoded\_stream\_len} = N \times 255$$

Because $L_{\text{raw}}$ is located in bytes `0x15..0x18` of the header body, it is **cryptographically authenticated** under `auth_tag` (HMAC-SHA256 in Encrypted Mode, SHA-256 in Plain Mode). Any unauthorized alteration of the payload length triggers an immediate header validation failure before Reed-Solomon decoding or memory allocation occurs.

### 4.2 Header Tag Calculation

Let $\text{header\_body} = \text{header}[0\text{x}00 \dots 0\text{x}18]$ (the first 25 bytes).
- **Encrypted Mode (`0x41`):**
  $$\text{auth\_tag} = \text{HMAC-SHA256}(K_{\text{auth}}, \text{header\_body})$$
- **Plain Mode (`0x40`):**
  $$\text{auth\_tag} = \text{SHA-256}(\text{header\_body})$$

### 4.3 Mode Downgrade Protection & Validation Policy

To prevent an adversary from tampering with byte `0x02` to downgrade an encrypted carrier to plain mode:
1. **Expected-Mode Parameter:** The extractor accepts an explicit `expected_mode` argument (`"auto"`, `"plain"`, or `"encrypted"`). Default: `"auto"`.
2. **Credential Invariant:** If `password is not None`, the extractor **strictly requires `mode == 0x41`**. If `mode == 0x40`, it immediately raises:
   ```python
   raise DowngradeAttackError("Carrier claims plain mode, but a password was provided. Rejected potential downgrade attack.")
   ```
3. **Strict Mode Enforcement:**
   - If `expected_mode == "encrypted"` and `mode == 0x40`: raise `DowngradeAttackError`.
   - If `expected_mode == "plain"` and `mode == 0x41`: raise `ValueError("Carrier is encrypted; password required.")`.
4. **Tag Verification:**
   - If `mode == 0x41`: Derive $K_{\text{auth}}$ from password, verify `auth_tag` using `hmac.compare_digest`. On mismatch, raise `HeaderAuthenticationError("Invalid password or corrupted header.")`.
   - If `mode == 0x40`: Compute $\text{SHA-256}(\text{header\_body})$, verify `auth_tag` using `hmac.compare_digest`. On mismatch, raise `HeaderIntegrityError("Corrupted plain header.")`.

---

## 5. Payload Serialization and Framing

### 5.1 Metadata Serialization

All embedded payloads include a JSON metadata envelope specifying file characteristics:
```json
{
  "filename": "secret.pdf",
  "file_type": "file",
  "file_size": 1048576,
  "compressed": true
}
```
*For text payloads: `"filename": "text_payload.txt"`, `"file_type": "text"`.*

**Metadata Framing:**
$$\text{metadata\_bytes} = \text{json.dumps}(metadata, \text{separators}=(',', ':')).\text{encode}(\text{"utf-8"})$$
$$\text{framed\_metadata} = \text{struct.pack}(b\text{">H"}, \text{len}(\text{metadata\_bytes})) \,\|\, \text{metadata\_bytes}$$

### 5.2 Compression

If `compressed == True`, the payload data is compressed using `zlib.compress(payload_bytes, level=9)`. If compression increases the size (or payload is already compressed), compression is skipped and `"compressed": False` is set.

### 5.3 Inner Stream Construction

- **Encrypted Mode:**
  $$\text{inner\_plain} = \text{framed\_metadata} \,\|\, \text{compressed\_payload}$$
  $$\text{raw\_token} = \text{base64.urlsafe\_b64decode}(\text{Fernet}(\text{Key}_{\text{Fernet}}).\text{encrypt}(\text{inner\_plain}))$$
  $$\text{raw\_payload\_stream} = \text{raw\_token}$$
- **Plain Mode:**
  $$\text{inner\_plain} = \text{framed\_metadata} \,\|\, \text{compressed\_payload}$$
  $$\text{checksum} = \text{struct.pack}(b\text{">I"}, \text{zlib.crc32}(\text{inner\_plain}) \ \& \ 0\text{xFFFFFFFF})$$
  $$\text{raw\_payload\_stream} = \text{checksum} \,\|\, \text{inner\_plain}$$

### 5.4 Pre-RS Padding and Exact Extraction Trimming

Reed-Solomon RS(255, 223) operates strictly on message blocks of 223 bytes.

#### 5.4.1 Embedding Padding Sequence
1. Measure the exact unpadded length of `raw_payload_stream`:
   $$L_{\text{raw}} = \text{len}(\text{raw\_payload\_stream})$$
2. Compute codeword count $N$ and padded length $\text{pre\_rs\_len}$:
   $$N = (L_{\text{raw}} + 222) // 223 = \left\lceil \frac{L_{\text{raw}}}{223} \right\rceil$$
   $$\text{pre\_rs\_len} = N \times 223$$
3. Determine padding bytes:
   $$pad = \text{pre\_rs\_len} - L_{\text{raw}} \quad (0 \le pad < 223)$$
4. Construct padded pre-RS stream:
   $$\text{pre\_rs\_stream} = \text{raw\_payload\_stream} \,\|\, (b\text{"\x00"} \times pad)$$
5. The exact unpadded length $L_{\text{raw}}$ is stored in header bytes `0x15..0x18` and authenticated by `auth_tag`.

#### 5.4.2 Extraction Trimming Behavior
1. Read and authenticate $L_{\text{raw}} = \text{header}[0\text{x}15 \dots 0\text{x}18]$.
2. Compute $N = (L_{\text{raw}} + 222) // 223$ and extract $N$ Reed-Solomon codewords ($N \times 255$ bytes).
3. Reed-Solomon decode the $N$ codewords to recover $\text{pre\_rs\_len} = N \times 223$ bytes.
4. Deterministically slice the recovered stream:
   $$\text{raw\_payload\_stream} = \text{recovered\_pre\_rs}[:L_{\text{raw}}]$$
5. All $pad$ zero-padding bytes are discarded without heuristic guessing or stripping legitimate data zeros:
   - In **Encrypted Mode**: Fernet receives the exact binary token, base64 urlsafe-encodes it, and validates the HMAC tag over the exact original ciphertext.
   - In **Plain Mode**: The extractor reads `expected_crc = raw_payload_stream[:4]`, computes $\text{CRC-32}(\text{raw\_payload\_stream}[4:])$, and verifies an exact match over the original serialized payload.

---

## 6. Ten-Round Feistel Permutation Specification

The permutation maps carrier indices deterministically onto available carrier channels.

### 6.1 Domain Decomposition

- Let $M$ be the total carrier channel capacity ($H \times W \times 3$).
- Channels $0 \dots 455$ are reserved for the sequential 57-byte header.
- Payload channel universe: $M_{\text{payload}} = M - 456$.
- In Matrix (3,2), channels are grouped into 3-channel triplets:
  $$M_{\text{triplets}} = \lfloor M_{\text{payload}} / 3 \rfloor$$
- Full block length: $2k = 2 \times \lceil \frac{1}{2} \lceil \log_2 M_{\text{triplets}} \rceil \rceil$.
- Half-block length: $k = 2k / 2$.
- Table entries count: $2^k$.

### 6.2 Precomputed AES-256-CTR Round Tables

- **Round Count:** $r = 10$.
- **Table Size:** $2^k$ entries of `uint16` ($16 \text{ KiB}$ at $k = 13$, total $160 \text{ KiB}$).
- For each round $i \in \{0, \dots, 9\}$:
  1. Generate $2 \times 2^k$ bytes of keystream by encrypting an all-zero buffer under $\text{AES-256-CTR}(K_i, \text{IV}_i)$.
  2. Parse as little-endian unsigned 16-bit words.
  3. Mask each entry with $\text{mask} = (1 \ll k) - 1$:
     $$T_i[j] = W_i[j] \ \& \ ((1 \ll k) - 1) \quad \forall j \in \{0, \dots, 2^k - 1\}$$

### 6.3 Forward and Inverse Algorithms

```python
def feistel_forward_step(x: int, k: int, tables: list[list[int]]) -> int:
    L = x >> k
    R = x & ((1 << k) - 1)
    for i in range(10):
        L, R = R, L ^ tables[i][R]
    return (R << k) | L

def feistel_inverse_step(y: int, k: int, tables: list[list[int]]) -> int:
    R = y >> k
    L = y & ((1 << k) - 1)
    for i in range(9, -1, -1):
        L, R = R ^ tables[i][L], L
    return (L << k) | R
```

---

## 7. Cycle-Walking Behavior & Runtime Guard Policy

Cycle walking (Black & Rogaway, 2002) restricts the Feistel permutation from $\{0, \dots, 2^{2k}-1\}$ onto arbitrary carrier channel triplet domains $\{0, \dots, M_{\text{triplets}}-1\}$.

```python
MAX_CYCLE_WALK_ITERATIONS = 100

def permute_forward(slot_idx: int, M: int, k: int, tables: list[array.array]) -> int:
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
```

### 7.1 Formal Distinction: Mathematical Guarantees vs. Runtime Guards

The V6 implementation formally separates five distinct concepts regarding cycle-walking behavior:

1. **The Bijection Property:**
   A balanced Feistel network is inherently bijective on its native domain $\{0, \dots, 2^{2k}-1\}$. Every input maps to a unique output, guaranteeing zero collisions.
2. **Cycle-Walking Domain Restriction:**
   When candidate values $\ge M$ fall outside the carrier triplet count, the Feistel step is iteratively reapplied. Because the permutation is finite and bijective, candidate values traverse a closed permutation cycle and must re-enter $\{0, \dots, M-1\}$ with probability 1. The resulting restricted mapping is a provably strict bijection on $\{0, \dots, M-1\}$.
3. **The Runtime Iteration Limit (`MAX_CYCLE_WALK_ITERATIONS = 100`):**
   The setting `MAX_CYCLE_WALK_ITERATIONS = 100` is an **operational runtime guard**, NOT a mathematical guarantee that all inputs terminate within 100 iterations. While the expected number of iterations per walk is $\frac{2^{2k}}{M} < 2$ (since $2^{2k-1} < M \le 2^{2k}$), worst-case paths on rare permutations could theoretically exceed 100 iterations. The 100-iteration ceiling bounds execution latency and prevents denial-of-service on pathological inputs.
4. **Retry Behavior During Embedding:**
   If cycle walking exceeds 100 iterations on any slot during embedding, the embedder catches `CycleWalkingExceededError`, draws a fresh 16-byte random salt (`os.urandom(16)`), discards the partially modified carrier copy, and retries embedding from scratch up to `MAX_CYCLE_WALK_RETRIES = 5` times.
5. **Extraction Failure Behavior If Guard Is Exceeded:**
   During extraction, the permutation is deterministically fixed by the salt stored in the 57-byte header. There is no alternative salt to retry. If any slot exceeds the 100-iteration cutoff during extraction, `CycleWalkingExceededError` is raised immediately, terminating the request safely rather than returning corrupt data or hanging server workers.

---

## 8. Matrix (3,2) Coset Embedding Specification

Matrix (3, 2) coset encoding embeds 2 message bits into 3 carrier channels with at most 1 bit modification.

### 8.1 Mathematical Foundation

- **Parity Check Matrix:**
  $$H = \begin{pmatrix} 1 & 0 & 1 \\ 0 & 1 & 1 \end{pmatrix}$$
- **Channel Triplet:** Let $(c_1, c_2, c_3)$ be the LSBs of the 3 carrier channels:
  $$c_i = \text{pixel\_byte}_i \ \& \ 1$$
- **Current Syndrome:**
  $$s = H \cdot \begin{pmatrix} c_1 \\ c_2 \\ c_3 \end{pmatrix} = \begin{pmatrix} c_1 \oplus c_3 \\ c_2 \oplus c_3 \end{pmatrix}$$
- **Message Bits to Embed:** $m = \begin{pmatrix} m_1 \\ m_2 \end{pmatrix} \in \{0, 1\}^2$.
- **Syndrome Difference:**
  $$d = m \oplus s = \begin{pmatrix} m_1 \oplus c_1 \oplus c_3 \\ m_2 \oplus c_2 \oplus c_3 \end{pmatrix}$$

### 8.2 Bit-Flip Coset Mapping

| Syndrome Difference $d$ | Error Vector $e = (e_1, e_2, e_3)$ | Channel to Flip | Flips |
| :---: | :---: | :---: | :---: |
| $(0, 0)^T$ | $(0, 0, 0)$ | None (Channels unchanged) | 0 |
| $(1, 0)^T$ | $(1, 0, 0)$ | Flip $c_1$ ($c_1' = c_1 \oplus 1$) | 1 |
| $(0, 1)^T$ | $(0, 1, 0)$ | Flip $c_2$ ($c_2' = c_2 \oplus 1$) | 1 |
| $(1, 1)^T$ | $(0, 0, 1)$ | Flip $c_3$ ($c_3' = c_3 \oplus 1$) | 1 |

Average bit flips per 2 bits: $\frac{0 + 1 + 1 + 1}{4} = 0.75$ flips ($0.375$ flips/bit).

**Exact Modification Reduction vs. Standard LSB:**
- In standard LSB replacement, each bit has a 50% chance of matching the carrier channel, requiring an average of $1.0$ bit flip per 2 bits embedded ($0.50$ flips/bit).
- In Matrix (3, 2) coset encoding, 2 bits are embedded into 3 channels with at most 1 bit flip, requiring an average of $0.75$ bit flips per 2 bits embedded ($0.375$ flips/bit).
- The relative reduction in carrier channel modifications is:
  $$\text{Reduction} = \frac{0.50 - 0.375}{0.50} = \frac{0.125}{0.50} = 25.00\%$$
*(Note: Earlier preliminary drafts incorrectly claimed 33% by dividing by 0.75 or 0.375; the true carrier modification reduction is strictly 25.00%).*

### 8.3 Channel Extraction

Given the modified channel triplet $(c_1', c_2', c_3')$:
$$m_1 = c_1' \oplus c_3'$$
$$m_2 = c_2' \oplus c_3'$$

---

## 9. Reed-Solomon Encoding and Decoding

### 9.1 Code Parameters

- **Code:** RS(255, 223) over $GF(2^8)$.
- **Symbol Size:** 8 bits (1 byte).
- **Primitive Polynomial:** $p(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`), standard in `reedsolo`.
- **Codeword Length:** $n = 255$ bytes.
- **Message Length:** $k = 223$ bytes.
- **Parity Overhead:** $2t = 32$ parity bytes per block.
- **Error Correction Radius:** $t = 16$ symbol errors per block.

### 9.2 Block Segmentation

Given the padded pre-RS stream of length $\text{pre\_rs\_len} = N \times 223$:
- Slice into $N$ blocks of 223 bytes: $M_0, M_1, \dots, M_{N-1}$.
- Encode each block:
  $$C_i = \text{RS\_Encode}(M_i) \quad \text{where } \text{len}(C_i) = 255$$

---

## 10. Dynamic Group-Size Interleaving

To prevent localized burst corruptions (e.g. image stamps, localized filtering) from destroying a single Reed-Solomon codeword, codewords are interleaved across superblocks.

### 10.1 Parameters

- **Interleaving Depth:** $K = 4$ (default).
- **Codeword Length:** $L = 255$ bytes.
- **Codeword Count:** $N$.

### 10.2 Forward Interleaving Algorithm

```python
def interleave_stream(codewords: list[bytes], K: int = 4) -> bytearray:
    N = len(codewords)
    interleaved = bytearray(N * 255)
    for g in range(0, N, K):
        k_curr = min(K, N - g)
        base = g * 255
        for j in range(255):
            for k in range(k_curr):
                interleaved[base + j * k_curr + k] = codewords[g + k][j]
    return interleaved
```

### 10.3 Inverse Deinterleaving Algorithm

```python
def deinterleave_stream(interleaved: bytes, N: int, K: int = 4) -> list[bytearray]:
    codewords = [bytearray(255) for _ in range(N)]
    for g in range(0, N, K):
        k_curr = min(K, N - g)
        base = g * 255
        for j in range(255):
            for k in range(k_curr):
                codewords[g + k][j] = interleaved[base + j * k_curr + k]
    return codewords
```

**Zero Padding Guarantee:** Both algorithms operate strictly over $N \times 255$ bytes. No zero-padding codewords are required when $N$ is not a multiple of $K$.

### 10.4 Burst Error Recovery Guarantees by Group Configuration

Each RS(255, 223) codeword can correct at most $t = 16$ symbol (byte) errors. Because Dynamic Group Interleaving divides $N$ codewords into superblocks of size $k_{\text{curr}} = \min(K, N - g)$, the maximum correctable contiguous burst of byte errors depends strictly on the group size $k_{\text{curr}}$:

$$\text{MaxBurst}(k_{\text{curr}}) = 16 \times k_{\text{curr}} \text{ bytes}$$

#### 10.4.1 Intra-Group Burst Bounds
1. **Complete $K = 4$ Superblock ($k_{\text{curr}} = 4$):**
   - Corrects up to **64 consecutive bytes**.
   - A 64-byte burst corrupts at most $\lceil 64 / 4 \rceil = 16$ bytes in any single codeword in the group.
   - A 65-byte burst corrupts $\lceil 65 / 4 \rceil = 17$ bytes in at least one codeword, causing uncorrectable decoding failure.
2. **Partial Superblock with 3 Codewords ($k_{\text{curr}} = 3$):**
   - Corrects up to **48 consecutive bytes** ($\lceil 48 / 3 \rceil = 16$ errors per codeword).
   - A 49-byte burst corrupts 17 bytes in at least one codeword and fails.
3. **Partial Superblock with 2 Codewords ($k_{\text{curr}} = 2$):**
   - Corrects up to **32 consecutive bytes** ($\lceil 32 / 2 \rceil = 16$ errors per codeword).
   - A 33-byte burst corrupts 17 bytes in at least one codeword and fails.
4. **Partial Superblock with 1 Codeword ($k_{\text{curr}} = 1$):**
   - Corrects up to **16 consecutive bytes** (equivalent to non-interleaved sequential transmission).
   - A 17-byte burst corrupts 17 bytes and fails.

#### 10.4.2 Bursts Crossing Superblock Boundaries
When a burst of length $B$ crosses the boundary between Group $A$ (size $k_A$) and Group $B$ (size $k_B$):
- Let $B_A$ be the number of bytes landing in Group $A$, and $B_B$ be the number of bytes landing in Group $B$ ($B = B_A + B_B$).
- Because Group $A$ and Group $B$ contain completely disjoint sets of codewords, both groups decode successfully if and only if:
  $$B_A \le 16 \times k_A \quad \text{and} \quad B_B \le 16 \times k_B$$
- **Cross-Group Behavior Examples:**
  - *Complete-to-Complete ($k_A = 4, k_B = 4$):* A burst spanning across the boundary can be up to $64 + 64 = 128$ bytes if centered on the boundary ($B_A \le 64$ and $B_B \le 64$).
  - *Complete-to-Partial ($k_A = 4, k_B = 1$):* Even if a burst is only 27 bytes long ($27 < 64$), if 10 bytes land in Group $A$ and 17 bytes land in Group $B$, Group $B$ will suffer 17 errors ($17 > 16$) and **fail**.
- **Important Qualification:** The 64-byte burst guarantee applies strictly to complete $K=4$ groups. It does **not** apply unconditionally to partial tail groups or arbitrary boundary crossings into partial groups. Tail partial groups have burst tolerance proportional to $16 \times k_{\text{curr}}$.

---

## 11. Capacity Calculation Formulations

Let an uncompressed carrier have height $H$ and width $W$.
1. **Total Channels:**
   $$M_{\text{total}} = H \times W \times 3$$
2. **Payload Available Channels:**
   $$M_{\text{payload}} = M_{\text{total}} - 456 \quad \text{(after reserving 456 channels for the 57-byte header)}$$
3. **Available Triplets:**
   $$M_{\text{triplets}} = \lfloor M_{\text{payload}} / 3 \rfloor$$
4. **Maximum Encoded Bits:**
   $$Bits_{\max} = M_{\text{triplets}} \times 2$$
5. **Maximum Encoded Bytes:**
   $$Bytes_{\max} = \lfloor Bits_{\max} / 8 \rfloor = \lfloor M_{\text{triplets}} / 4 \rfloor$$
6. **Maximum RS Blocks ($N_{\max}$):**
   $$N_{\max} = \lfloor Bytes_{\max} / 255 \rfloor$$
7. **Maximum Usable Pre-RS Capacity ($C_{\max}$):**
   $$C_{\max} = N_{\max} \times 223 \text{ bytes}$$

---

## 12. Complete Lifecycle Sequence

### 12.1 Embedding Lifecycle

1. **Ingress Validation:** Inspect carrier image. Ensure dimensions do not exceed deployment limits. Ensure carrier has at least 3 channels.
2. **Payload Preparation:** Compress payload with zlib (level 9) if advantageous. Construct JSON metadata.
3. **Stream Framing:**
   - If Encrypted Mode: Encrypt via Fernet with key derived via PBKDF2 ($600,000$ iterations). Decode base64 to binary token.
   - If Plain Mode: Prepend 4-byte CRC-32 checksum.
4. **Padding & RS Encoding:** Pad stream to multiple of 223 bytes. Segment into $N$ blocks of 223 bytes. Compute RS(255, 223) parity for each block.
5. **Interleaving:** Interleave $N \times 255$ bytes using Dynamic Group Interleaving ($K=4$).
6. **Header Assembly:** Assemble 25-byte header body (`magic`, `mode`, `interleave_k`, `reserved`, `salt`, `raw_payload_len`). Compute 32-byte `auth_tag`. Pack 57-byte header.
7. **Header Embedding:** Embed 57 bytes (456 bits) into carrier channels $0 \dots 455$ via LSB replacement.
8. **Permutation Setup:** Derive $K_{\text{perm\_root}}$ and precompute 10 Feistel round tables.
9. **Matrix (3,2) Payload Embedding:**
   - For each 2-bit symbol of the interleaved stream:
     - Compute triplet slot index using Feistel forward permutation and cycle walking.
     - Calculate absolute channel indices: $\text{ch}_1 = 456 + 3 \times \text{slot}$, $\text{ch}_2 = \text{ch}_1 + 1$, $\text{ch}_3 = \text{ch}_1 + 2$.
     - Apply Matrix (3,2) coset encoding to channels $(\text{ch}_1, \text{ch}_2, \text{ch}_3)$.
10. **Save Image:** Output stego-carrier as lossless PNG.

### 12.2 Extraction Lifecycle

1. **Header Extraction:** Read LSBs from carrier channels $0 \dots 455$. Reassemble 57 bytes.
2. **Magic & Header Parsing:** Validate magic bytes (`0xFF 0x06`). Extract `mode`, `interleave_k`, `salt`, `raw_payload_len`, and `auth_tag`.
3. **Downgrade & Authentication Check:**
   - If `password is not None` and `mode == 0x40`: raise `DowngradeAttackError`.
   - If `expected_mode == "encrypted"` and `mode == 0x40`: raise `DowngradeAttackError`.
   - If `mode == 0x41`: Verify `auth_tag == HMAC-SHA256(K_auth, body)`. On mismatch, raise `HeaderAuthenticationError`.
   - If `mode == 0x40`: Verify `auth_tag == SHA-256(body)`. On mismatch, raise `HeaderIntegrityError`.
4. **Permutation Setup:** Derive $K_{\text{perm\_root}}$ using password (Encrypted) or public seed (Plain). Precompute 10 Feistel round tables.
5. **Matrix (3,2) Extraction:**
   - Derive RS codeword count: $N = (raw\_payload\_len + 222) // 223$.
   - Total interleaved bytes: $N \times 255$.
   - For each 2-bit symbol:
     - Compute triplet slot index using Feistel forward permutation and cycle walking.
     - Extract 2 bits from channel triplet LSBs.
   - Reassemble $N \times 255$ interleaved bytes.
6. **Deinterleaving:** Run Dynamic Group Deinterleaving ($K=4$) to recover $N$ codewords of 255 bytes.
7. **Reed-Solomon Decoding:** Decode each codeword with RS(255, 223). Errors $\le 16$ bytes per block are repaired. Recover $N \times 223$ pre-RS bytes.
8. **Payload Reconstruction & Trimming:**
   - Deterministically slice the recovered pre-RS stream to the exact original length:
     $$\text{raw\_payload\_stream} = \text{recovered\_pre\_rs}[:raw\_payload\_len]$$
   - If Encrypted Mode: Encode binary Fernet token to base64, decrypt via Fernet. Extract framed metadata and compressed payload.
   - If Plain Mode: Verify 4-byte CRC-32 checksum ($\text{CRC-32}(\text{raw\_payload\_stream}[4:]) == \text{raw\_payload\_stream}[:4]$). Extract framed metadata and compressed payload.
9. **Decompression & Output:** Decompress with zlib if metadata specifies `"compressed": true`. Return extracted file and metadata dictionary.

---

## 13. Error Handling and Exceptions

V6 defines explicit, typed exceptions:

```python
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
    """Raised when uncorrectable noise (>16 bytes/block) corrupts a codeword."""

class ChecksumMismatchError(V6SteganographyError):
    """Raised when plain mode CRC-32 checksum fails."""
```

---

## 14. Compatibility and Version Isolation

- **Protocol Flag:** V6 uses wire format `0x40` (Plain) and `0x41` (Encrypted).
- **Orthogonality:** V6 flags are completely distinct from legacy versions:
  - `0x00`: Legacy v1 Plain
  - `0x01`: Legacy v1 AES-256-CBC
  - `0x02`: Legacy v2 Fernet
  - `0x20` / `0x21`: Legacy v3 2-bit LSB
  - `0x30` / `0x31`: Legacy v5 RS(255, 223)
- **Module Isolation:**
  - V6 logic must reside exclusively in:
    `backend/utils/steganography_v6.py`
  - The existing module `backend/utils/steganography.py` remains the active production engine for v1–v5 and must not be modified during initial V6 implementation.

---

## 15. Deterministic Test-Vector Requirements

To verify the isolated implementation, unit and integration tests must validate:

1. **Key Derivation Vector:**
   - Password: `b"InvisioVault-V6-Test-Password"`
   - Salt: `b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"`
   - Verified outputs: $K_{\text{master}}$, $K_{\text{auth}}$, $K_{\text{enc}}$, $K_{\text{perm\_root}}$.
2. **Feistel Round Table Generation Vector:**
   - Seed: Fixed $K_{\text{perm\_root}}$.
   - Verify table values for $i = 0 \dots 9$, entries $0, 1, 2, 8191$.
3. **Feistel Invertibility Vector:**
   - For all $x \in \{0, \dots, 2^{2k}-1\}$, verify $E_K^{-1}(E_K(x)) == x$.
4. **Cycle Walking Bijectivity Vector:**
   - For $M \in \{5, 17, 100, 1000\}$, verify that cycle walking produces a strict permutation on $\{0, \dots, M-1\}$ with zero duplicates and zero missing values.
5. **Matrix (3, 2) Syndrome Vector:**
   - Test all 64 combinations of $(c_1, c_2, c_3)$ and $(m_1, m_2)$. Verify at most 1 bit is flipped and extracted message matches exactly.
6. **Reed-Solomon Burst Recovery Vector:**
   - Test burst errors up to 64 consecutive bytes with $K=4$; verify 100% recovery.
7. **End-to-End Roundtrip Vector:**
   - Embed and extract both small text payloads and 64 KiB binary files in plain and encrypted modes.

---

## 16. Implementation Sign-Off

```text
================================================================================
SPECIFICATION FREEZE COMPLETE
STATUS: RATIFIED & AUTHORIZED
TARGET MODULE: backend/utils/steganography_v6.py
================================================================================
```

