# QR Steganography Test Fixtures

**Synthetic fixtures only.** Never commit a real capture: a real capture contains
the hidden secret and the public URL, and the debug frames under
`backend/uploads/debug/` are git-ignored for that reason.

This directory is the measurement input for the QR steganography redesign
(implementation plan Phase 0). It exists so every change is judged against
the same images instead of hand-picked screenshots.

## Layout and Committed Artifacts

| Path | Contents | Status |
|---|---|---|
| `manifest.json` | Every fixture: render parameters, degradation, observed version, recorded outcome, image SHA-256. | Committed |
| `fixture_png_sha256.json` | Authoritative SHA-256 digests for all 8 base PNG renders. | Committed |
| `png/*.png` | Base renders produced by the legacy encoder (8 images). | Committed |
| `backend/tests/qr_baseline.json` | Historical Phase 0 recorded success/BER/timing (101/112). Historical reference. | Committed |
| `backend/tests/qr_reference_phase3.json` | Current Phase 1–3 verified reference matrix (101/112). Pre-Phase-4 reference. | Committed |
| `backend/tests/qr_harness.py` | Rendering, degradation, extraction, BER probe, hash verification, statistics. | Committed (test-only) |
| `backend/tests/fixtures/*.png` | Legacy IVQR v1 fixtures (`v1_clean`, `v2_clean`, `v4_clean`, `v4_plain`, `base_carrier`). | Committed (repo HEAD) |

Degraded variants are derived from the committed base renders at test time, so
one PNG per payload/password/scale combination covers the whole matrix.

## Fixture Matrix

8 renders × 14 degradation profiles = 112 fixtures.

Renders (payload sizes are UTF-8 byte counts):

| Render | Payload | Password | Scale | Encrypted | Deterministic Regen |
|---|---|---:|---:|:---:|:---:|
| `small_plain_s20` | 9 B ASCII | no | 20 | No | Yes |
| `small_sealed_s20` | 9 B ASCII | yes | 20 | Yes (Fernet) | No (Random IV/Salt) |
| `medium_plain_s20` | 300 B | no | 20 | No | Yes |
| `medium_sealed_s20` | 300 B | yes | 20 | Yes (Fernet) | No (Random IV/Salt) |
| `large_plain_s20` | 696 B | no | 20 | No | Yes |
| `large_sealed_s20` | 696 B | yes | 20 | Yes (Fernet) | No (Random IV/Salt) |
| `medium_sealed_s10` | 300 B | yes | 10 | Yes (Fernet) | No (Random IV/Salt) |
| `small_plain_s10` | 9 B ASCII | no | 10 | No | Yes |

`medium`/`large` payloads are pseudo-random CJK text (3 UTF-8 bytes per code
point, near incompressible) so capacity is exercised at its worst case. `small`
is realistic short ASCII.

Degradation profiles: `clean`, `ppm10`, `ppm8`, `ppm7`, `ppm6`, `ppm5`, `ppm4`,
`ppm3`, `ppm8_blur05`, `ppm8_exposure120`, `ppm8_jpeg80`, `ppm8_rot5`,
`ppm8_persp03`, and `frontend_ppm4`.

Resampled profiles add deterministic Gaussian sensor noise (σ2, or σ3 at 3 ppm).
Without it the matrix scored BER 0 and 100% success at every resolution, which
cannot discriminate a good implementation from a bad one.

`frontend_ppm4` reproduces the historical client capture path: nearest-neighbour
upscale to a 450 px minimum only when a crop dimension is below 450, and 1 px
Gaussian blur only in that same small-crop branch. (Note: current frontend
capture sends native resolution without smoothing; `frontend_ppm4` tests
historical client resilience).

### Calibration Against Real Captures

Parameters are calibrated against 87 real camera captures of the shipped app
(git-ignored debug frames; no capture is committed). Measured payload-stage
recovery for v11 codes:

| px/module | captures | payload recovered |
|---|---:|---:|
| 3 | 13 | 62% |
| 4 | 18 | 83% |
| 5 | 14 | 100% |
| 6-10 | 39 | 100% |

The real failure band is **3-4 px/module**, not 6.

### Train / Held-Out Split

`ppm7`, `ppm5`, and `ppm8_exposure120` are marked `"split": "heldout"`. They must
not be used to tune modulation deltas, thresholds, or FEC parameters. Tuning uses
the `train` fixtures; the held-out set is measured only for release evidence.

### Fast Subset

The default pytest run evaluates 20 fixtures (all `clean` + all `ppm8`, plus
`ppm4` for four renders). It is a smoke test. **It is not release evidence** — a
95% cell needs ≥73 samples and a 99% cell ≥381 (see
`QR_STEGANOGRAPHY_TEST_PLAN.md` §12.1; helpers are in `qr_harness.py`).

## How to Read `ber`

`ber` is the **channel** bit-error rate: module interiors are sampled in exact
module space and classified per polarity. It deliberately excludes geometry, so:

* `ber` high → the modulation did not survive (optical SNR problem).
* `ber` low **and** `outcome != success` → the bits were present but the
  extractor failed to *find/rectify* the symbol (geometry problem).
* `ber_coverage < 1.0` → a polarity class collapsed and only part of the carrier
  was scored; never compare a low-coverage BER with a full one.

## Fernet Randomness and Fixture Determinism

* **Plain renders (`*_plain_*`) are deterministic**: Generating a plain QR code
  without a password produces byte-identical output across runs.
* **Sealed renders (`*_sealed_*`) are NOT byte-identical across runs**: Fernet
  encryption (`cryptography.fernet.Fernet`) generates a fresh, cryptographically
  random 128-bit salt and 128-bit initialization vector (IV) for every token.
  The ciphertext bytes differ on every execution, changing the carrier bitstream
  and image pixels.
* **Reproducibility Criterion**: Generated sealed PNG byte equality is NOT a valid
  test criterion. Instead:
  1. The 8 base PNG fixtures are permanently committed to git.
  2. Their SHA-256 digests are pinned in `fixture_png_sha256.json`.
  3. Extraction reproducibility is tested against these exact persisted images.
  4. Regeneration (`qr_harness build --force`) is decoupled from test verification.

## Baseline Separation: Historical Phase 0 vs. Current Phase 1–3 Reference

Two separate baseline files are tracked in the repository:

1. **`backend/tests/qr_baseline.json` (Historical Phase 0 Baseline)**:
   - Generated: 2026-11-03 against an uncommitted working tree state.
   - Success count: 101/112.
   - Known limitation: contains decoder diagnostics that did not exist at HEAD `1ab554a`.
   - Preserved unchanged as a historical artifact.

2. **`backend/tests/qr_reference_phase3.json` (Current Phase 1–3 Reference)**:
   - Generated: 2026-11-04 from the consolidated Phase 1–3 implementation.
   - Success count: 101/112.
   - Authoritative reference for future decoder experiments (Phase 4).

### The Known One-Cell Classification Drift

Across all 112 fixtures, exactly one cell exhibits a different classification
between the historical baseline and the current reference:

* **Fixture**: `small_sealed_s20__ppm8_persp03`
* **Historical Baseline**: `outcome: no_magic`, `stage: OPTICAL_SENSOR_SATURATION`, `error_code: null`
* **Current Reference**: `outcome: payload_fail`, `stage: PAYLOAD_DECODE_FAILED`, `error_code: HIDDEN_PAYLOAD_CORRUPTED`

**Technical Explanation**:
- Both outcomes are failures; the total success count remains unchanged (101/112).
- The current decoder includes Phase 2 header synchronization and structural grid
  alignment. Under perspective distortion (`ppm8_persp03`), it correctly recovers
  the QR version and header (detecting that a hidden payload is present), but fails
  at the payload Reed-Solomon decode stage.
- The historical decoder failed earlier at optical detection, incorrectly reporting
  "no hidden data" (`no_magic`).
- The current classification (`PAYLOAD_DECODE_FAILED`) is more accurate. It is not
  a success-rate regression.
- The historical baseline is preserved as-is; it is not modified to hide the drift.

## Running Tests and Verification

```bash
cd backend

# Fast regression suite (default, 26 tests, < 20s):
.\.venv\Scripts\python.exe -m pytest tests/test_qr_regression.py

# Full regression matrix (all 112 fixtures, ~80s):
.\.venv\Scripts\python.exe -m pytest tests/test_qr_regression.py -m slow

# Full backend test suite (203+ tests):
.\.venv\Scripts\python.exe -m pytest

# Verify fixture SHA-256 hashes against pinned manifest:
.\.venv\Scripts\python.exe -m tests.qr_harness verify

# Print historical baseline report:
.\.venv\Scripts\python.exe -m tests.qr_harness report

# Print current Phase 1-3 reference report:
.\.venv\Scripts\python.exe -m tests.qr_harness report --reference
```

## Rebuilding Fixtures

```bash
cd backend

# Re-evaluate matrix against existing committed PNGs:
.\.venv\Scripts\python.exe -m tests.qr_harness build

# Force re-render base PNGs (WARNING: will re-encrypt sealed images with new Fernet salt/IV):
.\.venv\Scripts\python.exe -m tests.qr_harness build --force
```

`--force` invalidates pinned hashes for sealed fixtures. Only run `--force` when an
intentional encoder redesign requires new base images, and re-record hashes in the same commit.
