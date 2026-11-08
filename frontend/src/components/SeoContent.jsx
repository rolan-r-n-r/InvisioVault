import { useState } from 'react'
import { ShieldCheck, Lock, EyeOff, Layers, QrCode, Cpu, AlertTriangle, ChevronDown, ChevronUp, FileCode, CheckCircle2 } from 'lucide-react'
import './SeoContent.css'

const FAQ_ITEMS = [
  {
    q: 'What is InvisioVault?',
    a: 'InvisioVault is an open-source, privacy-first cryptographic application that enables hiding confidential files and messages inside ordinary carriers like images, PDFs, videos, or QR codes using V6 Matrix steganography, universal polyglots, and stealth QR barcodes.'
  },
  {
    q: 'Can I hide any file type inside any format?',
    a: "Yes. InvisioVault's Universal Polyglot feature allows any file (ZIP archives, documents, executables) to be concatenated and offset-patched into any carrier (images, audio, PDF, video) while remaining completely functional in standard viewers."
  },
  {
    q: 'How are files protected inside InvisioVault?',
    a: 'In V6 Encrypted Mode, user passwords derive keys via PBKDF2-HMAC-SHA256 with 600,000 iterations and two-tier HKDF-SHA256 subkey separation. Payloads are encrypted using Fernet (AES-128-CBC + HMAC-SHA256) and protected by a 57-byte authenticated header. In Plain Mode, payloads are verified with CRC-32 checksums and SHA-256 integrity tags without passwords. Legacy carriers (V1–V5) are automatically decrypted upon extraction.'
  },
  {
    q: 'Do I need to select which engine was used to extract my carrier?',
    a: "No. InvisioVault's extraction pipeline automatically inspects carrier headers and detects whether the image was created using the advanced V6 engine or any legacy version (V1–V5), extracting the payload seamlessly without manual configuration."
  },
  {
    q: 'Does InvisioVault store my files on the server?',
    a: 'No. InvisioVault operates a strict zero-retention, stateless policy. Uploaded files and processing buffers are automatically erased immediately upon download or request completion.'
  },
  {
    q: 'Will hidden data survive if I share images on WhatsApp, Twitter, or Discord?',
    a: 'No. Social media and messaging platforms aggressively recompress images to lossy JPEG or WebP, destroying least-significant bit information. To preserve steganographic payloads, always send carrier images as uncompressed raw files or documents.'
  }
]

export default function SeoContent() {
  const [openFaq, setOpenFaq] = useState(null)

  const toggleFaq = (index) => {
    setOpenFaq(openFaq === index ? null : index)
  }

  return (
    <section className="seo-content" aria-label="Technical Documentation and Frequently Asked Questions">
      {/* Educational Architecture Grid */}
      <div className="seo-header">
        <h2 className="seo-main-title">Engineering Covert Communication &amp; Cryptography</h2>
        <p className="seo-main-subtitle">
          InvisioVault bridges low-level binary format manipulation with modern authenticated cryptography.
        </p>
      </div>

      <div className="seo-cards-grid">
        <article className="seo-card">
          <div className="seo-card-icon">
            <Cpu size={24} />
          </div>
          <h3>V6 Matrix Coset Steganography</h3>
          <p>
            InvisioVault's primary V6 engine implements <strong>Matrix (3,2) coset syndrome coding</strong>, embedding 2 payload bits into 3 carrier channels with at most 1 bit modification (average 0.375 flips/bit) — reducing carrier alterations by 25% compared to standard LSB replacement. Channels are permuted via an in-memory <strong>10-round Feistel network</strong> with cycle walking and protected by <strong>interleaved Reed-Solomon RS(255, 223)</strong>.
          </p>
          <div className="seo-card-tag">Matrix (3,2) · Feistel · RS(255, 223) ECC</div>
        </article>

        <article className="seo-card">
          <div className="seo-card-icon">
            <Layers size={24} />
          </div>
          <h3>Universal Polyglot Engineering</h3>
          <p>
            A polyglot file satisfies two distinct file format parsers simultaneously. Image and media readers parse metadata from byte 0, whereas ZIP archive decoders seek backward from the <strong>End of Central Directory (EOCD)</strong>. InvisioVault uses zero-copy <code>mmap</code> binary offset patching to rewrite internal ZIP relative pointers, producing seamless dual-format files.
          </p>
          <div className="seo-card-tag">In-Memory Offset Recalculation</div>
        </article>

        <article className="seo-card">
          <div className="seo-card-icon">
            <QrCode size={24} />
          </div>
          <h3>Stealth QR Code Steganography</h3>
          <p>
            Standard phone camera scanners see an ordinary, benign URL. By embedding encrypted secrets directly into non-structural QR data modules via <strong>Visual Module Steganography</strong>, the public URL remains 100% clean with zero steganographic trace. InvisioVault also retains backward-compatible scanning for legacy URL fragments (<code>#IVDATA:</code>).
          </p>
          <div className="seo-card-tag">Visual Module Structural Isolation</div>
        </article>
      </div>

      {/* Carrier Degradation Warning Callout */}
      <div className="carrier-warning-banner" role="alert">
        <div className="warning-icon-wrapper">
          <AlertTriangle size={24} />
        </div>
        <div className="warning-text">
          <h4>Carrier Degradation Notice for Social Media</h4>
          <p>
            Lossy image recompression algorithms (used by WhatsApp, Twitter/X, Discord, and Instagram) permanently destroy least-significant bit information.
            To preserve steganographic payloads, <strong>always transmit carrier files as uncompressed documents or raw files</strong>.
          </p>
        </div>
      </div>

      {/* Supported Carrier Matrix */}
      <div className="spec-table-container">
        <h3 className="spec-table-title">Carrier Format &amp; Cryptographic Specifications</h3>
        <div className="table-responsive">
          <table className="spec-table">
            <thead>
              <tr>
                <th scope="col">Carrier Format</th>
                <th scope="col">Hiding Mechanism</th>
                <th scope="col">Cipher / MAC</th>
                <th scope="col">Key Derivation</th>
                <th scope="col">Max Payload</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>PNG, BMP</strong> (Lossless)</td>
                <td>V6 Matrix (3,2) Coset Embedding + 10-Round Feistel (V1–V5 Legacy Supported)</td>
                <td>Fernet (AES-128-CBC) + HMAC-SHA256 / Plain CRC-32 + SHA-256</td>
                <td>PBKDF2-HMAC-SHA256 (600,000 iter) + HKDF-SHA256</td>
                <td>2 bits / triplet (up to ~20–25% of carrier with K=4 ECC)</td>
              </tr>
              <tr>
                <td><strong>PDF, MP4, MP3, JPG</strong></td>
                <td>Polyglot EOCD Offset Patching</td>
                <td>AES-256 (Optional ZIP encryption)</td>
                <td>PBKDF2-HMAC-SHA256</td>
                <td>Up to 50 MB</td>
              </tr>
              <tr>
                <td><strong>QR Barcode</strong></td>
                <td>Visual Module Masking / Legacy Fragment</td>
                <td>Fernet (AES-128-CBC + HMAC-SHA256)</td>
                <td>PBKDF2 (480,000 iter)</td>
                <td>Up to 2,953 bytes (Version 40-L)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Accessible FAQ Accordion */}
      <div className="faq-container">
        <h3 className="faq-section-title">Frequently Asked Questions</h3>
        <div className="faq-list">
          {FAQ_ITEMS.map((item, idx) => {
            const isOpen = openFaq === idx
            return (
              <div key={idx} className={`faq-item ${isOpen ? 'open' : ''}`}>
                <button
                  className="faq-question-btn"
                  onClick={() => toggleFaq(idx)}
                  aria-expanded={isOpen}
                  aria-controls={`faq-answer-${idx}`}
                  id={`faq-btn-${idx}`}
                >
                  <span>{item.q}</span>
                  {isOpen ? <ChevronUp size={18} aria-hidden="true" /> : <ChevronDown size={18} aria-hidden="true" />}
                </button>
                <div
                  id={`faq-answer-${idx}`}
                  className="faq-answer-panel"
                  role="region"
                  aria-labelledby={`faq-btn-${idx}`}
                  hidden={!isOpen}
                >
                  <p>{item.a}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Transparency & Security Links */}
      <div className="seo-footer-links">
        <p>
          <ShieldCheck size={16} className="inline-icon" /> <strong>Zero Retention:</strong> Files are processed statelessly in memory and purged immediately post-download.
        </p>
        <div className="links-group">
          <a href="https://github.com/rolan-r-n-r/InvisioVault" target="_blank" rel="noopener noreferrer">
            <FileCode size={14} className="inline-icon" /> View Source on GitHub
          </a>
        </div>
      </div>
    </section>
  )
}
