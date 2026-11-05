import PixelShield from './PixelShield';
import './AmbientBrandIdentity.css';

/**
 * Editorial Brand Identity Component
 * 
 * Occupies the right-side negative space with:
 * 1. An animated monochromatic pixel-art shield
 * 2. An editorial display headline: "HIDDEN IN PLAIN SIGHT."
 * 3. Understated supporting statement: "Privacy isn't just a feature. It's the foundation."
 * 4. Micro-scale cryptographic metadata hairline
 */
export default function AmbientBrandIdentity({ pointerRef }) {
  return (
    <div className="ambient-brand-identity" role="region" aria-label="Brand Philosophy">
      {/* 1. Animated Monochromatic Pixel-Art Shield */}
      <div className="shield-emblem-container">
        <PixelShield pointerRef={pointerRef} />
      </div>

      {/* 2. Cryptographic Protocol Metadata Hairline */}
      <div className="editorial-meta" aria-hidden="true">
        <span className="editorial-meta-line" />
        <span className="editorial-meta-tag">INVISIOVAULT PROTOCOL</span>
      </div>

      {/* 3. Primary Display Typography */}
      <h2 className="editorial-headline">
        Hidden in<br />plain sight.
      </h2>

      {/* 4. Understated Supporting Text */}
      <p className="editorial-supporting">
        Privacy isn't just a feature.<br />
        It's the foundation.
      </p>

      {/* 5. Delicate Micro-Pixel Identity Accents */}
      <div className="editorial-accents" aria-hidden="true">
        <span className="micro-pixel active" />
        <span className="micro-pixel" />
        <span className="micro-pixel" />
        <span className="micro-hash">SHA-256 / EOCD / LSB</span>
      </div>
    </div>
  );
}

