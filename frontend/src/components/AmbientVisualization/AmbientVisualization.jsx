import { useEffect, useRef } from 'react';
import EarthVisualization from './EarthVisualization';
import AmbientBrandIdentity from '../AmbientBrandIdentity/AmbientBrandIdentity';
import './AmbientVisualization.css';

export default function AmbientVisualization({ mode = 'stego' }) {
  // Shared pointer state for subtle cursor parallax
  const pointerRef = useRef({
    clientX: -9999,
    clientY: -9999,
    normX: 0,
    normY: 0,
    active: false,
  });

  useEffect(() => {
    const handlePointerMove = (e) => {
      pointerRef.current.clientX = e.clientX;
      pointerRef.current.clientY = e.clientY;
      pointerRef.current.normX = (e.clientX / window.innerWidth) * 2 - 1;
      pointerRef.current.normY = -(e.clientY / window.innerHeight) * 2 + 1;
      pointerRef.current.active = true;
    };

    const handlePointerLeave = () => {
      pointerRef.current.active = false;
      pointerRef.current.normX = 0;
      pointerRef.current.normY = 0;
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    window.addEventListener('pointerleave', handlePointerLeave, { passive: true });

    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerleave', handlePointerLeave);
    };
  }, []);

  return (
    <div
      className="ambient-visualization-root"
      aria-hidden="true"
      role="presentation"
    >
      {/* LEFT GUTTER: Prominent Hero Interactive Pixelated Earth */}
      <aside className="ambient-gutter-left">
        <div className="earth-wrapper">
          <EarthVisualization mode={mode} pointerRef={pointerRef} />
        </div>
      </aside>

      {/* RIGHT GUTTER: Editorial Typography & Pixel-Art Shield Brand Identity */}
      <aside className="ambient-gutter-right">
        <div className="brand-identity-wrapper">
          <AmbientBrandIdentity pointerRef={pointerRef} />
        </div>
      </aside>
    </div>
  );
}
