import { useEffect, useRef } from 'react';

/**
 * PixelArt Shield Matrix (16 cols x 18 rows)
 * 0: Empty
 * 1: Pure White (#FFFFFF) - Outer protective rim & central spine
 * 2: Light Silver (#E5E5E5) - Light-facing left facet
 * 3: Muted Silver (#A3A3A3) - Shaded right facet
 */
const SHIELD_MAP = [
  [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0], // Row 0
  [0, 0, 1, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 1, 0, 0], // Row 1
  [0, 1, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 1, 0], // Row 2
  [0, 1, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 1, 0], // Row 3
  [1, 2, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 3, 1], // Row 4
  [1, 2, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 3, 1], // Row 5
  [1, 2, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 3, 1], // Row 6
  [1, 2, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 3, 1], // Row 7
  [1, 2, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 3, 1], // Row 8
  [0, 1, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 1, 0], // Row 9
  [0, 1, 2, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 3, 1, 0], // Row 10
  [0, 0, 1, 2, 2, 2, 2, 1, 1, 3, 3, 3, 3, 1, 0, 0], // Row 11
  [0, 0, 1, 2, 2, 2, 1, 1, 1, 1, 3, 3, 3, 1, 0, 0], // Row 12
  [0, 0, 0, 1, 2, 2, 1, 1, 1, 1, 3, 3, 1, 0, 0, 0], // Row 13
  [0, 0, 0, 0, 1, 2, 1, 1, 1, 1, 3, 1, 0, 0, 0, 0], // Row 14
  [0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0], // Row 15
  [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0], // Row 16
  [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0], // Row 17
];

const COLOR_MAP = {
  1: '#FFFFFF', // Pure White
  2: '#D4D4D4', // Light Silver
  3: '#8E8E8E', // Muted Silver Shadow
};

export default function PixelShield({ pointerRef }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Physical pixel grid layout
    const COLS = 16;
    const ROWS = 18;
    const PIXEL_SIZE = 3.2; // Size of each individual square pixel
    const GAP = 0.8; // Gap between pixels
    const PITCH = PIXEL_SIZE + GAP;

    const totalWidth = COLS * PITCH;
    const totalHeight = ROWS * PITCH;

    // HiDPI canvas backing
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.ceil(totalWidth * dpr);
    canvas.height = Math.ceil(totalHeight * dpr);
    canvas.style.width = `${totalWidth}px`;
    canvas.style.height = `${totalHeight}px`;
    ctx.scale(dpr, dpr);

    // Build pixel objects with deterministic procedural assembly paths
    const pixels = [];
    let pixelIndex = 0;

    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const val = SHIELD_MAP[r][c];
        if (val === 0) continue;

        // Target assembled coordinates
        const targetX = c * PITCH;
        const targetY = r * PITCH;

        // Initial scatter offset for assembly phase
        const angle = (pixelIndex * 137.5 * Math.PI) / 180;
        const distance = 8 + (pixelIndex % 5) * 2.5;
        const scatterX = Math.cos(angle) * distance;
        const scatterY = Math.sin(angle) * distance;

        // Determine if this pixel belongs to the subtle detachment set
        const isDetaching =
          (r === 4 && (c === 0 || c === 15)) ||
          (r === 8 && (c === 0 || c === 15)) ||
          (r === 0 && (c === 3 || c === 12)) ||
          (r === 17 && (c === 7 || c === 8));

        const detachAngle = isDetaching ? angle : 0;
        const detachDist = isDetaching ? 3.0 + (pixelIndex % 3) * 1.0 : 0;

        pixels.push({
          targetX,
          targetY,
          scatterX,
          scatterY,
          isDetaching,
          detachOffsetX: Math.cos(detachAngle) * detachDist,
          detachOffsetY: Math.sin(detachAngle) * detachDist,
          color: COLOR_MAP[val],
          baseAlpha: val === 1 ? 0.95 : val === 2 ? 0.82 : 0.65,
          delay: (pixelIndex % 7) * 0.08,
        });

        pixelIndex++;
      }
    }

    let animationFrameId;
    const startTime = performance.now();
    const CYCLE_DURATION = 11.0; // 11 seconds meditative loop

    const render = (now) => {
      ctx.clearRect(0, 0, totalWidth, totalHeight);

      if (prefersReducedMotion) {
        // Static, perfectly assembled shield
        pixels.forEach((p) => {
          ctx.fillStyle = p.color;
          ctx.globalAlpha = p.baseAlpha;
          ctx.fillRect(p.targetX, p.targetY, PIXEL_SIZE, PIXEL_SIZE);
        });
        return;
      }

      const elapsed = ((now || performance.now()) - startTime) * 0.001;
      const cycleTime = elapsed % CYCLE_DURATION;

      // Pointer parallax influence
      let parallaxX = 0;
      let parallaxY = 0;
      if (pointerRef && pointerRef.current && pointerRef.current.active) {
        parallaxX = pointerRef.current.normX * 1.5;
        parallaxY = pointerRef.current.normY * 1.2;
      }

      // Phase Timing:
      // [0.0s - 1.6s]: Assemble into shield
      // [1.6s - 5.5s]: Steady assembled hold (micro-breathing)
      // [5.5s - 7.5s]: Subtle detachment of select perimeter pixels
      // [7.5s - 9.0s]: Gentle return to home slots
      // [9.0s - 11.0s]: Resting assembled state
      pixels.forEach((p) => {
        let curX = p.targetX;
        let curY = p.targetY;
        let curAlpha = p.baseAlpha;

        if (cycleTime < 1.6) {
          // Assemble
          const t = Math.max(0, Math.min(1, (cycleTime - p.delay) / 1.0));
          const easeOut = 1 - Math.pow(1 - t, 3);
          curX = p.targetX + p.scatterX * (1 - easeOut);
          curY = p.targetY + p.scatterY * (1 - easeOut);
          curAlpha = p.baseAlpha * easeOut;
        } else if (cycleTime >= 1.6 && cycleTime < 5.5) {
          // Stable hold with micro shimmer
          const breath = 1.0 + 0.05 * Math.sin(cycleTime * 1.5 + p.delay * 5);
          curAlpha = Math.min(1.0, p.baseAlpha * breath);
        } else if (cycleTime >= 5.5 && cycleTime < 7.5) {
          // Gentle detachment
          if (p.isDetaching) {
            const t = (cycleTime - 5.5) / 2.0;
            const ease = Math.sin((t * Math.PI) / 2);
            curX = p.targetX + p.detachOffsetX * ease;
            curY = p.targetY + p.detachOffsetY * ease;
            curAlpha = Math.min(1.0, p.baseAlpha + 0.25 * ease);
          }
        } else if (cycleTime >= 7.5 && cycleTime < 9.0) {
          // Smooth return
          if (p.isDetaching) {
            const t = (cycleTime - 7.5) / 1.5;
            const ease = 1 - Math.pow(1 - t, 2);
            curX = p.targetX + p.detachOffsetX * (1 - ease);
            curY = p.targetY + p.detachOffsetY * (1 - ease);
            curAlpha = p.baseAlpha;
          }
        }

        ctx.fillStyle = p.color;
        ctx.globalAlpha = curAlpha;
        ctx.fillRect(curX + parallaxX, curY + parallaxY, PIXEL_SIZE, PIXEL_SIZE);
      });

      ctx.globalAlpha = 1.0;
      animationFrameId = requestAnimationFrame(render);
    };

    render(performance.now());

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [pointerRef]);

  return (
    <canvas
      ref={canvasRef}
      className="pixel-shield-canvas"
      role="img"
      aria-label="InvisioVault pixel art shield emblem"
    />
  );
}

