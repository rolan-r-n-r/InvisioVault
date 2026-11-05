import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { isLand, CYBER_HUBS, TRANSMISSION_PAIRS } from './earthData.js';
import { VISUALIZATION_CONFIG } from './visualizationConfig.js';

// Persistent rotation state across route transitions or component remounts
let persistentGlobeRotY = 1.85;
if (typeof window !== 'undefined') {
  window.__invisiovault_earth_rot_y = () => persistentGlobeRotY;
}

export default function EarthVisualization({ mode = 'stego', pointerRef }) {
  const mountRef = useRef(null);
  const modeRef = useRef(mode);

  // Sync mode changes smoothly without re-initializing the Three.js scene
  useEffect(() => {
    modeRef.current = mode;
  }, [mode]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const RADIUS = 1.44;

    // Scene & Perspective Camera with 38° vertical FOV
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 50);

    // Exact Camera Distance Framing:
    // Positions the camera along Z so the Earth's visible spherical diameter
    // on screen matches the requested target scale across all screen resolutions:
    // - 1920x1080: 350-390px (target ~365px)
    // - 1600x900:  320-340px (target ~338px)
    // - 1366x768:  220-260px scaled to gutter width (target ~215px)
    const updateCameraFraming = (width, height) => {
      if (width === 0 || height === 0) return;
      const aspect = width / height;
      camera.aspect = aspect;

      const windowW = window.innerWidth;
      const gutterWidth = Math.max(0, (windowW - 900) / 2);
      let targetDiameterPx;
      if (windowW >= 1800) {
        targetDiameterPx = 365; // Target: 350-390px (at 1920x1080)
      } else if (windowW >= 1500) {
        const t = (windowW - 1500) / 300;
        targetDiameterPx = Math.round(325 + t * 40); // 338px at 1600 (target: 320-340px)
      } else if (windowW >= 1200) {
        // Scaled appropriately to available gutter width at 1366 (gutter: 233px)
        targetDiameterPx = Math.min(240, Math.max(200, Math.round(gutterWidth - 18)));
      } else {
        targetDiameterPx = Math.min(200, Math.round(gutterWidth - 16));
      }

      // Exact perspective projection distance formula:
      // VisibleDiameter = (2 * RADIUS * height) / (2 * Z * tan(vFov / 2))
      // => targetZ = (RADIUS * height) / (targetDiameterPx * tan(vFov / 2))
      const vFovHalfRad = (camera.fov * Math.PI) / 360;
      const targetZ = (RADIUS * height) / (targetDiameterPx * Math.tan(vFovHalfRad));

      // Fail-safe to ensure camera frustum half-width at Z is >= RADIUS * 1.08 (Earth + aura)
      const minAspectZ = (RADIUS * 1.08) / (Math.tan(vFovHalfRad) * aspect);

      camera.position.set(0, 0, Math.max(targetZ, minAspectZ));
      camera.updateProjectionMatrix();
    };

    // WebGL Renderer with 100% transparent background
    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setClearColor(0x000000, 0); // 100% transparent
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const initialWidth = container.clientWidth || 380;
    const initialHeight = container.clientHeight || 380;
    renderer.setSize(initialWidth, initialHeight);
    updateCameraFraming(initialWidth, initialHeight);
    container.appendChild(renderer.domElement);

    // Root Earth Group with natural 23.4° axial tilt
    const earthTiltGroup = new THREE.Group();
    earthTiltGroup.rotation.z = (23.4 * Math.PI) / 180;
    scene.add(earthTiltGroup);

    // Rotating Globe Group: Perfectly centered at (0, 0, 0)
    const globeGroup = new THREE.Group();
    globeGroup.position.set(0, 0, 0);
    earthTiltGroup.add(globeGroup);

    // -------------------------------------------------------------------------
    // 1. Monochromatic Fibonacci Point Cloud (Land & Ocean Silhouette)
    // -------------------------------------------------------------------------
    const TOTAL_POINTS = 8200;
    const goldenRatio = (1 + Math.sqrt(5)) / 2;

    const positions = [];
    const colors = [];
    const sizes = [];
    const alphas = [];
    const isLands = [];

    // Strictly Monochromatic Palette
    const cPureWhite = new THREE.Color(VISUALIZATION_CONFIG.palette.pureWhite);
    const cWhite = new THREE.Color(VISUALIZATION_CONFIG.palette.white);
    const cLightSilver = new THREE.Color(VISUALIZATION_CONFIG.palette.lightSilver);
    const cMutedSilver = new THREE.Color(VISUALIZATION_CONFIG.palette.mutedSilver);
    const cCharcoal = new THREE.Color(VISUALIZATION_CONFIG.palette.charcoal);

    for (let i = 0; i < TOTAL_POINTS; i++) {
      const y = 1 - (i / (TOTAL_POINTS - 1)) * 2;
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = (2 * Math.PI * i) / goldenRatio;

      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;

      const lat = Math.asin(y) * (180 / Math.PI);
      const lon = Math.atan2(z, x) * (180 / Math.PI);

      const isContinent = isLand(lat, lon);

      if (isContinent) {
        const landR = RADIUS * 1.012;
        positions.push(x * landR, y * landR, z * landR);

        // Continental grayscale palette: White and silver variations
        const rand = Math.random();
        let ptColor;
        if (rand < 0.65) {
          ptColor = cWhite;
        } else if (rand < 0.85) {
          ptColor = cLightSilver;
        } else if (rand < 0.94) {
          ptColor = cMutedSilver;
        } else {
          ptColor = cPureWhite;
        }

        colors.push(ptColor.r, ptColor.g, ptColor.b);
        sizes.push(1.8 + Math.random() * 1.0);
        alphas.push(0.86 + Math.random() * 0.14);
        isLands.push(1.0);
      } else {
        if (i % 7 === 0) {
          const oceanR = RADIUS * 0.995;
          positions.push(x * oceanR, y * oceanR, z * oceanR);
          colors.push(cCharcoal.r, cCharcoal.g, cCharcoal.b);
          sizes.push(1.0);
          alphas.push(0.05); // Transparent ocean silhouette
          isLands.push(0.0);
        }
      }
    }

    // Monochromatic Atmospheric aura particles (Extremely subtle white/silver)
    const ATMOS_POINTS = 340;
    for (let i = 0; i < ATMOS_POINTS; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = RADIUS * (1.03 + Math.random() * 0.08);

      const sinPhi = Math.sin(phi);
      const x = r * sinPhi * Math.cos(theta);
      const y = r * Math.cos(phi);
      const z = r * sinPhi * Math.sin(theta);

      positions.push(x, y, z);
      const isBright = Math.random() > 0.65;
      const ptColor = isBright ? cLightSilver : cMutedSilver;
      colors.push(ptColor.r, ptColor.g, ptColor.b);
      sizes.push(1.2 + Math.random() * 0.7);
      alphas.push(0.12 + Math.random() * 0.12);
      isLands.push(0.4);
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geometry.setAttribute('aColor', new THREE.Float32BufferAttribute(colors, 3));
    geometry.setAttribute('aSize', new THREE.Float32BufferAttribute(sizes, 1));
    geometry.setAttribute('aAlpha', new THREE.Float32BufferAttribute(alphas, 1));
    geometry.setAttribute('aIsLand', new THREE.Float32BufferAttribute(isLands, 1));

    const pointsMaterial = new THREE.ShaderMaterial({
      uniforms: {
        uPixelRatio: { value: Math.min(window.devicePixelRatio || 1, 2) },
        uPointer: { value: new THREE.Vector2(-10, -10) },
        uHover: { value: 0.0 },
        uTime: { value: 0.0 },
      },
      vertexShader: `
        uniform float uPixelRatio;
        uniform vec2 uPointer;
        uniform float uHover;
        uniform float uTime;

        attribute float aSize;
        attribute vec3 aColor;
        attribute float aAlpha;
        attribute float aIsLand;

        varying vec3 vColor;
        varying float vAlpha;
        varying float vIsLand;

        void main() {
          vColor = aColor;
          vAlpha = aAlpha;
          vIsLand = aIsLand;

          vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
          vec4 proj = projectionMatrix * mvPosition;
          vec2 screenPos = proj.xy / proj.w;

          float distToPointer = length(screenPos - uPointer);
          float proximity = smoothstep(0.45, 0.0, distToPointer) * uHover;

          vec3 norm = normalize(position);
          vec3 viewNorm = normalize(normalMatrix * norm);
          float facing = viewNorm.z;

          float depthAlpha;
          if (facing > 0.0) {
            depthAlpha = 0.45 + 0.55 * facing;
          } else {
            depthAlpha = max(0.015, 0.08 * (1.0 + facing));
          }

          float rim = (1.0 - abs(facing)) * 0.22;
          float sizeMultiplier = 1.0 + proximity * 0.45;
          float ptSize = (aSize * sizeMultiplier) * (4.5 / -mvPosition.z) * uPixelRatio;
          gl_PointSize = max(1.0, ptSize);
          gl_Position = proj;

          // Pure white hover highlight (Monochromatic)
          vColor = mix(vColor, vec3(1.0, 1.0, 1.0), proximity * 0.45);
          vAlpha = (vAlpha * depthAlpha + rim * aIsLand) * (1.0 + proximity * 0.35);
        }
      `,
      fragmentShader: `
        varying vec3 vColor;
        varying float vAlpha;
        varying float vIsLand;

        void main() {
          vec2 coord = gl_PointCoord - vec2(0.5);
          float dist = length(coord);
          if (dist > 0.5) discard;

          float alphaDisc = smoothstep(0.5, 0.2, dist);
          float core = smoothstep(0.2, 0.0, dist) * 0.35;
          vec3 finalColor = vColor + vec3(core);

          gl_FragColor = vec4(finalColor, vAlpha * alphaDisc);
        }
      `,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    const pointsMesh = new THREE.Points(geometry, pointsMaterial);
    globeGroup.add(pointsMesh);

    // -------------------------------------------------------------------------
    // 2. Monochromatic Hubs & Transmission Arcs
    // -------------------------------------------------------------------------
    function latLonToVector3(lat, lon, radius) {
      const latRad = lat * (Math.PI / 180);
      const lonRad = lon * (Math.PI / 180);
      const y = radius * Math.sin(latRad);
      const rAtY = radius * Math.cos(latRad);
      const x = rAtY * Math.cos(lonRad);
      const z = rAtY * Math.sin(lonRad);
      return new THREE.Vector3(x, y, z);
    }

    const hubPositions = CYBER_HUBS.map((hub) =>
      latLonToVector3(hub.lat, hub.lon, RADIUS * 1.016)
    );

    const hubGeo = new THREE.BufferGeometry().setFromPoints(hubPositions);
    const hubMat = new THREE.PointsMaterial({
      color: cPureWhite,
      size: 3.5,
      sizeAttenuation: false,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const hubPointsMesh = new THREE.Points(hubGeo, hubMat);
    globeGroup.add(hubPointsMesh);

    const arcCurves = [];
    const arcLinesGroup = new THREE.Group();
    const packetMeshes = [];

    TRANSMISSION_PAIRS.forEach(([idxA, idxB]) => {
      const vA = hubPositions[idxA];
      const vB = hubPositions[idxB];
      if (!vA || !vB) return;

      const mid = new THREE.Vector3().addVectors(vA, vB).multiplyScalar(0.5);
      const dist = vA.distanceTo(vB);
      const maxAlt = RADIUS * (1.04 + Math.min(dist * 0.08, 0.16));
      mid.normalize().multiplyScalar(maxAlt);

      const curve = new THREE.QuadraticBezierCurve3(vA, mid, vB);
      arcCurves.push(curve);

      const pts = curve.getPoints(24);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
      const lineMat = new THREE.LineBasicMaterial({
        color: cMutedSilver,
        transparent: true,
        opacity: 0.15,
        blending: THREE.AdditiveBlending,
      });
      const lineMesh = new THREE.Line(lineGeo, lineMat);
      arcLinesGroup.add(lineMesh);

      // Traveling Pure White Data Packet
      const pGeo = new THREE.BufferGeometry();
      pGeo.setAttribute('position', new THREE.Float32BufferAttribute([vA.x, vA.y, vA.z], 3));
      const pMat = new THREE.PointsMaterial({
        color: cPureWhite,
        size: 3.0,
        sizeAttenuation: false,
        transparent: true,
        opacity: 0.95,
        blending: THREE.AdditiveBlending,
      });
      const pMesh = new THREE.Points(pGeo, pMat);
      globeGroup.add(pMesh);
      packetMeshes.push({
        mesh: pMesh,
        curve,
        progress: Math.random(),
        speedMultiplier: 0.8 + Math.random() * 0.4,
      });
    });
    globeGroup.add(arcLinesGroup);

    // -------------------------------------------------------------------------
    // 3. Smooth Interaction Dynamics (Rotation & Viewport-Persistent Positioning)
    // -------------------------------------------------------------------------
    let targetRotY = 0;
    let targetRotX = 0;
    let currentRotY = 0;
    let currentRotX = 0;

    let targetScrollRotY = 0;
    let currentScrollRotY = 0;

    const mouseScreenPos = new THREE.Vector2(-10, -10);
    let targetHover = 0;
    let currentHover = 0;

    const handleScroll = () => {
      if (prefersReducedMotion) return;
      const scrollY = window.scrollY;
      // Scroll purely induces smooth axial yaw rotation without moving vertical position
      targetScrollRotY = scrollY * 0.0007;
    };

    window.addEventListener('scroll', handleScroll, { passive: true });

    // Responsive Canvas Resize Observer with dynamic camera distance framing
    const handleResize = () => {
      if (!container || !renderer || !camera) return;
      const width = container.clientWidth;
      const height = container.clientHeight;
      if (width === 0 || height === 0) return;

      updateCameraFraming(width, height);
      renderer.setSize(width, height);
      pointsMaterial.uniforms.uPixelRatio.value = Math.min(window.devicePixelRatio || 1, 2);
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    // Visibility management
    let isTabVisible = !document.hidden;
    const handleVisibilityChange = () => {
      isTabVisible = !document.hidden;
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Initial orientation: Restore continuous rotation state (or default to Americas/Atlantic)
    globeGroup.rotation.y = persistentGlobeRotY;

    // -------------------------------------------------------------------------
    // 4. Main Animation Loop
    // -------------------------------------------------------------------------
    let animationFrameId;
    const startTime = performance.now();

    const animate = (time) => {
      if (!isTabVisible) {
        animationFrameId = requestAnimationFrame(animate);
        return;
      }

      const currentTime = time || performance.now();
      const elapsedTime = (currentTime - startTime) * 0.001;

      // Read pointer state if available
      if (pointerRef && pointerRef.current && !prefersReducedMotion) {
        const ptr = pointerRef.current;
        targetRotY = ptr.normX * 0.28;
        targetRotX = ptr.normY * 0.18;

        const rect = container.getBoundingClientRect();
        const distFromContainer = Math.hypot(
          ptr.clientX - (rect.left + rect.width * 0.5),
          ptr.clientY - (rect.top + rect.height * 0.5)
        );
        targetHover = distFromContainer < rect.width * 0.9 ? 1.0 : 0.2;

        const px = ((ptr.clientX - rect.left) / rect.width) * 2 - 1;
        const py = -(((ptr.clientY - rect.top) / rect.height) * 2 - 1);
        mouseScreenPos.set(px, py);
      }

      if (!prefersReducedMotion) {
        // Read current mode configuration dynamically without tearing down scene
        const currentModeConfig = VISUALIZATION_CONFIG.modes[modeRef.current] || VISUALIZATION_CONFIG.modes.stego;

        // Slow organic continuous rotation preserved across navigation
        globeGroup.rotation.y += 0.0012 * currentModeConfig.earth.pulseRate;
        persistentGlobeRotY = globeGroup.rotation.y;

        // Smooth damping interpolation (lerp)
        currentRotY += (targetRotY - currentRotY) * 0.04;
        currentRotX += (targetRotX - currentRotX) * 0.04;
        currentScrollRotY += (targetScrollRotY - currentScrollRotY) * 0.045;
        currentHover += (targetHover - currentHover) * 0.05;

        earthTiltGroup.rotation.x = currentRotX;
        earthTiltGroup.rotation.y = currentRotY + currentScrollRotY;
        // Keep persistent position in viewport — no vertical displacement
        earthTiltGroup.position.y = 0;

        // Update shader uniforms
        pointsMaterial.uniforms.uPointer.value.copy(mouseScreenPos);
        pointsMaterial.uniforms.uHover.value = currentHover;
        pointsMaterial.uniforms.uTime.value = elapsedTime;

        // Animate transmission packet progress along curves
        const currentDataPacketSpeed = currentModeConfig.earth.dataPacketSpeed;
        packetMeshes.forEach((item) => {
          item.progress = (item.progress + currentDataPacketSpeed * item.speedMultiplier) % 1.0;
          const pos = item.curve.getPoint(item.progress);
          const posAttr = item.mesh.geometry.attributes.position;
          posAttr.setXYZ(0, pos.x, pos.y, pos.z);
          posAttr.needsUpdate = true;
        });
      }

      renderer.render(scene, camera);
      animationFrameId = requestAnimationFrame(animate);
    };

    animate(performance.now());

    // -------------------------------------------------------------------------
    // 5. Cleanup & Resource Disposal on Unmount
    // -------------------------------------------------------------------------
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('scroll', handleScroll);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      resizeObserver.disconnect();

      geometry.dispose();
      pointsMaterial.dispose();
      hubGeo.dispose();
      hubMat.dispose();

      arcCurves.length = 0;
      arcLinesGroup.children.forEach((child) => {
        if (child.geometry) child.geometry.dispose();
        if (child.material) child.material.dispose();
      });

      packetMeshes.forEach((item) => {
        item.mesh.geometry.dispose();
        item.mesh.material.dispose();
      });

      renderer.dispose();
      if (renderer.domElement && renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }
    };
  }, [pointerRef]);

  return (
    <div
      ref={mountRef}
      className="earth-canvas-container"
      role="presentation"
      aria-hidden="true"
    />
  );
}
