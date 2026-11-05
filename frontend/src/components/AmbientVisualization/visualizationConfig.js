/**
 * Configuration and contextual settings for the Ambient Visualization system.
 * Strictly monochromatic black & white palette:
 * Pure black, near black, dark charcoal, graphite, muted silver, light silver, white, pure white.
 * Zero blue / cyan decorative elements.
 */

export const VISUALIZATION_CONFIG = {
  palette: {
    pureBlack: '#000000',
    nearBlack: '#050505',
    charcoal: '#111111',
    graphite: '#222222',
    mutedSilver: '#A3A3A3',
    lightSilver: '#D4D4D4',
    white: '#F5F5F5',
    pureWhite: '#FFFFFF',
  },

  modes: {
    stego: {
      id: 'stego',
      earth: {
        accentColor: '#FFFFFF',
        pulseRate: 1.0,
        arcColor: '#A3A3A3',
        dataPacketSpeed: 0.007,
      },
    },

    polyglot: {
      id: 'polyglot',
      earth: {
        accentColor: '#D4D4D4',
        pulseRate: 1.15,
        arcColor: '#A3A3A3',
        dataPacketSpeed: 0.0085,
      },
    },

    qrcode: {
      id: 'qrcode',
      earth: {
        accentColor: '#FFFFFF',
        pulseRate: 0.95,
        arcColor: '#D4D4D4',
        dataPacketSpeed: 0.006,
      },
    },
  },
};
