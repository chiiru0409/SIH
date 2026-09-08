/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#080c14',
          surface: '#0d131f',
          panel: '#121a2a',
          card: '#162035',
          border: '#1e2d4a',
          borderLight: '#2a3e66',
          cyan: '#00f0ff',
          blue: '#3b82f6',
          violet: '#8b5cf6',
          purple: '#a855f7',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444',
          muted: '#64748b',
          text: '#f1f5f9',
          textDim: '#94a3b8',
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      backgroundImage: {
        'cyber-grid': 'radial-gradient(rgba(0, 240, 255, 0.08) 1px, transparent 1px)',
        'cyber-grid-dense': 'radial-gradient(rgba(59, 130, 246, 0.12) 1px, transparent 1px)',
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-cyan': 'glowCyan 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glowCyan: {
          '0%': { boxShadow: '0 0 5px rgba(0, 240, 255, 0.2), inset 0 0 5px rgba(0, 240, 255, 0.1)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 240, 255, 0.4), inset 0 0 10px rgba(0, 240, 255, 0.2)' },
        }
      }
    },
  },
  plugins: [],
}
