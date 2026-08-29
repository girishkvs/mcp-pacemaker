/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // Dark palette ported from the Baton dashboard for a consistent family look.
      colors: {
        bg: '#0f1117',
        panel: '#171a23',
        panel2: '#1e222d',
        line: '#2a2f3a',
        fg: '#e6e8ee',
        muted: '#9aa3b2',
        accent: '#6ea8fe',
        amber: '#f0b429',
        ok: '#34d399',
        teal: '#2dd4bf',
        danger: '#f87171',
        purple: '#a78bfa',
      },
    },
  },
  plugins: [],
};
