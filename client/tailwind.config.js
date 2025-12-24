/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          yellow: '#facc15',
          yellowDark: '#eab308',
        },
      },
    },
  },
  plugins: [],
};
