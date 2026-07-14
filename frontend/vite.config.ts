import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The FastAPI backend has no CORS middleware; same-origin via proxy instead.
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
