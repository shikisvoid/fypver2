import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8088'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    proxy: {
      '/api/login': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/mfa': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/token': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/logout': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/me': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/admin': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/patients': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/appointments': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/vitals': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/prescriptions': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/lab': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/billing': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/pharmacy': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/files': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/audit': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/monitoring': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/health': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api/dashboard': { target: proxyTarget, changeOrigin: true, secure: false },
      '/api': { target: proxyTarget, changeOrigin: true, secure: false }
    }
  }
})
