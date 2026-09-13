import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [react(), VitePWA({
    registerType: 'autoUpdate',
    includeAssets: [],
    manifest: {
      name: 'KasirKita POS',
      short_name: 'KasirKita',
      description: 'Aplikasi kasir dan transaksi toko',
      theme_color: '#202821',
      background_color: '#f7f6f2',
      display: 'standalone',
      start_url: '/',
    },
    workbox: { navigateFallback: '/index.html' },
  })],
})
