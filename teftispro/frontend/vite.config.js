import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
    root: '.',
    publicDir: 'public',
    server: {
        port: 2525,
        host: '0.0.0.0',
        proxy: {
            '/api': {
                target: 'http://localhost:3636',
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/api/, '')
            },
            '/uploads': {
                target: 'http://localhost:3636',
                changeOrigin: true
            }
        }
    },
    build: {
        outDir: 'dist',
        rollupOptions: {
            input: {
                main: resolve(__dirname, 'index.html'),
                login: resolve(__dirname, 'public/login.html'),
                dashboard: resolve(__dirname, 'public/kontrol_paneli.html'),
                denetimCevaplama: resolve(__dirname, 'public/denetim_cevaplama.html'),
                denetimListesi: resolve(__dirname, 'public/denetim_listesi.html'),
                denetimInceleme: resolve(__dirname, 'public/denetim_inceleme.html'),
                adminYonetimi: resolve(__dirname, 'public/admin_yonetimi.html'),
                sirketYonetimi: resolve(__dirname, 'public/sirket_yonetimi.html'),
                subeYonetimi: resolve(__dirname, 'public/sube_yonetimi.html'),
                bolgeYonetimi: resolve(__dirname, 'public/bolge_yonetimi.html'),
                raporlar: resolve(__dirname, 'public/raporlar.html'),
                profil: resolve(__dirname, 'public/profil.html'),
                kategoriYonetimi: resolve(__dirname, 'public/kategori_yonetimi.html')
            }
        }
    }
});
