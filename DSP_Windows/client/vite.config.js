import { defineConfig } from 'vite';

export default defineConfig({
  // 개발 서버 설정
  server: {
    port: 5173,
    // /upload, /scan, /health 요청을 백엔드(3000)로 프록시
    proxy: {
      '/upload': 'http://localhost:3000',
      '/scan':   'http://localhost:3000',
      '/health': 'http://localhost:3000',
      '/files':  'http://localhost:3000',
    },
  },
  // 멀티 페이지 빌드 (업로드 + 결과 페이지)
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main:   'index.html',
        result: 'result.html',
      },
    },
  },
});
