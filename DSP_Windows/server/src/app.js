const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const uploadRouter = require('./routes/upload');
const scanRouter   = require('./routes/scan');
const filesRouter  = require('./routes/files');
const { ALLOWED_ORIGINS } = require('./config');

const app = express();

const isProd = process.env.NODE_ENV === 'production';
const clientDist = path.join(__dirname, '../../client/dist');

// ── CORS (개발 전용) ──────────────────────────────────────
// 프로덕션: Express가 빌드된 프론트를 직접 서빙하므로 CORS 불필요
if (!isProd) {
  app.use(cors({
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
}

app.use(express.json());

// 업로드된 파일 정적 제공
app.use('/files', express.static(path.join(__dirname, '../uploads')));

// ── 라우터 ────────────────────────────────────────────────
app.use('/upload', uploadRouter);
app.use('/scan',   scanRouter);
app.use('/files-manage', filesRouter);

// ── 헬스체크 ──────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'DSP' });
});

// ── 프로덕션: 빌드된 프론트엔드 서빙 ────────────────────
if (isProd && fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  // result.html은 별도 파일이므로 catch-all에서 index.html만 처리
  app.get('*', (req, res) => {
    const page = req.path.includes('result') ? 'result.html' : 'index.html';
    const filePath = path.join(clientDist, page);
    if (fs.existsSync(filePath)) {
      res.sendFile(filePath);
    } else {
      res.sendFile(path.join(clientDist, 'index.html'));
    }
  });
} else if (isProd) {
  console.warn('[Warning] client/dist 없음 — npm run build:client 실행 필요');
}

// ── 404 핸들러 (API 전용, 프론트 catch-all 이후) ─────────
app.use((_req, res) => {
  res.status(404).json({ error: '요청한 경로를 찾을 수 없습니다.' });
});

// ── 글로벌 에러 핸들러 ────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[Error]', err);
  res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

module.exports = app;
