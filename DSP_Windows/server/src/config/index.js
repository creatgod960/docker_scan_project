module.exports = {
  PORT: process.env.PORT || 3000,

  // ── CORS ──────────────────────────────────────────────
  // 쉼표로 구분해서 여러 오리진 허용 가능
  // 예: http://localhost:5173,http://localhost:4173
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:5173', 'http://localhost:4173', 'http://localhost:3000'],

  // ── Supabase ───────────────────────────────────────────
  SUPABASE_URL:         process.env.SUPABASE_URL         || '',
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY || '',

  // ── Redis (Bull Queue) ────────────────────────────────
  REDIS: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT) || 6379,
  },

  // ── 스캔 도구 경로 ────────────────────────────────────
  TRIVY_BIN: process.env.TRIVY_BIN || 'trivy',
  GRYPE_BIN: process.env.GRYPE_BIN || 'grype',

  // ── Python 파서 경로 ──────────────────────────────────
  PYTHON_BIN:         process.env.PYTHON_BIN         || 'python',
  PYTHON_PARSER_PATH: process.env.PYTHON_PARSER_PATH || '../python/parse_result.py',

  // ── Python 스캐너 (교차 분석) ─────────────────────────
  // uvicorn python.scanner:app --port 8000 으로 실행
  PYTHON_SCANNER_URL: process.env.PYTHON_SCANNER_URL || 'http://localhost:8000',

  // ── 파일 업로드 ───────────────────────────────────────
  UPLOAD_DIR:       process.env.UPLOAD_DIR       || 'uploads',
  MAX_FILE_SIZE_MB: parseInt(process.env.MAX_FILE_SIZE_MB) || 2048,
};
