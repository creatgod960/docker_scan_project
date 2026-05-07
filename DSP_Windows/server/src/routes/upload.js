/**
 * POST /upload
 *
 * Docker 이미지 .tar 파일을 받아 서버에 저장하고
 * scan_jobs 테이블에 초기 레코드(status: queued)를 생성한다.
 *
 * 응답: { jobId, filename, savedAs, size, uploadedAt }
 */

const express  = require('express');
const multer   = require('multer');
const path     = require('path');
const { v4: uuidv4 } = require('uuid');
const { UPLOAD_DIR, MAX_FILE_SIZE_MB } = require('../config');
const repo = require('../db/scanRepository');

const router = express.Router();

// ── Multer 설정 ────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, path.join(__dirname, '../../', UPLOAD_DIR));
  },
  filename: (_req, file, cb) => {
    const jobId = uuidv4();
    const ext   = path.extname(file.originalname) || '.tar';
    cb(null, `${jobId}${ext}`);
  },
});

const fileFilter = (_req, file, cb) => {
  const allowed = ['.tar', '.tar.gz', '.tgz'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext) || file.mimetype === 'application/x-tar') {
    cb(null, true);
  } else {
    cb(new Error(`허용되지 않는 파일 형식: ${ext} (.tar, .tar.gz, .tgz 만 허용)`));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 },
});

// ── POST /upload ───────────────────────────────────────────
router.post('/', upload.single('image'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: '파일이 없습니다. form-data key: "image"' });
    }

    const jobId = path.basename(req.file.filename, path.extname(req.file.filename));

    // DB에 잡 레코드 생성 (status: queued)
    // tool은 /scan 요청 시 확정되므로 기본값 'trivy' 임시 설정
    try {
      await repo.createJob({
        id:           jobId,
        originalName: req.file.originalname,
        savedName:    req.file.filename,
        tool:         'trivy',   // POST /scan 에서 tool 업데이트 가능
      });
    } catch (dbErr) {
      console.warn('[Upload] DB 잡 생성 실패 (파일은 저장됨):', dbErr.message);
    }

    return res.status(201).json({
      jobId,
      filename:   req.file.originalname,
      savedAs:    req.file.filename,
      size:       req.file.size,
      uploadedAt: new Date().toISOString(),
      message:    'POST /scan 으로 스캔을 요청하세요.',
    });
  } catch (err) {
    next(err);
  }
});

// ── multer 에러 핸들러 ─────────────────────────────────────
router.use((err, _req, res, _next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `파일 크기 초과 (최대 ${MAX_FILE_SIZE_MB} MB)` });
  }
  return res.status(400).json({ error: err.message });
});

module.exports = router;
