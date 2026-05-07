/**
 * 파일 관리 라우터
 *
 * GET    /files           → 저장된 파일 목록 (DB + 실제 파일 크기)
 * GET    /files/:jobId    → 특정 파일 정보
 * DELETE /files/:jobId    → 특정 파일 삭제 (디스크 + DB upload_path 초기화)
 */

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const { UPLOAD_DIR } = require('../config');
const supabase = require('../db/index');

const router   = express.Router();
const uploadDir = path.join(__dirname, '../../', UPLOAD_DIR);

/** 파일 크기를 사람이 읽기 쉬운 형태로 변환 */
function formatSize(bytes) {
  if (bytes == null) return null;
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 ** 2)   return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)   return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

/** uploads/ 디렉토리에서 실제 파일 정보를 가져옴 */
function getFileInfo(filename) {
  if (!filename) return null;
  try {
    const fullPath = path.join(uploadDir, filename);
    const stat = fs.statSync(fullPath);
    return { exists: true, size: stat.size, sizeLabel: formatSize(stat.size), mtime: stat.mtime };
  } catch {
    return { exists: false, size: null, sizeLabel: null, mtime: null };
  }
}

// ── GET /files ────────────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 50;

    const { data: jobs, error } = await supabase
      .from('scan_jobs')
      .select('id, file_name, upload_path, status, created_at, finished_at')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) return res.status(500).json({ error: error.message });

    const files = (jobs || []).map(job => {
      const info = getFileInfo(job.upload_path);
      return {
        jobId:      job.id,
        fileName:   job.file_name,
        uploadPath: job.upload_path,
        status:     job.status,
        createdAt:  job.created_at,
        finishedAt: job.finished_at,
        file:       info,
        downloadUrl: info?.exists ? `/files/${job.upload_path}` : null,
      };
    });

    // 총 디스크 사용량 계산
    const totalBytes = files.reduce((sum, f) => sum + (f.file?.size || 0), 0);

    return res.json({
      count:      files.length,
      totalSize:  formatSize(totalBytes),
      totalBytes,
      files,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /files/:jobId ─────────────────────────────────────
router.get('/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;

    const { data: job, error } = await supabase
      .from('scan_jobs')
      .select('id, file_name, upload_path, status, created_at, finished_at')
      .eq('id', jobId)
      .single();

    if (error || !job) return res.status(404).json({ error: '잡을 찾을 수 없습니다.' });

    const info = getFileInfo(job.upload_path);
    return res.json({
      jobId:       job.id,
      fileName:    job.file_name,
      uploadPath:  job.upload_path,
      status:      job.status,
      createdAt:   job.created_at,
      finishedAt:  job.finished_at,
      file:        info,
      downloadUrl: info?.exists ? `/files/${job.upload_path}` : null,
    });
  } catch (err) {
    next(err);
  }
});

// ── DELETE /files/:jobId ──────────────────────────────────
router.delete('/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;

    // DB에서 파일 경로 조회
    const { data: job, error: fetchErr } = await supabase
      .from('scan_jobs')
      .select('id, file_name, upload_path')
      .eq('id', jobId)
      .single();

    if (fetchErr || !job) return res.status(404).json({ error: '잡을 찾을 수 없습니다.' });
    if (!job.upload_path)  return res.status(404).json({ error: '저장된 파일이 없습니다.' });

    const fullPath = path.join(uploadDir, job.upload_path);

    // 디스크에서 삭제
    let deleted = false;
    try {
      fs.unlinkSync(fullPath);
      deleted = true;
    } catch (e) {
      if (e.code !== 'ENOENT') throw e; // 이미 없는 경우는 무시
    }

    // DB upload_path 초기화
    await supabase
      .from('scan_jobs')
      .update({ upload_path: null })
      .eq('id', jobId);

    return res.json({
      jobId,
      fileName: job.file_name,
      deleted,
      message: deleted ? '파일이 삭제되었습니다.' : '파일이 이미 존재하지 않았습니다.',
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
