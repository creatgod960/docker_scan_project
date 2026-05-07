/**
 * 스캔 라우터
 *
 * POST /scan            → 스캔 잡 Bull Queue 등록
 * GET  /scan/:jobId     → 잡 상태·결과 조회 (DB + Bull 상태 병합)
 * GET  /scan            → 최근 잡 목록
 */

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const { UPLOAD_DIR } = require('../config');
const repo = require('../db/scanRepository');

const router = express.Router();

// ── Bull Queue 초기화 (Redis 없어도 서버 기동) ────────────
let scanQueue = null;
try {
  const Queue = require('bull');
  const { REDIS } = require('../config');
  scanQueue = new Queue('scan', { redis: REDIS });
  console.log('[Queue] Bull scan queue 초기화 완료');
} catch (e) {
  console.warn('[Queue] Redis 미연결 — 더미 모드:', e.message);
}

// ── POST /scan ────────────────────────────────────────────
router.post('/', async (req, res, next) => {
  try {
    const { jobId, tool = 'trivy' } = req.body;

    if (!jobId) {
      return res.status(400).json({ error: 'jobId 가 필요합니다. POST /upload 후 받은 jobId를 사용하세요.' });
    }

    const validTools = ['trivy', 'grype', 'both'];
    if (!validTools.includes(tool)) {
      return res.status(400).json({ error: `tool 은 ${validTools.join(' | ')} 중 하나여야 합니다.` });
    }

    // 업로드된 파일 확인
    const uploadDir = path.join(__dirname, '../../', UPLOAD_DIR);
    const files = fs.readdirSync(uploadDir).filter(f => f.startsWith(jobId));
    if (files.length === 0) {
      return res.status(404).json({ error: `jobId 에 해당하는 파일을 찾을 수 없습니다: ${jobId}` });
    }
    const tarPath = path.join(uploadDir, files[0]);

    // 상태 → queued 업데이트 (새 DB: tool 컬럼 없음)
    try {
      await repo.updateJobStatus(jobId, 'queued');
    } catch (_) {}

    if (scanQueue) {
      const job = await scanQueue.add(
        { jobId, tarPath, tool },
        { attempts: 2, backoff: { type: 'fixed', delay: 5000 } },
      );
      return res.status(202).json({
        jobId,
        queueJobId: job.id,
        tool,
        status:  'queued',
        message: 'GET /scan/:jobId 로 결과를 조회하세요.',
      });
    } else {
      return res.status(202).json({
        jobId,
        tool,
        status:  'queued (dummy — Redis 미연결)',
        message: 'Redis를 실행해야 실제 스캔이 동작합니다.',
      });
    }
  } catch (err) {
    next(err);
  }
});

// ── GET /scan/:jobId ──────────────────────────────────────
router.get('/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;

    // DB에서 잡 + 결과 조회
    let dbResult = null;
    try {
      dbResult = await repo.getJobWithResults(jobId);
    } catch (e) {
      console.warn('[Scan] DB 조회 실패:', e.message);
    }

    if (!dbResult) {
      return res.status(404).json({ error: `jobId를 찾을 수 없습니다: ${jobId}` });
    }

    // Bull 상태 보완 (DB status 우선, Bull은 보조)
    let queueState = null;
    if (scanQueue) {
      try {
        const jobs = await scanQueue.getJobs(['waiting', 'active', 'completed', 'failed']);
        const bJob = jobs.find(j => j.data.jobId === jobId);
        if (bJob) queueState = await bJob.getState();
      } catch (_) {}
    }

    const job = dbResult.job;
    const sr  = dbResult.scanReport;

    // 실제 파일 크기 조회
    let fileSize = null;
    let fileSizeLabel = null;
    if (job?.upload_path) {
      try {
        const stat = fs.statSync(path.join(__dirname, '../../', UPLOAD_DIR, job.upload_path));
        fileSize = stat.size;
        const mb = stat.size / (1024 ** 2);
        fileSizeLabel = mb >= 1024
          ? `${(mb / 1024).toFixed(2)} GB`
          : `${mb.toFixed(1)} MB`;
      } catch { /* 파일이 없으면 null */ }
    }

    return res.json({
      jobId,
      status:        job?.status    || queueState || 'unknown',
      fileName:      job?.file_name || null,
      imageName:     job?.image_name || null,
      fileType:      job?.file_type  || null,
      fileUrl:       job?.upload_path ? `/files/${job.upload_path}` : null,
      fileSize,
      fileSizeLabel,
      createdAt:     job?.created_at || null,
      updatedAt:     job?.updated_at || null,
      startedAt:     job?.started_at || null,
      finishedAt:    job?.finished_at || null,
      // ── 취약점 집계 ───────────────────────────────────
      summary: {
        total:    job?.total_vulnerabilities || 0,
        critical: job?.critical_count        || 0,
        high:     job?.high_count            || 0,
        medium:   job?.medium_count          || 0,
        low:      job?.low_count             || 0,
        unknown:  job?.unknown_count         || 0,
      },
      // ── 취약점 상세 ───────────────────────────────────
      trivy: {
        total:   dbResult.applicationFiltered.length,
        results: dbResult.applicationFiltered,
      },
      grype: {
        total:   dbResult.grypeFiltered.length,
        results: dbResult.grypeFiltered,
      },
      security: dbResult.securityFiltered,
      logs:     dbResult.logs,
      // ── Python 교차 분석 결과 ─────────────────────────
      crossAnalysis: sr ? {
        totalCount:    sr.total_count    || 0,
        commonCount:   sr.common_count   || 0,
        grypeOnlyCount: sr.grype_only   || 0,   // ← 구버전: grype_only_count
        trivyOnlyCount: sr.trivy_only   || 0,   // ← 구버전: trivy_only_count
        mismatchCount: sr.mismatch_count || 0,
      } : null,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /scan ─────────────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const jobs  = await repo.listJobs(limit);
    return res.json(jobs);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
