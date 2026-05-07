/**
 * Bull Worker — 스캔 잡 처리기
 *
 * 실행: node src/workers/scanWorker.js  (또는 npm run worker)
 *
 * 처리 흐름:
 *   1. scan_jobs 상태 → running
 *   2. Trivy 스캔 (vuln + secret) → application_filtered, security_filtered
 *   3. Grype 스캔                 → grype_filtered
 *   4. [NEW] Python 교차 분석     → scan_reports (grype_only / trivy_only / mismatch)
 *   5. scan_jobs 취약점 카운트 집계 업데이트
 *   6. scan_jobs 상태 → done / failed
 *   7. 각 단계마다 analysis_logs 기록
 *
 * ※ 연동 DB: zyppdhjjetyogpuvjafp.supabase.co
 * ※ trivy_results / grype_results / sbom_raw 테이블 없음
 *
 * Python 스캐너 (python/scanner.py) 가 실행 중이 아니어도
 * 기존 Trivy/Grype 스캔 결과는 정상 저장됩니다.
 */

require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });

const Queue  = require('bull');
const fs     = require('fs');
const { REDIS } = require('../config');

const { runTrivy, parseTrivyResult } = require('../services/trivy');
const { runGrype, parseGrypeResult }               = require('../services/grype');
const pythonScanner = require('../services/pythonScanner');
const repo     = require('../db/scanRepository');
const supabase = require('../db/index');

// 파일 보관 정책: 스캔 후 삭제하지 않고 uploads/ 에 유지
// 수동 삭제는 DELETE /files/:jobId API 사용

// ── Queue 연결 ────────────────────────────────────────────
const scanQueue = new Queue('scan', { redis: REDIS });
console.log('[Worker] DSP scan worker 시작...');

// Python 스캐너 가용 여부 (시작 시 1회 확인, 이후 잡마다 재시도)
let pythonAvailable = false;
pythonScanner.isAvailable().then(ok => {
  pythonAvailable = ok;
  if (ok) {
    console.log('[Worker] Python 교차 분석 스캐너 연결 확인 ✓');
  } else {
    console.warn('[Worker] Python 교차 분석 스캐너 미연결 — 교차 분석 없이 동작합니다.');
    console.warn('[Worker] 실행: uvicorn python.scanner:app --port 8000');
  }
});

// ── 잡 처리 ───────────────────────────────────────────────
scanQueue.process(async (job) => {
  const { jobId, tarPath, tool } = job.data;
  console.log(`[Worker] 잡 시작 — jobId: ${jobId}, tool: ${tool}`);

  await repo.updateJobStatus(jobId, 'running').catch(() => {});
  await repo.addLog(jobId, 'info', `스캔 시작 (tool: ${tool})`);

  const result = { jobId, tool, trivy: null, grype: null };

  // 교차 분석용 원시 JSON 보관
  let trivyRaw = null;
  let grypeRaw = null;

  try {
    // ────────────────────────────────────────────────────
    // ── [1] Trivy 스캔 ──────────────────────────────────
    // ────────────────────────────────────────────────────
    if (tool === 'trivy' || tool === 'both') {
      job.progress(10);
      await repo.addLog(jobId, 'info', 'Trivy 취약점 스캔 시작');
      console.log(`[Worker] Trivy 스캔 중: ${tarPath}`);

      // trivy_status → running
      try { await supabase.from('scan_jobs').update({ trivy_status: 'running' }).eq('id', jobId); } catch (_) {}

      trivyRaw      = await runTrivy(tarPath);
      const parsed  = parseTrivyResult(trivyRaw);
      result.trivy  = parsed;

      // application_filtered (Trivy 취약점 전체)
      try {
        await repo.saveTrivyResults(jobId, parsed.vulnerabilities);
        await repo.addLog(jobId, 'info',
          `Trivy 취약점 저장 완료 (총 ${parsed.vulnerabilities.length}건)`);
      } catch (e) {
        console.warn('[Worker] Trivy 취약점 DB 저장 실패:', e.message);
        await repo.addLog(jobId, 'warn', `Trivy 취약점 저장 실패: ${e.message}`);
      }

      // security_filtered (시크릿)
      try {
        await repo.saveSecurityFiltered(jobId, parsed.secrets);
        await repo.addLog(jobId, 'info',
          `Trivy 시크릿 저장 완료 (${parsed.secrets.length}건)`);
      } catch (e) {
        console.warn('[Worker] 시크릿 DB 저장 실패:', e.message);
        await repo.addLog(jobId, 'warn', `시크릿 저장 실패: ${e.message}`);
      }

      // trivy_status → completed
      try { await supabase.from('scan_jobs').update({ trivy_status: 'completed' }).eq('id', jobId); } catch (_) {}
      job.progress(tool === 'both' ? 40 : 80);
    }

    // ────────────────────────────────────────────────────
    // ── [3] Grype 스캔 ──────────────────────────────────
    // ────────────────────────────────────────────────────
    if (tool === 'grype' || tool === 'both') {
      await repo.addLog(jobId, 'info', 'Grype 스캔 시작');
      console.log(`[Worker] Grype 스캔 중: ${tarPath}`);

      // grype_status → running
      try { await supabase.from('scan_jobs').update({ grype_status: 'running' }).eq('id', jobId); } catch (_) {}

      grypeRaw      = await runGrype(tarPath);
      const parsed  = parseGrypeResult(grypeRaw);
      result.grype  = parsed;

      // grype_filtered (Grype 취약점 전체)
      try {
        await repo.saveGrypeResults(jobId, parsed.vulnerabilities);
        await repo.addLog(jobId, 'info',
          `Grype 취약점 저장 완료 (총 ${parsed.vulnerabilities.length}건, KEV ${parsed.kevList.length}건)`);
      } catch (e) {
        console.warn('[Worker] Grype DB 저장 실패:', e.message);
        await repo.addLog(jobId, 'warn', `Grype 저장 실패: ${e.message}`);
      }

      // grype_status → completed
      try { await supabase.from('scan_jobs').update({ grype_status: 'completed' }).eq('id', jobId); } catch (_) {}
      job.progress(80);
    }

    // ────────────────────────────────────────────────────
    // ── [4] Python 교차 분석 (두 도구 모두 실행된 경우) ──
    // ────────────────────────────────────────────────────
    if (trivyRaw && grypeRaw) {
      // 연결 상태 재확인 (워커 기동 후 Python 스캐너가 늦게 시작된 경우 대비)
      if (!pythonAvailable) {
        pythonAvailable = await pythonScanner.isAvailable();
      }

      if (pythonAvailable) {
        try {
          await repo.addLog(jobId, 'info', 'Python 교차 분석 시작 (grype_only / trivy_only / mismatch)');

          const job_data = await job.data; // jobId 확인용
          const analysis = await pythonScanner.analyze(
            jobId,
            trivyRaw,
            grypeRaw,
            job_data?.originalName || '',
          );

          await repo.saveScanReport(
            jobId,
            analysis.scan_report,
          );

          const sr = analysis.scan_report;
          await repo.addLog(jobId, 'info',
            `교차 분석 완료 — 전체: ${sr.total_count} | ` +
            `공통: ${sr.common_count} | ` +
            `Grype only: ${sr.grype_only} | ` +
            `Trivy only: ${sr.trivy_only} | ` +
            `심각도 불일치: ${sr.mismatch_count}`);

          console.log(`[Worker] 교차 분석 완료 — jobId: ${jobId}`);
        } catch (e) {
          console.warn('[Worker] Python 교차 분석 실패 (계속 진행):', e.message);
          await repo.addLog(jobId, 'warn', `Python 교차 분석 실패: ${e.message}`).catch(() => {});
        }
      } else {
        await repo.addLog(jobId, 'warn',
          'Python 스캐너 미연결 — 교차 분석 생략. ' +
          'uvicorn python.scanner:app --port 8000 실행 후 재스캔하면 교차 분석이 저장됩니다.');
      }
    }

    // ── 취약점 카운트 집계 → scan_jobs 업데이트 ──────────
    try {
      const trivySev  = result.trivy?.summary?.severity  || {};
      const grypeSev  = result.grype?.summary?.severity  || {};

      // 심각도별 합산 (Trivy + Grype — 중복 포함, 단순 집계)
      const total    = (result.trivy?.summary?.total || 0) + (result.grype?.summary?.total || 0);
      const critical = (trivySev.CRITICAL || 0) + (grypeSev.Critical || 0);
      const high     = (trivySev.HIGH     || 0) + (grypeSev.High     || 0);
      const medium   = (trivySev.MEDIUM   || 0) + (grypeSev.Medium   || 0);
      const low      = (trivySev.LOW      || 0) + (grypeSev.Low      || 0);
      const unknown  = (trivySev.UNKNOWN  || 0) + (grypeSev.Unknown  || 0) + (grypeSev.Negligible || 0);

      await repo.updateJobCounts(jobId, { total, critical, high, medium, low, unknown });
    } catch (e) {
      console.warn('[Worker] 카운트 업데이트 실패 (계속 진행):', e.message);
    }

    // ── 완료 ──────────────────────────────────────────────
    await repo.updateJobStatus(jobId, 'done').catch(() => {});
    await repo.addLog(jobId, 'info', '스캔 완료');
    job.progress(100);
    console.log(`[Worker] 잡 완료 — jobId: ${jobId}`);
    return result;

  } catch (err) {
    console.error(`[Worker] 잡 실패 — jobId: ${jobId}`, err.message);
    await repo.updateJobStatus(jobId, 'failed', err.message).catch(() => {});
    await repo.addLog(jobId, 'error', `스캔 실패: ${err.message}`).catch(() => {});
    throw err;
  }
});

// ── 이벤트 로그 ───────────────────────────────────────────
scanQueue.on('completed', (job) => {
  console.log(`[Queue] 완료 — Bull jobId: ${job.id}, TF jobId: ${job.data.jobId}`);
});
scanQueue.on('failed', (job, err) => {
  console.error(`[Queue] 실패 — Bull jobId: ${job.id}, TF jobId: ${job.data.jobId}`, err.message);
});
scanQueue.on('stalled', (job) => {
  console.warn(`[Queue] Stalled — Bull jobId: ${job.id}`);
});
