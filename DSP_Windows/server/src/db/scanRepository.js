/**
 * Supabase CRUD — DB 테이블 저장·조회 함수 모음
 *
 * ※ 연동 DB: zyppdhjjetyogpuvjafp.supabase.co
 *
 * 테이블 구조:
 *   scan_jobs           — PK: id (uuid)
 *   analysis_logs       — log_level (not level)
 *   application_filtered — Trivy 취약점, package_name (not pkg_name)
 *   security_filtered   — Trivy 시크릿, match_text / diff_id
 *   grype_filtered      — Grype 취약점, package_name / fix_version(단수)
 *   scan_reports        — FK: scan_jobs_id (with 's')
 *
 * 없는 테이블 (구버전에서 제거됨):
 *   trivy_results, grype_results, sbom_raw
 */

const supabase = require('./index');

// ── 공통 헬퍼 ─────────────────────────────────────────────
function assertNoError({ error }, label) {
  if (error) throw new Error(`[DB] ${label}: ${error.message}`);
}

/**
 * Supabase REST API 1000행 제한 대응 — chunk 단위 순차 insert
 */
async function insertChunked(table, rows, chunkSize = 500) {
  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);
    const res = await supabase.from(table).insert(chunk);
    if (res.error) {
      console.error(`[DB] ${table} INSERT 실패 — code:${res.error.code} msg:${res.error.message}`);
      console.error(`[DB] ${table} INSERT 실패 — 첫 행 컬럼:`, JSON.stringify(Object.keys(chunk[0])));
      console.error(`[DB] ${table} INSERT 실패 — 첫 행 null 컬럼:`,
        Object.entries(chunk[0]).filter(([,v]) => v == null).map(([k]) => k));
    }
    assertNoError(res, `${table} bulk insert`);
  }
}

// ── scan_jobs ──────────────────────────────────────────────
/**
 * 새 스캔 잡 생성
 * 새 DB: PK = id, 컬럼 = file_name / file_type / image_name / upload_path
 */
async function createJob({ id, originalName, savedName }) {
  const res = await supabase.from('scan_jobs').insert({
    id,
    file_name:    originalName || savedName || '',
    file_type:    'image_tar',   // CHECK: 'image_tar' | 'dockerfile' | 'sbom'
    image_name:   originalName || null,
    upload_path:  savedName    || null,
    status:       'uploaded',   // CHECK: pending|uploaded|running|completed|failed|cancelled
    trivy_status: 'pending',    // CHECK: pending|running|completed|failed|skipped
    grype_status: 'pending',    // CHECK: pending|running|completed|failed|skipped
  });
  assertNoError(res, 'createJob');
}

/**
 * 잡 상태 업데이트
 * 새 DB: .eq('id', ...) / error_message (not error_msg)
 */
// 상태값 매핑 (구버전 → 새 DB CHECK 허용값)
const STATUS_MAP = {
  queued:    'uploaded',    // 'queued' → CHECK 미허용, 'uploaded' 사용
  done:      'completed',   // 'done'   → CHECK 미허용, 'completed' 사용
  running:   'running',
  failed:    'failed',
  cancelled: 'cancelled',
  pending:   'pending',
  uploaded:  'uploaded',
  completed: 'completed',
};

async function updateJobStatus(id, status, errorMsg = null) {
  const mappedStatus = STATUS_MAP[status] || status;
  const update = {
    status:        mappedStatus,
    error_message: errorMsg,
    updated_at:    new Date().toISOString(),
  };

  if (mappedStatus === 'running') {
    update.started_at = new Date().toISOString();
  }
  if (mappedStatus === 'completed' || mappedStatus === 'failed') {
    update.finished_at = new Date().toISOString();
  }

  const res = await supabase
    .from('scan_jobs')
    .update(update)
    .eq('id', id);           // ← 구버전: .eq('scan_job_id', id)
  assertNoError(res, 'updateJobStatus');
}

/**
 * 스캔 완료 후 집계 카운트 업데이트
 */
async function updateJobCounts(id, counts) {
  const res = await supabase
    .from('scan_jobs')
    .update({
      total_vulnerabilities: counts.total       || 0,
      critical_count:        counts.critical    || 0,
      high_count:            counts.high        || 0,
      medium_count:          counts.medium      || 0,
      low_count:             counts.low         || 0,
      unknown_count:         counts.unknown     || 0,
      updated_at:            new Date().toISOString(),
    })
    .eq('id', id);
  assertNoError(res, 'updateJobCounts');
}

// ── analysis_logs ─────────────────────────────────────────
/**
 * 로그 기록
 * 새 DB: log_level (not level)
 */
// analysis_logs.log_level CHECK 허용값 매핑 ('warn' → 'warning')
const LOG_LEVEL_MAP = {
  warn:    'warning',
  warning: 'warning',
  info:    'info',
  error:   'error',
  debug:   'debug',
};

async function addLog(jobId, level, message) {
  const mappedLevel = LOG_LEVEL_MAP[level] || 'info';
  const res = await supabase.from('analysis_logs').insert({
    scan_job_id: jobId,
    log_level:   mappedLevel,
    message,
  });
  // 로그 실패는 워커 흐름을 막지 않음
  if (res.error) console.warn('[DB] addLog 실패:', res.error.message);
}

// ── application_filtered (Trivy 취약점) ────────────────────
/**
 * Trivy 취약점 저장
 * 새 DB: trivy_results 없음 → 바로 application_filtered에 저장
 * 컬럼: package_name(not pkg_name), package_path, scanner, result_class, result_type
 */
async function saveTrivyResults(jobId, vulnerabilities) {
  if (!vulnerabilities || !vulnerabilities.length) return;

  const rows = vulnerabilities
    .filter(v => v.vulnerabilityId && v.pkgName)   // 필수 컬럼 null 행 제외
    .map(v => ({
      scan_job_id:        jobId,
      scanner:            'trivy',
      target:             v.target            || null,
      result_class:       v.resultClass       || null,
      result_type:        v.targetType        || null,
      vulnerability_id:   v.vulnerabilityId,
      package_name:       v.pkgName,               // ← 구버전: pkg_name
      package_path:       v.pkgPath           || null,
      installed_version:  v.installedVersion  || null,
      fixed_version:      v.fixedVersion      || null,
      severity:           v.severity          || 'UNKNOWN',
      title:              v.title             || null,
      description:        v.description       || null,
      primary_url:        v.primaryURL        || null,
      // is_fixed_available: DB generated column — 직접 삽입 불가
    }));

  if (!rows.length) return;
  await insertChunked('application_filtered', rows);
}

// ── security_filtered (Trivy 시크릿) ──────────────────────
/**
 * Trivy 시크릿 저장
 * 새 DB: match_text(not match_masked), diff_id(not layer_diff_id)
 */
async function saveSecurityFiltered(jobId, secrets) {
  if (!secrets || !secrets.length) return;

  const rows = secrets.map(s => ({
    scan_job_id:  jobId,
    scanner:      'trivy',
    rule_id:      s.ruleId,
    category:     s.category    || null,
    severity:     s.severity    || 'HIGH',
    match_text:   s.match       || null,      // ← 구버전: match_masked
    layer_digest: s.layerDigest || null,
    diff_id:      s.layerDiffID || null,      // ← 구버전: layer_diff_id
  }));

  await insertChunked('security_filtered', rows);
}

// ── grype_filtered (Grype 취약점) ─────────────────────────
/**
 * Grype 취약점 저장
 * 새 DB: grype_results 없음 → 바로 grype_filtered에 저장
 * 컬럼: package_name(not pkg_name), package_type, fix_version(단수), state, risk
 */
async function saveGrypeResults(jobId, vulnerabilities) {
  if (!vulnerabilities || !vulnerabilities.length) return;

  const rows = vulnerabilities
    .filter(v => v.vulnerabilityId && v.name)       // 필수 컬럼 null 행 제외
    .map(v => ({
      scan_job_id:              jobId,
      scanner:                  'grype',
      vulnerability_id:         v.vulnerabilityId,
      data_source:              v.dataSource                       || null,
      severity:                 v.severity                         || 'Unknown',
      description:              v.description                      || null,
      fix_version:              v.fix                              || null,  // ← 구버전: fix_versions
      state:                    v.state                            || null,
      risk:                     v.riskScore != null
                                  ? String(v.riskScore)
                                  : null,
      artifact_id:              v.artifactId                       || null,
      package_name:             v.name,                                      // ← 구버전: pkg_name
      package_type:             v.type                            || null,   // ← 구버전: pkg_type
      install_path:             v.pkgPath                          || null,
      related_vulnerability_id: v.relatedIds?.length > 0
                                  ? v.relatedIds[0]
                                  : null,
      // is_fixed_available: DB generated column — 직접 삽입 불가
    }));

  if (!rows.length) return;
  await insertChunked('grype_filtered', rows);
}

// ── scan_reports (교차 분석) ───────────────────────────────
/**
 * 교차 분석 결과 저장
 * 새 DB: FK 컬럼명 scan_jobs_id(with 's'), 컬럼명 grype_only / trivy_only(count 없음)
 */
async function saveScanReport(jobId, scanReport /*, filteredData, severityCounts */) {
  const res = await supabase.from('scan_reports').insert({
    scan_jobs_id:  jobId,                           // ← 구버전: scan_job_id
    total_count:   scanReport.total_count    || 0,
    common_count:  scanReport.common_count   || 0,
    grype_only:    scanReport.grype_only     || 0,  // ← 구버전: grype_only_count
    trivy_only:    scanReport.trivy_only     || 0,  // ← 구버전: trivy_only_count
    mismatch_count: scanReport.mismatch_count || 0,
  });
  assertNoError(res, 'saveScanReport');
}

// ── 결과 조회 ─────────────────────────────────────────────
/**
 * 잡 + 전체 결과 조회
 * 새 DB: .eq('id', jobId) / trivy_results·grype_results·sbom_raw 없음
 */
async function getJobWithResults(jobId) {
  const { data: job, error: jobErr } = await supabase
    .from('scan_jobs')
    .select('*')
    .eq('id', jobId)          // ← 구버전: .eq('scan_job_id', jobId)
    .single();
  if (jobErr) throw new Error(`[DB] getJob: ${jobErr.message}`);
  if (!job) return null;

  const [
    { data: appFiltered,   error: appErr   },
    { data: grypeFiltered, error: grypeErr },
    { data: secFiltered,   error: secErr   },
    { data: logs,          error: logsErr  },
    { data: scanReport,    error: reportErr},
  ] = await Promise.all([
    supabase.from('application_filtered').select('*').eq('scan_job_id', jobId),
    supabase.from('grype_filtered').select('*').eq('scan_job_id', jobId),
    supabase.from('security_filtered').select('*').eq('scan_job_id', jobId),
    supabase.from('analysis_logs').select('*').eq('scan_job_id', jobId).order('created_at'),
    supabase.from('scan_reports').select('*').eq('scan_jobs_id', jobId).maybeSingle(),
  ]);

  if (appErr)    console.warn('[DB] application_filtered SELECT 실패:', appErr.message);
  if (grypeErr)  console.warn('[DB] grype_filtered SELECT 실패:', grypeErr.message);
  if (secErr)    console.warn('[DB] security_filtered SELECT 실패:', secErr.message);
  if (logsErr)   console.warn('[DB] analysis_logs SELECT 실패:', logsErr.message);
  if (reportErr) console.warn('[DB] scan_reports SELECT 실패:', reportErr.message);

  console.log(`[DB] getJobWithResults — trivy:${(appFiltered||[]).length} grype:${(grypeFiltered||[]).length} secrets:${(secFiltered||[]).length} logs:${(logs||[]).length}`);

  return {
    job,
    applicationFiltered: appFiltered   || [],
    grypeFiltered:       grypeFiltered || [],
    securityFiltered:    secFiltered   || [],
    logs:                logs          || [],
    scanReport:          scanReport    || null,
  };
}

async function listJobs(limit = 20) {
  const { data, error } = await supabase
    .from('scan_jobs')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw new Error(`[DB] listJobs: ${error.message}`);
  return data || [];
}

module.exports = {
  createJob,
  updateJobStatus,
  updateJobCounts,
  addLog,
  saveTrivyResults,
  saveSecurityFiltered,
  saveGrypeResults,
  saveScanReport,
  getJobWithResults,
  listJobs,
};
