import { getResult, pollResult } from './api.js';
import { countSeverity, renderDonut } from './charts.js';

const jobId = new URLSearchParams(location.search).get('jobId');
if (!jobId) location.href = '/';

const loadingBox  = document.getElementById('loadingBox');
const loadingMsg  = document.getElementById('loadingMsg');
const resultMain  = document.getElementById('resultMain');
const scanStatus  = document.getElementById('scanStatus');

// ── 초기 로드 ──────────────────────────────────────────────
async function init() {
  try {
    const data = await getResult(jobId);

    // 새 DB 상태값: completed (구버전: done)
    if (data.status === 'completed' || data.status === 'done') {
      render(data);
    } else if (data.status === 'failed') {
      loadingMsg.textContent = '스캔 실패: ' + (data.logs?.slice(-1)[0]?.message || '알 수 없는 오류');
    } else {
      loadingMsg.textContent = '스캔 진행 중...';
      pollResult(
        jobId,
        msg  => { loadingMsg.textContent = msg; },
        data => render(data),
        err  => { loadingMsg.textContent = '스캔 실패: ' + err; },
      );
    }
  } catch (e) {
    loadingMsg.textContent = '오류: ' + e.message;
  }
}

// ── 전체 렌더링 ────────────────────────────────────────────
function render(data) {
  loadingBox.classList.add('hidden');
  resultMain.classList.remove('hidden');

  // 새 API 응답 구조
  // data.trivy.results  = application_filtered (Trivy 취약점)
  // data.grype.results  = grype_filtered       (Grype 취약점)
  // data.security       = security_filtered    (시크릿)
  // data.summary        = { total, critical, high, medium, low, unknown }
  const trivyResults = data.trivy?.results  || [];
  const grypeResults = data.grype?.results  || [];
  const secrets      = data.security        || [];
  const logs         = data.logs            || [];

  // ── 스캔 상태 배지 ────────────────────────────────────
  scanStatus.textContent = '✅ 스캔 완료';
  scanStatus.className   = 'scan-status done';

  // ── 요약 배너 ────────────────────────────────────────
  document.getElementById('summaryImage').textContent = data.fileName || data.imageName || '—';
  document.getElementById('summaryTool').textContent  = 'TRIVY + GRYPE';

  // ── 파일 다운로드 버튼 ────────────────────────────────
  const dlBox = document.getElementById('fileDownloadBox');
  if (dlBox) {
    if (data.fileUrl) {
      const label = data.fileSizeLabel ? ` (${data.fileSizeLabel})` : '';
      dlBox.innerHTML = `
        <a href="${data.fileUrl}" download class="btn-download">
          📥 이미지 다운로드${label}
        </a>`;
    } else {
      dlBox.innerHTML = '<span class="file-deleted">파일이 삭제되었습니다</span>';
    }
  }

  // 새 API: data.summary에 집계값 있음
  const sum = data.summary || {};
  document.getElementById('sumCritical').textContent = sum.critical ?? countSeverity(trivyResults).CRITICAL;
  document.getElementById('sumHigh').textContent     = sum.high     ?? countSeverity(trivyResults).HIGH;
  document.getElementById('sumMedium').textContent   = sum.medium   ?? countSeverity(trivyResults).MEDIUM;
  document.getElementById('sumLow').textContent      = sum.low      ?? countSeverity(trivyResults).LOW;

  // 새 DB grype_filtered에 kev_included 없음 → is_fixed_available 대체 표시
  const kevCount = grypeResults.filter(v => v.kev_included).length;
  document.getElementById('sumKev').textContent    = kevCount || '—';
  document.getElementById('sumSecret').textContent = secrets.length;

  // ── 도넛 차트 ────────────────────────────────────────
  if (trivyResults.length) renderDonut('trivyDonut', countSeverity(trivyResults), 'Trivy');
  if (grypeResults.length) renderDonut('grypeDonut', countSeverity(grypeResults), 'Grype');

  // ── 탭 데이터 렌더링 ──────────────────────────────────
  renderKevTable(grypeResults.filter(v => v.kev_included));
  renderTopRisks(grypeResults);
  // appVulnsTable = Trivy 취약점 (application_filtered)
  renderVulnTable('appVulnsTable', trivyResults, ['result_type']);
  // osVulnsTable  = Grype 취약점 (grype_filtered)
  renderVulnTable('osVulnsTable',  grypeResults, ['package_type', 'is_fixed_available']);
  renderSecrets(secrets);
  renderCrossAnalysis(data.crossAnalysis);
  renderLogs(logs);
}

// ── KEV 테이블 ────────────────────────────────────────────
function renderKevTable(kev) {
  const el = document.getElementById('kevTable');
  if (!kev.length) { el.innerHTML = '<p class="empty-msg">KEV 등재 취약점 없음 ✅</p>'; return; }

  const sorted = [...kev].sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0));
  el.innerHTML = table(
    ['CVE', '패키지', '버전', '심각도', 'EPSS', '수정 버전'],
    sorted.map(v => [
      `<span class="kev-badge">KEV</span> ${v.vulnerability_id}`,
      v.package_name || v.pkg_name || '—',       // 새 DB: package_name
      v.installed_version || '—',
      sevBadge(v.severity),
      epss(v.epss_score),
      v.fix_version || v.fix_versions || '패치 없음', // 새 DB: fix_version(단수)
    ]),
  );
}

// ── Top 위험 (EPSS 또는 risk 순) ─────────────────────────
function renderTopRisks(grype) {
  const el = document.getElementById('topRisksTable');
  // 새 DB: epss_score 없음 → risk(text) 또는 severity 기준 정렬
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  const top = [...grype]
    .sort((a, b) => {
      const epssA = a.epss_score || 0, epssB = b.epss_score || 0;
      if (epssB !== epssA) return epssB - epssA;
      return (severityOrder[(b.severity||'').toUpperCase()] || 0) -
             (severityOrder[(a.severity||'').toUpperCase()] || 0);
    })
    .slice(0, 10);

  if (!top.length) { el.innerHTML = '<p class="empty-msg">데이터 없음</p>'; return; }

  el.innerHTML = table(
    ['#', 'CVE', '패키지', '심각도', 'EPSS', '위험도', '수정가능'],
    top.map((v, i) => [
      i + 1,
      v.vulnerability_id,
      v.package_name || v.pkg_name || '—',
      sevBadge(v.severity),
      epss(v.epss_score),
      v.risk || v.risk_score || '—',             // 새 DB: risk(text)
      v.is_fixed_available ? '✅' : '—',          // 새 DB: is_fixed_available
    ]),
  );
}

// ── 취약점 공통 테이블 ────────────────────────────────────
function renderVulnTable(elId, rows, extraCols = []) {
  const el = document.getElementById(elId);
  if (!rows.length) { el.innerHTML = '<p class="empty-msg">취약점 없음 ✅</p>'; return; }

  const headers = ['CVE', '패키지', '버전', '심각도'];
  if (extraCols.includes('pkg_type') || extraCols.includes('result_type') || extraCols.includes('package_type')) headers.push('타입');
  if (extraCols.includes('kev_included') || extraCols.includes('is_fixed_available')) headers.push('수정가능');
  headers.push('수정 버전');

  const tableRows = rows.map(v => {
    const pkgName = v.package_name || v.pkg_name || '—'; // 새 DB: package_name
    const fixVer  = v.fix_version  || v.fixed_version || v.fix_versions || '패치 없음'; // 새 DB: fix_version
    const cells = [v.vulnerability_id, pkgName, v.installed_version || '—', sevBadge(v.severity)];

    if (extraCols.includes('pkg_type') || extraCols.includes('result_type') || extraCols.includes('package_type')) {
      cells.push(v.package_type || v.result_type || v.pkg_type || '—');
    }
    if (extraCols.includes('kev_included') || extraCols.includes('is_fixed_available')) {
      const isKev  = v.kev_included;
      const isFix  = v.is_fixed_available;
      cells.push(isKev ? '<span class="kev-badge">KEV</span>' : (isFix ? '✅' : ''));
    }
    cells.push(fixVer);
    return cells;
  });

  el.innerHTML = table(headers, tableRows);
}

// ── 시크릿 탐지 ───────────────────────────────────────────
function renderSecrets(secrets) {
  const el = document.getElementById('secretsTable');
  if (!secrets.length) { el.innerHTML = '<p class="empty-msg">시크릿 탐지 없음 ✅</p>'; return; }

  el.innerHTML = table(
    ['심각도', 'Rule ID', '유형', '레이어', '탐지 내용'],
    secrets.map(s => [
      sevBadge(s.severity),
      s.rule_id,
      s.category    || '—',
      s.layer_digest ? s.layer_digest.substring(0, 16) + '…' : '—', // 새 DB: layer_digest
      `<code>${s.match_text || s.match_masked || '—'}</code>`,       // 새 DB: match_text
    ]),
  );
}

// ── 분석 로그 ─────────────────────────────────────────────
function renderLogs(logs) {
  const el = document.getElementById('logList');
  if (!logs.length) { el.innerHTML = '<p class="empty-msg">로그 없음</p>'; return; }

  el.innerHTML = logs.map(l => {
    // 새 DB: log_level (구버전: level)
    const level = l.log_level || l.level || 'info';
    return `
    <div class="log-item log-${level}">
      <span class="log-time">${new Date(l.created_at).toLocaleTimeString('ko-KR')}</span>
      <span class="log-level">[${level.toUpperCase()}]</span>
      <span class="log-msg">${l.message}</span>
    </div>`;
  }).join('');
}

// ── 교차 분석 렌더링 ─────────────────────────────────────
function renderCrossAnalysis(ca) {
  const noneEl = document.getElementById('crossNone');
  if (!ca) {
    noneEl.classList.remove('hidden');
    return;
  }
  noneEl.classList.add('hidden');

  document.getElementById('crossSummary').innerHTML = `
    <div class="cross-card cc-total">
      <div class="cc-label">전체 고유</div>
      <div class="cc-value">${ca.totalCount}</div>
    </div>
    <div class="cross-card cc-common">
      <div class="cc-label">공통 탐지</div>
      <div class="cc-value">${ca.commonCount}</div>
    </div>
    <div class="cross-card cc-grype">
      <div class="cc-label">Grype Only</div>
      <div class="cc-value">${ca.grypeOnlyCount}</div>
    </div>
    <div class="cross-card cc-trivy">
      <div class="cc-label">Trivy Only</div>
      <div class="cc-value">${ca.trivyOnlyCount}</div>
    </div>
    <div class="cross-card cc-mismatch">
      <div class="cc-label">심각도 불일치</div>
      <div class="cc-value">${ca.mismatchCount}</div>
    </div>
  `;

  // Grype Only
  const goEl = document.getElementById('cross-grypeOnly');
  const grypeOnly = ca.grypeOnly || [];
  if (!grypeOnly.length) {
    goEl.innerHTML = '<p class="empty-msg">Grype만 탐지한 취약점 없음 ✅</p>';
  } else {
    goEl.innerHTML = table(
      ['CVE', '패키지', '버전', '심각도', '수정 버전'],
      grypeOnly.map(v => [
        v.vulnerability_id || '—',
        v.package_name     || '—',
        v.version          || '—',
        sevBadge(v.severity),
        v.fix_version      || '패치 없음',
      ]),
    );
  }

  // Trivy Only
  const toEl = document.getElementById('cross-trivyOnly');
  const trivyOnly = ca.trivyOnly || [];
  if (!trivyOnly.length) {
    toEl.innerHTML = '<p class="empty-msg">Trivy만 탐지한 취약점 없음 ✅</p>';
  } else {
    toEl.innerHTML = table(
      ['CVE', '패키지', '버전', '심각도', '수정 버전'],
      trivyOnly.map(v => [
        v.vulnerability_id  || '—',
        v.package_name      || '—',
        v.installed_version || '—',
        sevBadge(v.severity),
        v.fixed_version     || '패치 없음',
      ]),
    );
  }

  // Mismatch
  const mmEl = document.getElementById('cross-mismatch');
  const mismatch = ca.mismatch || [];
  if (!mismatch.length) {
    mmEl.innerHTML = '<p class="empty-msg">심각도 불일치 없음 ✅</p>';
  } else {
    mmEl.innerHTML = table(
      ['CVE', '패키지', 'Grype 심각도', '', 'Trivy 심각도'],
      mismatch.map(v => [
        v.vulnerability_id || '—',
        v.package_name     || '—',
        sevBadge(v.grype_severity || v.severity),
        '<span class="sev-arrow">→</span>',
        sevBadge(v.trivy_severity || v.trivy_data?.severity),
      ]),
    );
  }

  // 서브 탭 전환
  document.querySelectorAll('.cross-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.cross-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.cross-panel').forEach(p => p.classList.add('hidden'));
      btn.classList.add('active');
      document.getElementById(`cross-${btn.dataset.cross}`).classList.remove('hidden');
    });
  });
}

// ── 탭 전환 ───────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
  });
});

// ── 헬퍼 ──────────────────────────────────────────────────
function sevBadge(sev) {
  const s = (sev || 'UNKNOWN').toUpperCase();
  const cls = { CRITICAL:'sev-critical', HIGH:'sev-high', MEDIUM:'sev-medium', LOW:'sev-low' }[s] || 'sev-unknown';
  return `<span class="${cls}">${s}</span>`;
}

function epss(score) {
  return score != null ? `${(score * 100).toFixed(2)}%` : '—';
}

function table(headers, rows) {
  const ths = headers.map(h => `<th>${h}</th>`).join('');
  const trs = rows.map(r =>
    `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`
  ).join('');
  return `<div class="table-wrap"><table><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table></div>`;
}

init();
