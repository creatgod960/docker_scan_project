/**
 * Grype 실행 서비스
 *
 * runGrype(tarPath)     → docker-archive .tar 직접 스캔
 * parseGrypeResult(raw) → { vulnerabilities[], summary }
 *
 * Grype 전용 필드: EPSS 점수, KEV 등재 여부, 복합 Risk Score, pkg_type
 */

const { execFile } = require('child_process');
const { GRYPE_BIN } = require('../config');

/**
 * Grype로 이미지 .tar 파일 스캔
 * @param {string} tarPath
 * @returns {Promise<Object>} Grype JSON 결과
 */
function runGrype(tarPath) {
  return new Promise((resolve, reject) => {
    const args = [
      `docker-archive:${tarPath}`,
      '--output', 'json',
      '--quiet',
    ];

    execFile(GRYPE_BIN, args, { maxBuffer: 200 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        if (stdout && stdout.trim()) {
          try { return resolve(JSON.parse(stdout)); }
          catch (e) { return reject(new Error(`Grype JSON 파싱 실패: ${e.message}`)); }
        }
        return reject(new Error(`Grype 실행 오류: ${err.message}\nstderr: ${stderr}`));
      }
      try { resolve(JSON.parse(stdout)); }
      catch (e) { reject(new Error(`Grype JSON 파싱 실패: ${e.message}`)); }
    });
  });
}

/**
 * Grype 원시 결과 → 정제 데이터
 * @param {Object} raw  runGrype() 반환값
 * @returns {{ vulnerabilities: Array, summary: Object }}
 */
function parseGrypeResult(raw) {
  const vulnerabilities = [];

  for (const match of raw.matches || []) {
    const vuln     = match.vulnerability          || {};
    const artifact = match.artifact               || {};
    const related  = match.relatedVulnerabilities || [];

    vulnerabilities.push({
      // ── 취약점 정보 ─────────────────────────────────
      vulnerabilityId:  vuln.id,
      dataSource:       vuln.dataSource              || null,
      severity:         vuln.severity                || 'Unknown',
      description:      vuln.description             || null,
      fix:              vuln.fix?.versions?.join(', ') || null,
      state:            vuln.fix?.state              || 'unknown',
      // ── Grype 전용 ───────────────────────────────────
      epssScore:        vuln.epss?.[0]?.epss         ?? null,
      epssPercentile:   vuln.epss?.[0]?.percentile   ?? null,
      riskScore:        vuln.riskScore               ?? null,
      kevIncluded:      vuln.cisa?.kev               || false,
      // ── 패키지 정보 ──────────────────────────────────
      artifactId:       artifact.id                  || null,
      name:             artifact.name,
      type:             artifact.type                || null,   // deb/rpm/apk/npm/pip 등
      installedVersion: artifact.version             || null,
      pkgPath:          artifact.locations?.[0]?.path || null,
      layerDigest:      artifact.locations?.[0]?.layerID || null,
      // ── 관련 CVE ────────────────────────────────────
      relatedIds:       related.map(r => r.id),
    });
  }

  // ── 심각도별 요약 ────────────────────────────────────
  const severityCount = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };
  for (const v of vulnerabilities) {
    severityCount[v.severity] = (severityCount[v.severity] || 0) + 1;
  }

  // ── KEV 목록 ────────────────────────────────────────
  const kevList = vulnerabilities
    .filter(v => v.kevIncluded)
    .map(v => ({ vulnerabilityId: v.vulnerabilityId, name: v.name, severity: v.severity, epssScore: v.epssScore }));

  return {
    imageName: raw.source?.target?.imageID || null,
    vulnerabilities,
    summary: {
      total:    vulnerabilities.length,
      severity: severityCount,
      kevCount: kevList.length,
    },
    kevList,
  };
}

module.exports = { runGrype, parseGrypeResult };
