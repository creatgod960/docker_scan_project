/**
 * Trivy 실행 서비스
 *
 * runTrivy(tarPath)     → 취약점 + 시크릿 JSON 결과
 * runTrivySbom(tarPath) → CycloneDX SBOM JSON
 * parseTrivyResult(raw) → { vulnerabilities[], secrets[], summary }
 */

const { execFile } = require('child_process');
const { TRIVY_BIN } = require('../config');

// ── 공통 실행 헬퍼 ────────────────────────────────────────
function execTrivy(args) {
  return new Promise((resolve, reject) => {
    execFile(TRIVY_BIN, args, { maxBuffer: 200 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        // exit code 1은 취약점 발견 시에도 반환 → stdout 있으면 성공
        if (stdout && stdout.trim()) {
          try { return resolve(JSON.parse(stdout)); }
          catch (e) { return reject(new Error(`Trivy JSON 파싱 실패: ${e.message}`)); }
        }
        return reject(new Error(`Trivy 실행 오류: ${err.message}\nstderr: ${stderr}`));
      }
      try { resolve(JSON.parse(stdout)); }
      catch (e) { reject(new Error(`Trivy JSON 파싱 실패: ${e.message}`)); }
    });
  });
}

/**
 * 취약점 + 시크릿 스캔
 * @param {string} tarPath
 * @returns {Promise<Object>} Trivy JSON 결과
 */
function runTrivy(tarPath) {
  return execTrivy([
    'image',
    '--input', tarPath,
    '--scanners', 'vuln,secret',
    '--format', 'json',
    '--quiet',
  ]);
}

/**
 * CycloneDX SBOM 생성
 * @param {string} tarPath
 * @returns {Promise<Object>} CycloneDX JSON
 */
function runTrivySbom(tarPath) {
  return execTrivy([
    'image',
    '--input', tarPath,
    '--format', 'cyclonedx',
    '--quiet',
  ]);
}

/**
 * Trivy 원시 결과 → 정제 데이터
 * @param {Object} raw  runTrivy() 반환값
 * @returns {{ vulnerabilities: Array, secrets: Array, summary: Object }}
 */
function parseTrivyResult(raw) {
  const vulnerabilities = [];
  const secrets         = [];

  for (const result of raw.Results || []) {
    const target      = result.Target;
    const targetType  = result.Type  || null;   // npm / pip / ubuntu / alpine 등
    const resultClass = result.Class || null;   // os-pkgs / lang-pkgs 등 (application_filtered.result_class)

    // ── 취약점 ──────────────────────────────────────────
    for (const vuln of result.Vulnerabilities || []) {
      vulnerabilities.push({
        target,
        targetType,
        resultClass,                             // ← 새 DB application_filtered.result_class
        vulnerabilityId:  vuln.VulnerabilityID,
        pkgName:          vuln.PkgName,
        pkgPath:          vuln.PkgPath          || null,
        installedVersion: vuln.InstalledVersion || null,
        fixedVersion:     vuln.FixedVersion     || null,
        severity:         vuln.Severity         || 'UNKNOWN',
        title:            vuln.Title            || null,
        description:      vuln.Description      || null,
        primaryURL:       vuln.PrimaryURL       || null,
        cvssV3Score:      vuln.CVSS?.nvd?.V3Score ?? null,
        publishedDate:    vuln.PublishedDate    || null,
        layerDigest:      vuln.Layer?.Digest    || null,
        layerDiffID:      vuln.Layer?.DiffID    || null,
      });
    }

    // ── 시크릿 ──────────────────────────────────────────
    for (const secret of result.Secrets || []) {
      secrets.push({
        target,
        ruleId:      secret.RuleID,
        category:    secret.Category   || null,
        severity:    secret.Severity   || 'HIGH',
        match:       secret.Match      || null,
        startLine:   secret.StartLine  ?? null,
        endLine:     secret.EndLine    ?? null,
        layerDigest: secret.Layer?.Digest || null,
        layerDiffID: secret.Layer?.DiffID || null,
      });
    }
  }

  // ── 심각도별 요약 ────────────────────────────────────
  const severityCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of vulnerabilities) {
    const key = (v.severity || 'UNKNOWN').toUpperCase();
    severityCount[key] = (severityCount[key] || 0) + 1;
  }

  return {
    imageName:   raw.ArtifactName || null,
    imageDigest: raw.Metadata?.ImageID || null,
    os:          raw.Metadata?.OS
                   ? `${raw.Metadata.OS.Family} ${raw.Metadata.OS.Name}`.trim()
                   : null,
    vulnerabilities,
    secrets,
    summary: {
      total:    vulnerabilities.length,
      severity: severityCount,
      secrets:  secrets.length,
    },
  };
}

module.exports = { runTrivy, runTrivySbom, parseTrivyResult };
