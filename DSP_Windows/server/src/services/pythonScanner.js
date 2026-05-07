/**
 * Python 교차 분석 서비스
 *
 * Python FastAPI (python/scanner.py) 의 /analyze 엔드포인트를 호출합니다.
 * Node.js 워커가 이미 실행한 Trivy/Grype 원시 JSON을 전달받아
 * grype_only / trivy_only / mismatch 교차 분석 결과를 반환합니다.
 *
 * Python 스캐너 실행:
 *   cd <프로젝트루트>
 *   uvicorn python.scanner:app --port 8000
 *   또는: python python/scanner.py
 */

const axios = require('axios');
const { PYTHON_SCANNER_URL } = require('../config');

/**
 * Python /analyze 호출 — 스캔 재실행 없이 교차 분석만 수행
 * @param {string} jobId
 * @param {object} trivyRaw  runTrivy() 반환 원시 JSON
 * @param {object} grypeRaw  runGrype() 반환 원시 JSON
 * @param {string} imageName 원본 파일명
 * @returns {Promise<{scan_report, filtered_data, severity_counts}>}
 */
async function analyze(jobId, trivyRaw, grypeRaw, imageName = '') {
  const res = await axios.post(
    `${PYTHON_SCANNER_URL}/analyze`,
    {
      job_id:     jobId,
      image_name: imageName,
      trivy:      trivyRaw  || {},
      grype:      grypeRaw  || {},
    },
    { timeout: 120_000 },   // 교차 분석은 CPU 바운드라 넉넉하게
  );
  return res.data;
}

/**
 * Python 스캐너 가용 여부 확인 (워커 시작 시 1회 호출)
 * @returns {Promise<boolean>}
 */
async function isAvailable() {
  try {
    await axios.get(`${PYTHON_SCANNER_URL}/health`, { timeout: 3_000 });
    return true;
  } catch {
    return false;
  }
}

module.exports = { analyze, isAvailable };
