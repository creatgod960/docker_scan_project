/**
 * DSP API 모듈
 * Vite 프록시 덕분에 개발/프로덕션 모두 경로만 쓰면 됨
 */

/** Docker .tar 파일 업로드 → jobId 반환 */
export async function uploadFile(file) {
  const form = new FormData();
  form.append('image', file);

  const res = await fetch('/upload', { method: 'POST', body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || '업로드 실패');
  }
  return res.json(); // { jobId, filename, size, ... }
}

/** 스캔 요청 */
export async function startScan(jobId, tool = 'both') {
  const res = await fetch('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jobId, tool }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || '스캔 요청 실패');
  }
  return res.json();
}

/** 결과 조회 */
export async function getResult(jobId) {
  const res = await fetch(`/scan/${jobId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || '조회 실패');
  }
  return res.json();
}

/**
 * 완료될 때까지 2초마다 폴링
 * @param {string} jobId
 * @param {(log: string) => void} onLog   - 로그 메시지 콜백
 * @param {(data: object) => void} onDone - 완료 콜백
 * @param {(err: string) => void} onError - 실패 콜백
 */
export function pollResult(jobId, onLog, onDone, onError) {
  const timer = setInterval(async () => {
    try {
      const data = await getResult(jobId);

      // 최신 로그 메시지 전달 (새 DB: log_level 컬럼)
      if (data.logs?.length) {
        const last = data.logs[data.logs.length - 1];
        const lvl  = (last.log_level || last.level || 'info').toUpperCase();
        onLog(`[${lvl}] ${last.message}`);
      }

      if (data.status === 'completed' || data.status === 'done') {
        clearInterval(timer);
        onDone(data);
      } else if (data.status === 'failed') {
        clearInterval(timer);
        onError(data.logs?.slice(-1)[0]?.message || '스캔 실패');
      }
    } catch (e) {
      clearInterval(timer);
      onError(e.message);
    }
  }, 2000);

  return () => clearInterval(timer); // 취소 함수 반환
}

/** 잡 목록 */
export async function listJobs(limit = 20) {
  const res = await fetch(`/scan?limit=${limit}`);
  return res.json();
}

/** 서버 헬스체크 */
export async function healthCheck() {
  const res = await fetch('/health');
  return res.json();
}
