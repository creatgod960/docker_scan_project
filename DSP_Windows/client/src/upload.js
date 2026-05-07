import { uploadFile, startScan, pollResult, listJobs } from './api.js';

const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const fileNameEl = document.getElementById('fileName');
const scanBtn    = document.getElementById('scanBtn');
const progressBox = document.getElementById('progressBox');
const progressMsg = document.getElementById('progressMsg');
const errorMsg   = document.getElementById('errorMsg');
const historyList = document.getElementById('historyList');

let selectedFile = null;

// ── 파일 선택 ──────────────────────────────────────────────
function setFile(file) {
  if (!file) return;
  const allowed = ['.tar', '.tar.gz', '.tgz'];
  const ext = '.' + file.name.split('.').slice(1).join('.');
  if (!allowed.some(e => file.name.endsWith(e))) {
    showError('허용된 파일 형식: .tar, .tar.gz, .tgz');
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = `📁 ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`;
  scanBtn.disabled = false;
  clearError();
}

fileInput.addEventListener('change', e => setFile(e.target.files[0]));

// 드래그&드롭
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  setFile(e.dataTransfer.files[0]);
});

// ── 스캔 실행 ──────────────────────────────────────────────
scanBtn.addEventListener('click', async () => {
  if (!selectedFile) return;

  const tool = document.querySelector('input[name="tool"]:checked')?.value || 'both';

  scanBtn.disabled = true;
  showProgress('업로드 중...');
  clearError();

  try {
    // 1) 업로드
    const { jobId } = await uploadFile(selectedFile);
    showProgress('스캔 대기 중...');

    // 2) 스캔 요청
    await startScan(jobId, tool);
    showProgress('스캔 진행 중...');

    // 3) 완료까지 폴링
    pollResult(
      jobId,
      msg => showProgress(msg),
      data => {
        // 결과 페이지로 이동
        window.location.href = `/result.html?jobId=${data.jobId}`;
      },
      err => {
        hideProgress();
        showError(`스캔 실패: ${err}`);
        scanBtn.disabled = false;
      },
    );
  } catch (e) {
    hideProgress();
    showError(e.message);
    scanBtn.disabled = false;
  }
});

// ── 최근 스캔 목록 ──────────────────────────────────────────
async function loadHistory() {
  try {
    const jobs = await listJobs(10);
    if (!jobs.length) return;

    // 새 DB: status CHECK = pending|uploaded|running|completed|failed|cancelled
    const statusLabel = {
      pending:   '대기',
      uploaded:  '업로드됨',
      running:   '진행 중',
      completed: '완료',
      failed:    '실패',
      cancelled: '취소',
    };
    const statusClass = {
      pending:   'status-queued',
      uploaded:  'status-queued',
      running:   'status-running',
      completed: 'status-done',
      failed:    'status-failed',
      cancelled: 'status-failed',
    };

    historyList.innerHTML = jobs.map(j => `
      <a class="history-item" href="/result.html?jobId=${j.id}">
        <span class="history-name">${j.file_name || j.image_name || '—'}</span>
        <span class="history-tool">TRIVY + GRYPE</span>
        <span class="history-status ${statusClass[j.status] || ''}">
          ${statusLabel[j.status] || j.status}
        </span>
        <span class="history-date">${new Date(j.created_at).toLocaleString('ko-KR')}</span>
      </a>
    `).join('');
  } catch (_) {}
}

// ── 유틸 ───────────────────────────────────────────────────
function showProgress(msg) {
  progressBox.classList.remove('hidden');
  progressMsg.textContent = msg;
}
function hideProgress() {
  progressBox.classList.add('hidden');
}
function showError(msg) {
  errorMsg.textContent = msg;
  errorMsg.classList.remove('hidden');
}
function clearError() {
  errorMsg.classList.add('hidden');
}

loadHistory();
