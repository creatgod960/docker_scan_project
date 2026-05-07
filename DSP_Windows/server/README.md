# DSP — 백엔드 적용 가이드

Docker 이미지 취약점 분석 플랫폼의 Node.js API 서버입니다.

---

## 아키텍처

```
클라이언트
  │
  ├─ POST /upload ──→ .tar 파일 저장 + scan_jobs 생성
  │
  ├─ POST /scan ───→ Bull Queue 등록
  │                       │
  │                 [scanWorker.js]
  │                  ├─ Trivy 실행 → trivy_results, application_filtered, security_filtered
  │                  ├─ SBOM 생성  → sbom_raw
  │                  └─ Grype 실행 → grype_results, grype_filtered
  │
  └─ GET /scan/:jobId ─→ Supabase에서 결과 조회
```

---

## 선행 조건

| 도구 | 버전 | 설치 |
|------|------|------|
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| Redis | 7+ | [redis.io](https://redis.io) (또는 Docker) |
| Trivy | 0.48+ | `winget install aquasecurity.trivy` |
| Grype | 0.74+ | `winget install anchore.grype` |
| Python | 3.9+ | [python.org](https://python.org) |
| Supabase 계정 | — | [supabase.com](https://supabase.com) (무료) |

---

## 1단계 — Supabase 프로젝트 설정

1. [supabase.com](https://supabase.com) 에서 새 프로젝트 생성
2. **SQL Editor** 탭 열기
3. `src/db/schema.sql` 전체 내용 붙여넣기 → **Run** 클릭
4. 9개 테이블이 생성됐는지 **Table Editor** 에서 확인

```
테이블 목록:
  profiles, scan_jobs, sbom_raw,
  trivy_results, grype_results,
  grype_filtered, application_filtered, security_filtered,
  analysis_logs
```

5. **Settings → API** 에서 다음 두 값 복사:
   - `Project URL` → `SUPABASE_URL`
   - `service_role` 키 (Secret) → `SUPABASE_SERVICE_KEY`

---

## 2단계 — 환경 변수 설정

```bash
cp .env.example .env
```

`.env` 파일 편집:

```env
PORT=3000

SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJ...   # service_role 키 (절대 노출 금지)

REDIS_HOST=localhost
REDIS_PORT=6379

TRIVY_BIN=trivy
GRYPE_BIN=grype

PYTHON_BIN=python
PYTHON_PARSER_PATH=../python/parse_result.py

UPLOAD_DIR=uploads
MAX_FILE_SIZE_MB=2048
```

---

## 3단계 — 의존성 설치

```bash
cd server
npm install
```

---

## 4단계 — Redis 실행

**Docker 사용 시:**
```bash
docker run -d -p 6379:6379 redis:alpine
```

**Windows 직접 설치 시:** Redis 서비스 시작

---

## 5단계 — 서버 실행

터미널 2개를 엽니다.

**[터미널 1] API 서버:**
```bash
cd server
npm run dev        # 개발 (nodemon, 자동 재시작)
# 또는
npm start          # 프로덕션
```

**[터미널 2] Bull Worker:**
```bash
cd server
npm run worker
```

서버 정상 기동 로그:
```
[DB] Supabase 연결 성공
[Queue] Bull scan queue 초기화 완료
[Server] DSP API 서버 실행 중: http://localhost:3000
[Worker] DSP scan worker 시작...
```

---

## API 사용 예시

### 1) 파일 업로드

```bash
curl -X POST http://localhost:3000/upload \
  -F "image=@./myimage.tar"
```

응답:
```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "myimage.tar",
  "savedAs": "550e8400-e29b-41d4-a716-446655440000.tar",
  "size": 134217728,
  "uploadedAt": "2026-04-16T10:00:00.000Z",
  "message": "POST /scan 으로 스캔을 요청하세요."
}
```

### 2) 스캔 요청

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"jobId": "550e8400-...", "tool": "both"}'
```

`tool` 옵션: `trivy` | `grype` | `both`

응답:
```json
{
  "jobId": "550e8400-...",
  "queueJobId": "1",
  "tool": "both",
  "status": "queued",
  "message": "GET /scan/:jobId 로 결과를 조회하세요."
}
```

### 3) 결과 조회

```bash
curl http://localhost:3000/scan/550e8400-...
```

응답 구조:
```json
{
  "jobId": "...",
  "status": "done",
  "tool": "both",
  "trivy": {
    "total": 142,
    "results": [...]
  },
  "grype": {
    "total": 98,
    "results": [...]
  },
  "filtered": {
    "application": [...],   // 라이브러리 취약점 (Trivy)
    "grypeOs": [...],       // OS 취약점 (Grype)
    "security": [...]       // 시크릿 탐지 (Trivy)
  },
  "logs": [...],
  "sbom": [...]
}
```

### 4) 잡 목록 조회

```bash
curl http://localhost:3000/scan?limit=20
```

### 5) 헬스체크

```bash
curl http://localhost:3000/health
```

---

## 디렉토리 구조

```
server/
├── src/
│   ├── index.js                  # 서버 진입점
│   ├── app.js                    # Express 앱
│   ├── config/
│   │   └── index.js              # 환경변수 중앙 관리
│   ├── routes/
│   │   ├── upload.js             # POST /upload
│   │   └── scan.js               # POST|GET /scan
│   ├── services/
│   │   ├── trivy.js              # runTrivy(), runTrivySbom(), parseTrivyResult()
│   │   └── grype.js              # runGrype(), parseGrypeResult()
│   ├── workers/
│   │   └── scanWorker.js         # Bull Worker
│   └── db/
│       ├── index.js              # Supabase 클라이언트
│       ├── schema.sql            # PostgreSQL DDL (Supabase SQL Editor용)
│       └── scanRepository.js     # CRUD 함수
├── uploads/                      # .tar 파일 임시 저장소
├── .env                          # 환경변수 (gitignore)
├── .env.example                  # 환경변수 템플릿
└── package.json
```

---

## DB 테이블 설명

| 테이블 | 설명 |
|--------|------|
| `profiles` | 사용자 정보 (Supabase Auth 연동용) |
| `scan_jobs` | 스캔 작업 단위 관리 |
| `sbom_raw` | 이미지에서 추출한 CycloneDX SBOM |
| `trivy_results` | Trivy 전체 취약점 결과 |
| `grype_results` | Grype 전체 취약점 결과 |
| `grype_filtered` | Grype 결과 중 OS 패키지 취약점 |
| `application_filtered` | Trivy 결과 중 라이브러리 취약점 |
| `security_filtered` | Trivy 시크릿 탐지 결과 |
| `analysis_logs` | 스캔 단계별 진행 로그 |
