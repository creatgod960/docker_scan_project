-- ============================================================
--  DSP DB 스키마  (PostgreSQL / Supabase)
--
--  사용법: Supabase 대시보드 → SQL Editor → 전체 붙여넣기 후 실행
--  순서: 위에서 아래로 순서대로 실행됨 (FK 의존성 고려)
-- ============================================================

-- ── 1. profiles (사용자 정보) ─────────────────────────────
--   Supabase Auth 사용 시 auth.users.id 를 PK로 사용
CREATE TABLE IF NOT EXISTS profiles (
  id          UUID         NOT NULL PRIMARY KEY,   -- auth.users.id 와 동일
  username    TEXT,
  email       TEXT,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── 2. scan_jobs (스캔 작업 단위) ─────────────────────────
CREATE TABLE IF NOT EXISTS scan_jobs (
  scan_job_id   UUID         NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID         REFERENCES profiles(id) ON DELETE SET NULL,  -- 로그인 시 연동
  original_name VARCHAR(512) NOT NULL,             -- 업로드 원본 파일명
  saved_name    VARCHAR(512) NOT NULL,             -- 서버 저장 파일명
  tool          VARCHAR(8)   NOT NULL DEFAULT 'trivy'
                             CHECK (tool IN ('trivy','grype','both')),
  status        VARCHAR(8)   NOT NULL DEFAULT 'queued'
                             CHECK (status IN ('queued','running','done','failed')),
  error_msg     TEXT,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- updated_at 자동 갱신 트리거
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_scan_jobs_updated_at ON scan_jobs;
CREATE TRIGGER set_scan_jobs_updated_at
  BEFORE UPDATE ON scan_jobs
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── 3. sbom_raw (이미지에서 추출한 SBOM 원데이터) ─────────
CREATE TABLE IF NOT EXISTS sbom_raw (
  id           BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id  UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  tool         VARCHAR(16)  NOT NULL CHECK (tool IN ('trivy','grype')),
  format       VARCHAR(32)  NOT NULL DEFAULT 'cyclonedx',  -- cyclonedx | spdx
  content      JSONB        NOT NULL,                      -- 원시 SBOM JSON
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sbom_job_id ON sbom_raw (scan_job_id);

-- ── 4. trivy_results (SBOM 기준 Trivy 전체 취약점) ────────
CREATE TABLE IF NOT EXISTS trivy_results (
  id                BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id       UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  target            VARCHAR(512),                          -- 스캔 대상 경로
  target_type       VARCHAR(64),                           -- npm/pip/ubuntu/alpine 등
  vulnerability_id  VARCHAR(64)  NOT NULL,                 -- CVE-xxxx / GHSA-xxxx
  pkg_name          VARCHAR(255) NOT NULL,
  pkg_path          TEXT,
  installed_version VARCHAR(128),
  fixed_version     VARCHAR(128),
  severity          VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN'
                                 CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
  cvss_v3_score     NUMERIC(4,1),
  title             TEXT,
  primary_url       TEXT,
  layer_digest      VARCHAR(128),
  layer_diff_id     VARCHAR(128),
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tr_job_id    ON trivy_results (scan_job_id);
CREATE INDEX IF NOT EXISTS idx_tr_severity  ON trivy_results (severity);
CREATE INDEX IF NOT EXISTS idx_tr_vuln_id   ON trivy_results (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_tr_type      ON trivy_results (target_type);

-- ── 5. grype_results (SBOM 기준 Grype 전체 취약점) ────────
CREATE TABLE IF NOT EXISTS grype_results (
  id                BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id       UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  vulnerability_id  VARCHAR(64)  NOT NULL,
  data_source       TEXT,
  severity          VARCHAR(32)  NOT NULL DEFAULT 'Unknown',
  description       TEXT,
  fix_versions      VARCHAR(512),
  fix_state         VARCHAR(32),                           -- fixed/not-fixed/wont-fix/unknown
  -- Grype 전용
  epss_score        NUMERIC(6,5),                          -- 30일 내 악용 확률 (0~1)
  epss_percentile   NUMERIC(6,5),
  risk_score        NUMERIC(4,1),                          -- 복합 위험도 (0~10)
  kev_included      BOOLEAN      NOT NULL DEFAULT FALSE,   -- CISA KEV 등재
  -- 패키지 정보
  artifact_id       VARCHAR(128),
  pkg_name          VARCHAR(255) NOT NULL,
  pkg_type          VARCHAR(64),                           -- deb/rpm/apk/npm/pip 등
  installed_version VARCHAR(128),
  pkg_path          TEXT,
  layer_digest      VARCHAR(128),
  related_ids       TEXT,                                  -- 관련 CVE (쉼표 구분)
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gr_job_id   ON grype_results (scan_job_id);
CREATE INDEX IF NOT EXISTS idx_gr_severity ON grype_results (severity);
CREATE INDEX IF NOT EXISTS idx_gr_vuln_id  ON grype_results (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_gr_kev      ON grype_results (kev_included);
CREATE INDEX IF NOT EXISTS idx_gr_type     ON grype_results (pkg_type);

-- ── 6. grype_filtered (Grype 결과 중 OS 취약점) ───────────
CREATE TABLE IF NOT EXISTS grype_filtered (
  id               BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id      UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  grype_id         BIGINT       REFERENCES grype_results(id) ON DELETE SET NULL,
  vulnerability_id VARCHAR(64)  NOT NULL,
  pkg_name         VARCHAR(255) NOT NULL,
  pkg_type         VARCHAR(64),                            -- deb/rpm/apk/alpm 등
  installed_version VARCHAR(128),
  severity         VARCHAR(32)  NOT NULL DEFAULT 'Unknown',
  kev_included     BOOLEAN      NOT NULL DEFAULT FALSE,
  epss_score       NUMERIC(6,5),
  risk_score       NUMERIC(4,1),
  fix_versions     VARCHAR(512),
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gf_job_id ON grype_filtered (scan_job_id);

-- ── 7. application_filtered (Trivy 결과 중 라이브러리 취약점)
CREATE TABLE IF NOT EXISTS application_filtered (
  id                BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id       UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  trivy_id          BIGINT       REFERENCES trivy_results(id) ON DELETE SET NULL,
  vulnerability_id  VARCHAR(64)  NOT NULL,
  pkg_name          VARCHAR(255) NOT NULL,
  pkg_type          VARCHAR(64),                           -- npm/pip/gem/cargo/go 등
  installed_version VARCHAR(128),
  fixed_version     VARCHAR(128),
  severity          VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN'
                                 CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
  cvss_v3_score     NUMERIC(4,1),
  primary_url       TEXT,
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_af_job_id ON application_filtered (scan_job_id);

-- ── 8. security_filtered (Trivy Secret / 보안 위협) ────────
CREATE TABLE IF NOT EXISTS security_filtered (
  id            BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id   UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  target        VARCHAR(512),                              -- 탐지된 파일 경로
  rule_id       VARCHAR(128) NOT NULL,                    -- private-key / jwt-token 등
  category      VARCHAR(128),
  severity      VARCHAR(16)  NOT NULL DEFAULT 'HIGH'
                             CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
  match_masked  TEXT,                                      -- 마스킹된 탐지 내용
  start_line    INT,
  end_line      INT,
  layer_digest  VARCHAR(128),
  layer_diff_id VARCHAR(128),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sf_job_id ON security_filtered (scan_job_id);

-- ── 9. analysis_logs (스캔 진행 로그) ─────────────────────
CREATE TABLE IF NOT EXISTS analysis_logs (
  id           BIGINT       NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_job_id  UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  level        VARCHAR(8)   NOT NULL DEFAULT 'info'
                            CHECK (level IN ('info','warn','error')),
  message      TEXT         NOT NULL,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_al_job_id ON analysis_logs (scan_job_id);
