-- ============================================================
--  DSP 교차 분석 스키마 추가 (schema.sql 이후 실행)
--
--  Supabase SQL Editor → 붙여넣기 → Run
-- ============================================================

-- ── scan_reports (Grype·Trivy 교차 분석 요약) ────────────────
CREATE TABLE IF NOT EXISTS scan_reports (
  id               UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_job_id      UUID         NOT NULL REFERENCES scan_jobs(scan_job_id) ON DELETE CASCADE,
  -- 집계 카운트
  total_count      INT          NOT NULL DEFAULT 0,  -- 전체 고유 취약점 (Grype ∪ Trivy)
  common_count     INT          NOT NULL DEFAULT 0,  -- 두 도구가 모두 탐지
  grype_only_count INT          NOT NULL DEFAULT 0,  -- Grype만 탐지
  trivy_only_count INT          NOT NULL DEFAULT 0,  -- Trivy만 탐지
  mismatch_count   INT          NOT NULL DEFAULT 0,  -- 같은 CVE, 심각도 불일치
  -- 상세 목록 (JSONB)
  grype_only_detail  JSONB,   -- grype_only 취약점 배열
  trivy_only_detail  JSONB,   -- trivy_only 취약점 배열
  mismatch_detail    JSONB,   -- mismatch 취약점 배열 (grype_severity + trivy_severity)
  severity_counts    JSONB,   -- count_by_severity() 결과 (분류별 심각도 분포)
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sr_job_id ON scan_reports (scan_job_id);
