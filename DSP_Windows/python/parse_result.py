#!/usr/bin/env python3
"""
DSP Python 분석 및 정리 도구
====================================
Trivy / Grype JSON 출력을 읽어 대시보드용으로 정제한다.

사용:
  python parse_result.py --tool trivy  --input result.json
  python parse_result.py --tool grype  --input result.json
  python parse_result.py --tool trivy  --input result.json --translate  # 설명 한국어 번역 (DeepL/Papago API 키 필요)

출력: JSON (stdout)  →  Node.js Worker가 파이프로 읽는다.
"""

import argparse
import json
import sys
from typing import Any


# ── 심각도 가중치 (도넛 그래프 색상 매핑용) ─────────────────
SEVERITY_ORDER = {
    "CRITICAL": 5, "Critical": 5,
    "HIGH": 4,     "High": 4,
    "MEDIUM": 3,   "Medium": 3,
    "LOW": 2,      "Low": 2,
    "NEGLIGIBLE": 1, "Negligible": 1,
    "UNKNOWN": 0,  "Unknown": 0,
}

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626", "Critical": "#dc2626",
    "HIGH":     "#ea580c", "High":     "#ea580c",
    "MEDIUM":   "#ca8a04", "Medium":   "#ca8a04",
    "LOW":      "#16a34a", "Low":      "#16a34a",
    "NEGLIGIBLE":"#6b7280","Negligible":"#6b7280",
    "UNKNOWN":  "#9ca3af", "Unknown":  "#9ca3af",
}


# ════════════════════════════════════════════════════════════
#  Trivy 파서
# ════════════════════════════════════════════════════════════
def parse_trivy(raw: dict) -> dict:
    vulnerabilities: list[dict] = []
    secrets: list[dict] = []
    layers: list[dict] = []

    for result in raw.get("Results", []):
        target = result.get("Target", "")

        # 취약점
        for v in result.get("Vulnerabilities") or []:
            vulnerabilities.append({
                "target":           target,
                "vulnerabilityId":  v.get("VulnerabilityID"),
                "pkgName":          v.get("PkgName"),
                "pkgPath":          v.get("PkgPath"),
                "installedVersion": v.get("InstalledVersion"),
                "fixedVersion":     v.get("FixedVersion"),
                "severity":         v.get("Severity", "UNKNOWN"),
                "title":            v.get("Title"),
                "description":      v.get("Description"),
                "primaryURL":       v.get("PrimaryURL"),
                "cvssV3Score":      (v.get("CVSS") or {}).get("nvd", {}).get("V3Score"),
                "publishedDate":    v.get("PublishedDate"),
                "layerDigest":      (v.get("Layer") or {}).get("Digest"),
                "layerDiffID":      (v.get("Layer") or {}).get("DiffID"),
                "color":            SEVERITY_COLOR.get(v.get("Severity", "UNKNOWN"), "#9ca3af"),
            })

        # 시크릿
        for s in result.get("Secrets") or []:
            secrets.append({
                "target":     target,
                "ruleId":     s.get("RuleID"),
                "category":   s.get("Category"),
                "severity":   s.get("Severity", "HIGH"),
                "match":      s.get("Match"),
                "startLine":  s.get("StartLine"),
                "endLine":    s.get("EndLine"),
                "layerDigest":  (s.get("Layer") or {}).get("Digest"),
                "layerDiffID":  (s.get("Layer") or {}).get("DiffID"),
            })

    # 레이어 (ImageConfig.history)
    meta = raw.get("Metadata", {})
    for h in (meta.get("ImageConfig") or {}).get("history") or []:
        layers.append({
            "createdBy": h.get("created_by") or h.get("CreatedBy"),
            "empty":     h.get("empty_layer", False),
        })

    # ── 심각도별 집계 ─────────────────────────────────────
    severity_count: dict[str, int] = {}
    for v in vulnerabilities:
        sev = v["severity"]
        severity_count[sev] = severity_count.get(sev, 0) + 1

    # ── 도넛 그래프용 데이터 ──────────────────────────────
    donut_chart = [
        {"label": sev, "value": cnt, "color": SEVERITY_COLOR.get(sev, "#9ca3af")}
        for sev, cnt in sorted(severity_count.items(), key=lambda x: -SEVERITY_ORDER.get(x[0], 0))
    ]

    # ── 상위 위험 패키지 (심각도 기준 top-20) ─────────────
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: -SEVERITY_ORDER.get(v["severity"], 0),
    )

    return {
        "tool":            "trivy",
        "imageName":       raw.get("ArtifactName"),
        "imageDigest":     meta.get("ImageID"),
        "os":              f"{(meta.get('OS') or {}).get('Family','')} {(meta.get('OS') or {}).get('Name','')}".strip() or None,
        "vulnerabilities": sorted_vulns,
        "secrets":         secrets,
        "layers":          layers,
        "summary": {
            "total":    len(vulnerabilities),
            "severity": severity_count,
            "secrets":  len(secrets),
        },
        "charts": {
            "severityDonut": donut_chart,
        },
        "topRisks": sorted_vulns[:20],
    }


# ════════════════════════════════════════════════════════════
#  Grype 파서
# ════════════════════════════════════════════════════════════
def parse_grype(raw: dict) -> dict:
    vulnerabilities: list[dict] = []

    for match in raw.get("matches", []):
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related  = match.get("relatedVulnerabilities", [])

        sev = vuln.get("severity", "Unknown")
        vulnerabilities.append({
            "vulnerabilityId":  vuln.get("id"),
            "dataSource":       vuln.get("dataSource"),
            "severity":         sev,
            "description":      vuln.get("description"),
            "fix":              ", ".join(vuln.get("fix", {}).get("versions") or []),
            "state":            vuln.get("fix", {}).get("state", "unknown"),
            # Grype 전용
            "epssScore":        (vuln.get("epss") or [{}])[0].get("epss"),
            "epssPercentile":   (vuln.get("epss") or [{}])[0].get("percentile"),
            "riskScore":        vuln.get("riskScore"),
            "kevIncluded":      bool((vuln.get("cisa") or {}).get("kev")),
            # 패키지
            "artifactId":       artifact.get("id"),
            "name":             artifact.get("name"),
            "type":             artifact.get("type"),
            "installedVersion": artifact.get("version"),
            "pkgPath":          (artifact.get("locations") or [{}])[0].get("path"),
            "layerDigest":      (artifact.get("locations") or [{}])[0].get("layerID"),
            "relatedIds":       [r.get("id") for r in related],
            "color":            SEVERITY_COLOR.get(sev, "#9ca3af"),
        })

    # 심각도별 집계
    severity_count: dict[str, int] = {}
    for v in vulnerabilities:
        sev = v["severity"]
        severity_count[sev] = severity_count.get(sev, 0) + 1

    donut_chart = [
        {"label": sev, "value": cnt, "color": SEVERITY_COLOR.get(sev, "#9ca3af")}
        for sev, cnt in sorted(severity_count.items(), key=lambda x: -SEVERITY_ORDER.get(x[0], 0))
    ]

    # EPSS 기준 정렬 (Grype 전용 우선순위)
    sorted_by_epss = sorted(
        vulnerabilities,
        key=lambda v: (-(v["epssScore"] or 0), -SEVERITY_ORDER.get(v["severity"], 0)),
    )

    # KEV 목록
    kev_list = [v for v in vulnerabilities if v["kevIncluded"]]

    return {
        "tool":            "grype",
        "imageName":       (raw.get("source") or {}).get("target", {}).get("imageID"),
        "vulnerabilities": sorted_by_epss,
        "summary": {
            "total":    len(vulnerabilities),
            "severity": severity_count,
            "kev":      len(kev_list),
        },
        "charts": {
            "severityDonut": donut_chart,
        },
        "topRisks":  sorted_by_epss[:20],
        "kevList":   kev_list,
    }


# ════════════════════════════════════════════════════════════
#  메인
# ════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="DSP 결과 파서")
    parser.add_argument("--tool",  required=True, choices=["trivy", "grype"])
    parser.add_argument("--input", required=True, help="스캔 결과 JSON 파일 경로")
    parser.add_argument("--translate", action="store_true",
                        help="description을 한국어로 번역 (API 키 필요, 미구현 stub)")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as f:
            raw: dict[str, Any] = json.load(f)
    except FileNotFoundError:
        print(json.dumps({"error": f"파일을 찾을 수 없습니다: {args.input}"}))
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"JSON 파싱 실패: {e}"}))
        sys.exit(1)

    if args.tool == "trivy":
        result = parse_trivy(raw)
    else:
        result = parse_grype(raw)

    # TODO: --translate 옵션 시 DeepL / Papago API 호출
    if args.translate:
        result["_translateNote"] = "번역 기능은 API 키 설정 후 활성화됩니다."

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
