import subprocess
import json
import os
import uuid
import asyncio
import sys
import requests
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, Request

app = FastAPI()

TOOL_SYFT  = os.environ.get("SYFT_PATH",  "syft")
TOOL_GRYPE = os.environ.get("GRYPE_PATH", "grype")
TOOL_TRIVY = os.environ.get("TRIVY_PATH", "trivy")

WORK_DIR = os.environ.get("SCANNER_WORK_DIR", os.path.abspath("."))
os.makedirs(WORK_DIR, exist_ok=True)

API_SERVER_URL    = os.environ.get("API_SERVER_URL", "http://localhost:3000")
API_SAVE_ENDPOINT = f"{API_SERVER_URL}/save"
API_TIMEOUT       = 30

CLEANUP_IMAGE_FILE = os.environ.get("CLEANUP_IMAGE_FILE", "true").lower() == "true"

# DB CHECK 제약이 허용하는 5개 표준 심각도 값
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def normalize_severity(sev) -> str:
    """
    도구별로 다양한 심각도 값을 DB CHECK 제약이 허용하는 5개 표준값으로 정규화합니다.
    예) None / "" / "Negligible" / "negligible" → "UNKNOWN"
    """
    if not sev:
        return "UNKNOWN"
    s = str(sev).strip().upper()
    if s in ALLOWED_SEVERITIES:
        return s
    return "UNKNOWN"


# ── 유틸리티 ─────────────────────────────────────────────────────────────────

def work_path(filename: str) -> str:
    return os.path.join(WORK_DIR, filename)


def log(msg: str) -> None:
    print(msg, flush=True)
    sys.stdout.flush()


async def save_upload_chunked(upload: UploadFile, dest: str, chunk_size: int = 1024 * 1024) -> None:
    with open(dest, "wb") as out:
        while True:
            chunk = await upload.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)


async def run_tool(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        ),
    )


async def ensure_trivy_db() -> bool:
    log("[*] Trivy DB 상태 확인 중...")
    res = await run_tool([TOOL_TRIVY, "image", "--download-db-only"], timeout=1800)
    if res.returncode == 0:
        log("[+] Trivy DB 준비 완료")
        return True
    log(f"[!] Trivy DB 업데이트 실패: {res.stderr[:300]}")
    return False


async def send_to_api_server(payload: dict, endpoint: str = None) -> bool:
    if endpoint is None:
        endpoint = API_SAVE_ENDPOINT
    try:
        log(f"[*] API 서버로 결과 전송 중: {endpoint}")
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(endpoint, json=payload, timeout=API_TIMEOUT),
        )
        if response.status_code in [200, 201]:
            log(f"[+] API 서버 전송 성공 (상태: {response.status_code})")
            return True
        log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
        return False
    except requests.exceptions.Timeout:
        log(f"[!] API 서버 요청 타임아웃 ({API_TIMEOUT}초)")
        return False
    except requests.exceptions.ConnectionError:
        log(f"[!] API 서버 연결 실패: {endpoint}")
        return False
    except Exception as e:
        log(f"[!] API 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        return False


async def send_all_files_to_api(payload: dict, json_files: dict, endpoint: str = None) -> bool:
    if endpoint is None:
        endpoint = API_SAVE_ENDPOINT
    try:
        log(f"[*] API 서버로 모든 파일 전송 중: {endpoint}")
        files = {}
        for file_name, file_path in json_files.items():
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    file_content = f.read()
                files[file_name] = (file_name, file_content, "application/json")
                log(f"  [준비] {file_name}: {len(file_content) / 1024:.1f} KB")
            else:
                log(f"  [경고] 파일 없음: {file_path}")
        data = {"payload": json.dumps(payload)}
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: requests.post(endpoint, files=files, data=data, timeout=API_TIMEOUT * 2),
        )
        if response.status_code in [200, 201]:
            log(f"[+] API 서버 전송 성공 (상태: {response.status_code})")
            return True
        log(f"[!] API 서버 전송 실패 (상태: {response.status_code}): {response.text[:300]}")
        return False
    except Exception as e:
        log(f"[!] 파일 전송 중 예외 발생: {type(e).__name__}: {str(e)[:300]}")
        return False


# ── 데이터 처리 함수 ──────────────────────────────────────────────────────────

def filter_results(grype_data: dict, trivy_data: dict) -> dict:
    """
    Grype + Trivy 원시 결과를 grype_only / trivy_only / mismatch 로 분류합니다.
    필드명은 DB 컬럼명과 일치하며, normalize_severity()로 심각도를 표준화합니다.
    NOT NULL 필드(vulnerability_id, package_name, rule_id) 누락 시 해당 항목을 건너뜁니다.
    """
    grype_vulns: dict = {}
    trivy_vulns: dict = {}
    processed = {"grype_only": [], "trivy_only": [], "mismatch": [], "secrets": []}

    # ── Grype 결과 파싱 ──────────────────────────────────────────────────────
    for match in grype_data.get("matches", []):
        vuln     = match.get("vulnerability", {})
        art      = match.get("artifact", {})
        related  = match.get("relatedVulnerabilities", [])

        vuln_id  = vuln.get("id")
        pkg_name = art.get("name")

        # NOT NULL 필수 필드 검증
        if not vuln_id or not pkg_name:
            continue

        cvss      = vuln.get("cvss", [])
        risk      = cvss[0].get("metrics", {}).get("baseScore", "N/A") if cvss else "N/A"
        fix_info  = vuln.get("fix", {})
        fix_state = fix_info.get("state", "not-fixed")
        fix_ver   = ", ".join(fix_info.get("versions", []))
        if not fix_ver.strip():
            fix_ver = None

        grype_vulns[vuln_id] = {
            "source":                   "grype",
            "vulnerability_id":         vuln_id,          # DB 컬럼명 일치
            "data_source":              vuln.get("dataSource"),
            "description":              vuln.get("description"),
            "fix_version":              fix_ver,
            "state":                    fix_state,
            "is_fixed_available":       fix_state == "fixed",
            "artifact_id":              art.get("id"),
            "package_name":             pkg_name,
            "package_type":             art.get("type"),
            "install_path":             art.get("locations", [{}])[0].get("realPath")
                                        if art.get("locations") else None,
            "severity":                 normalize_severity(vuln.get("severity")),
            "risk":                     risk,
            "version":                  art.get("version"),
            "related_vulnerability_id": related[0].get("id") if related else None,
        }

    # ── Trivy 결과 파싱 ──────────────────────────────────────────────────────
    if "Results" in trivy_data:
        for result in trivy_data["Results"]:
            target    = result.get("Target")
            res_class = result.get("Class")
            res_type  = result.get("Type")

            for v in result.get("Vulnerabilities") or []:
                vuln_id  = v.get("VulnerabilityID")
                pkg_name = v.get("PkgName")

                if not vuln_id or not pkg_name:
                    continue

                fixed_ver = v.get("FixedVersion")
                if fixed_ver is not None and not str(fixed_ver).strip():
                    fixed_ver = None

                trivy_vulns[vuln_id] = {
                    "source":            "trivy",
                    "target":            target,
                    "result_class":      res_class,
                    "result_type":       res_type,
                    "vulnerability_id":  vuln_id,          # DB 컬럼명 일치
                    "package_name":      pkg_name,
                    "package_path":      v.get("PkgPath"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version":     fixed_ver,
                    "is_fixed_available": bool(fixed_ver),
                    "severity":          normalize_severity(v.get("Severity")),
                    "primary_url":       v.get("PrimaryURL"),
                    "title":             v.get("Title"),
                    "description":       v.get("Description"),
                }

            for s in result.get("Secrets") or []:
                rule_id = s.get("RuleID")
                if not rule_id:
                    continue
                processed["secrets"].append({
                    "title":        s.get("Title"),
                    "rule_id":      rule_id,
                    "severity":     normalize_severity(s.get("Severity")),
                    "match_text":   s.get("Match"),
                    "category":     s.get("Category"),
                    "layer_digest": s.get("Layer", {}).get("Digest"),
                    "diff_id":      s.get("Layer", {}).get("DiffID"),
                    "created_by":   s.get("Layer", {}).get("CreatedBy"),
                })

    # ── 분류 ─────────────────────────────────────────────────────────────────
    grype_ids      = set(grype_vulns.keys())
    trivy_ids      = set(trivy_vulns.keys())
    grype_only_ids = grype_ids - trivy_ids
    trivy_only_ids = trivy_ids - grype_ids
    common_ids     = grype_ids & trivy_ids

    for vid in grype_only_ids:
        processed["grype_only"].append(grype_vulns[vid])

    for vid in trivy_only_ids:
        processed["trivy_only"].append(trivy_vulns[vid])

    for vid in common_ids:
        g_sev = grype_vulns[vid].get("severity", "UNKNOWN")
        t_sev = trivy_vulns[vid].get("severity", "UNKNOWN")
        if g_sev != t_sev:
            entry = grype_vulns[vid].copy()
            entry["grype_severity"] = g_sev
            entry["trivy_severity"] = t_sev
            entry["trivy_data"]     = trivy_vulns[vid]
            processed["mismatch"].append(entry)

    processed["grype_vulnerabilities"] = list(grype_vulns.values())
    processed["trivy_vulnerabilities"] = list(trivy_vulns.values())
    processed["vulnerabilities"] = (
        processed["grype_only"] + processed["trivy_only"] + processed["mismatch"]
    )
    return processed


def count_by_severity(filtered_data: dict) -> dict:
    severity_counts = {
        "grype_only":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "trivy_only":     {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "mismatch":       {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "common_matched": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
    }

    def _bump(category: str, sev: str) -> None:
        if sev in severity_counts[category]:
            severity_counts[category][sev] += 1
        else:
            severity_counts[category]["UNKNOWN"] += 1

    for v in filtered_data.get("grype_only", []):
        _bump("grype_only", normalize_severity(v.get("severity")))

    for v in filtered_data.get("trivy_only", []):
        _bump("trivy_only", normalize_severity(v.get("severity")))

    for v in filtered_data.get("mismatch", []):
        _bump("mismatch", normalize_severity(v.get("severity")))

    grype_sev_map = {
        (v.get("vulnerability_id") or "").strip().upper(): normalize_severity(v.get("severity"))
        for v in filtered_data.get("grype_vulnerabilities", [])
        if v.get("vulnerability_id")
    }
    trivy_sev_map = {
        (v.get("vulnerability_id") or "").strip().upper(): normalize_severity(v.get("severity"))
        for v in filtered_data.get("trivy_vulnerabilities", [])
        if v.get("vulnerability_id")
    }
    for vid in set(grype_sev_map) & set(trivy_sev_map):
        if grype_sev_map[vid] == trivy_sev_map[vid]:
            _bump("common_matched", grype_sev_map[vid])

    return severity_counts


def build_scan_report(
    filtered_data: dict,
    scan_job_id,
    user_id: str,
    image_tag: str,
    report_path=None,
) -> dict:
    grype_map: dict[str, str] = {}
    trivy_map: dict[str, str] = {}

    for v in filtered_data.get("grype_vulnerabilities", []):
        vid = (v.get("vulnerability_id") or "").strip().upper()
        if vid:
            grype_map.setdefault(vid, normalize_severity(v.get("severity")))

    for v in filtered_data.get("trivy_vulnerabilities", []):
        vid = (v.get("vulnerability_id") or "").strip().upper()
        if vid:
            trivy_map.setdefault(vid, normalize_severity(v.get("severity")))

    grype_ids    = set(grype_map.keys())
    trivy_ids    = set(trivy_map.keys())
    common_ids   = grype_ids & trivy_ids
    mismatch_ids = {vid for vid in common_ids if grype_map[vid] != trivy_map[vid]}

    return {
        "id":             str(uuid.uuid4()),
        "user_id":        user_id,
        "scan_job_id":    scan_job_id,
        "image_tag":      image_tag,
        "total_count":    len(grype_ids | trivy_ids),
        "common_count":   len(common_ids),
        "grype_only":     len(grype_ids - trivy_ids),
        "trivy_only":     len(trivy_ids - grype_ids),
        "mismatch_count": len(mismatch_ids),
        "report_path":    report_path,
        "created_at":     datetime.now(timezone.utc).isoformat(),
    }


def _dump(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


# ── /health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "DSP Python Scanner"}


# ── /analyze  (교차 분석 전용 — Node.js 워커에서 호출) ───────────────────────
# 이미 실행된 Trivy/Grype 원시 JSON을 받아 filter_results + build_scan_report 만 수행합니다.
# 스캔 재실행이 없으므로 빠르고 중복이 없습니다.

@app.post("/analyze")
async def analyze_endpoint(request: Request):
    """
    요청 body (JSON):
      {
        "job_id":     "<jobId>",
        "image_name": "<filename>",
        "trivy":      { ...Trivy 원시 JSON... },
        "grype":      { ...Grype 원시 JSON... }
      }
    """
    body       = await request.json()
    grype_raw  = body.get("grype", {})
    trivy_raw  = body.get("trivy", {})
    job_id     = body.get("job_id", "unknown")
    image_name = body.get("image_name", "")

    filtered_data   = filter_results(grype_raw, trivy_data=trivy_raw)
    severity_counts = count_by_severity(filtered_data)
    scan_report     = build_scan_report(
        filtered_data=filtered_data,
        scan_job_id=job_id,
        user_id=job_id,
        image_tag=image_name,
    )

    log(
        f"[Analyze] job={job_id} | "
        f"grype_only={scan_report['grype_only']} | "
        f"trivy_only={scan_report['trivy_only']} | "
        f"mismatch={scan_report['mismatch_count']}"
    )

    return {
        "scan_report":     scan_report,
        "filtered_data":   filtered_data,
        "severity_counts": severity_counts,
    }


# ── /scan  (풀 스캔 — Syft + Grype + Trivy 직접 실행) ────────────────────────

@app.post("/scan")
async def custom_scan_endpoint(
    user_id:   str        = Form(...),
    scan_name: str        = Form(...),
    file:      UploadFile = File(...),
):
    safe_uid       = user_id.replace("/", "_").replace("\\", "_")
    image_path     = work_path(f"temp_{safe_uid}_{file.filename}")
    syft_raw_file  = work_path(f"syft_{safe_uid}.json")
    trivy_raw_file = work_path(f"trivy_{safe_uid}.json")
    grype_raw_file = work_path(f"grype_{safe_uid}.json")
    files_to_cleanup = [image_path]

    trivy_status = "pending"
    grype_status = "pending"
    started_at   = datetime.now(timezone.utc).isoformat()

    try:
        log(f"[*] 파일 저장 중 → {image_path}")
        await save_upload_chunked(file, image_path)
        size_mb = os.path.getsize(image_path) / (1024 * 1024)
        log(f"[+] 파일 저장 완료: {size_mb:.1f} MB")

        # Syft
        log(f"[*] Syft 실행 중 (사용자: {user_id})...")
        syft_res = await run_tool([TOOL_SYFT, image_path, "-o", "cyclonedx-json"])
        if syft_res.returncode == 0 and syft_res.stdout:
            syft_raw = json.loads(syft_res.stdout)
            _dump(syft_raw_file, syft_raw)
            log(f"[+] Syft 완료: {len(syft_raw.get('components', []))} 컴포넌트")
        else:
            syft_raw = {}
            log(f"[!] Syft 실패 (returncode={syft_res.returncode}): {syft_res.stderr[:300]}")

        # Grype
        log("[*] Grype 실행 중...")
        grype_res = await run_tool([TOOL_GRYPE, image_path, "-o", "json"])
        if grype_res.returncode == 0 and grype_res.stdout:
            grype_raw    = json.loads(grype_res.stdout)
            grype_status = "completed"
            _dump(grype_raw_file, grype_raw)
            log(f"[+] Grype 완료: {len(grype_raw.get('matches', []))} 매칭")
        else:
            grype_raw    = {}
            grype_status = "failed"
            log(f"[!] Grype 실패 (returncode={grype_res.returncode}): {grype_res.stderr[:300]}")

        # Trivy
        await ensure_trivy_db()
        log("[*] Trivy 실행 중...")
        trivy_res = await run_tool([
            TOOL_TRIVY, "image",
            "--input", image_path,
            "--format", "json",
            "--scanners", "vuln,secret",
        ])
        if trivy_res.returncode == 0 and trivy_res.stdout:
            trivy_raw    = json.loads(trivy_res.stdout)
            trivy_status = "completed"
            _dump(trivy_raw_file, trivy_raw)
            log(f"[+] Trivy 완료: {len(trivy_raw.get('Results', []))} 결과 블록")
        else:
            trivy_raw    = {}
            trivy_status = "failed"
            log(f"[!] Trivy 실패 (returncode={trivy_res.returncode}): {trivy_res.stderr[:300]}")

        # 교차 분석
        filtered_data   = filter_results(grype_raw, trivy_data=trivy_raw)
        severity_counts = count_by_severity(filtered_data)
        finished_at     = datetime.now(timezone.utc).isoformat()
        scan_report     = build_scan_report(
            filtered_data=filtered_data,
            scan_job_id=None,
            user_id=user_id,
            image_tag=file.filename,
        )

        all_vuln_ids: set = set()
        for v in filtered_data.get("grype_vulnerabilities", []):
            if v.get("vulnerability_id"):
                all_vuln_ids.add(v["vulnerability_id"])
        for v in filtered_data.get("trivy_vulnerabilities", []):
            if v.get("vulnerability_id"):
                all_vuln_ids.add(v["vulnerability_id"])

        def _total_sev(sev_key):
            return sum(severity_counts[cat].get(sev_key, 0) for cat in severity_counts)

        # overall_status 결정
        if grype_status == "failed" and trivy_status == "failed":
            overall_status = "failed"
        elif grype_status == "completed" or trivy_status == "completed":
            overall_status = "completed"
        else:
            overall_status = "failed"

        final_payload = {
            "scan_job": {
                "user_id":               user_id,
                "scan_name":             scan_name,
                "file_name":             file.filename,
                "file_type":             "image_tar",
                "image_name":            file.filename,
                "status":                overall_status,
                "grype_status":          grype_status,
                "trivy_status":          trivy_status,
                "started_at":            started_at,
                "finished_at":           finished_at,
                "total_vulnerabilities": len(all_vuln_ids),
                "critical_count":        _total_sev("CRITICAL"),
                "high_count":            _total_sev("HIGH"),
                "medium_count":          _total_sev("MEDIUM"),
                "low_count":             _total_sev("LOW"),
                "unknown_count":         _total_sev("UNKNOWN"),
                "severity_counts":       severity_counts,
            },
            "scan_report":   scan_report,
            "filtered_data": filtered_data,
        }

        # Node.js /save 로 전송 (실패해도 계속 진행)
        _dump(work_path(f"result_scan_report_{safe_uid}.json"), scan_report)
        _dump(work_path(f"result_grype_vulnerabilities_{safe_uid}.json"), filtered_data["grype_vulnerabilities"])
        _dump(work_path(f"result_trivy_vulnerabilities_{safe_uid}.json"), filtered_data["trivy_vulnerabilities"])
        _dump(work_path(f"result_secrets_{safe_uid}.json"), filtered_data["secrets"])
        _dump(work_path(f"result_cross_analysis_{safe_uid}.json"), {
            "grype_only": filtered_data["grype_only"],
            "trivy_only": filtered_data["trivy_only"],
            "mismatch":   filtered_data["mismatch"],
        })

        json_files_to_send = {
            "syft.json":                         syft_raw_file,
            "grype.json":                        grype_raw_file,
            "trivy.json":                        trivy_raw_file,
            "result_scan_report.json":           work_path(f"result_scan_report_{safe_uid}.json"),
            "result_grype_vulnerabilities.json": work_path(f"result_grype_vulnerabilities_{safe_uid}.json"),
            "result_trivy_vulnerabilities.json": work_path(f"result_trivy_vulnerabilities_{safe_uid}.json"),
            "result_secrets.json":               work_path(f"result_secrets_{safe_uid}.json"),
            "result_cross_analysis.json":        work_path(f"result_cross_analysis_{safe_uid}.json"),
        }
        await send_all_files_to_api(final_payload, json_files_to_send)

        log(
            f"[+] 스캔 완료. 전체 고유 취약점: {len(all_vuln_ids)} / "
            f"시크릿: {len(filtered_data['secrets'])}"
        )
        return final_payload

    except Exception as e:
        log(f"[!] 예외 발생: {type(e).__name__}: {str(e)[:500]}")
        error_payload = {
            "scan_job": {
                "user_id":       user_id,
                "scan_name":     scan_name,
                "file_name":     file.filename,
                "file_type":     "image_tar",
                "status":        "failed",
                "error_message": str(e)[:500],
                "started_at":    started_at,
                "finished_at":   datetime.now(timezone.utc).isoformat(),
            }
        }
        await send_to_api_server(error_payload)
        return {"status": "Error", "detail": str(e)}

    finally:
        if CLEANUP_IMAGE_FILE:
            for f_path in files_to_cleanup:
                try:
                    if os.path.exists(f_path):
                        os.remove(f_path)
                        log(f"  [삭제] {f_path}")
                except Exception as cleanup_err:
                    log(f"  [삭제실패] {f_path}: {cleanup_err}")


# ── 서버 진입점 ───────────────────────────────────────────────────────────────
# 실행: uvicorn python.scanner:app --port 8000  (프로젝트 루트에서)
#       또는: python python/scanner.py

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
