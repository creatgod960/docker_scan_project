@echo off
chcp 65001 > nul
echo.
echo =====================================================
echo   DSP 초기 설치 (Windows)
echo =====================================================
echo.

:: ── Node.js 확인 ───────────────────────────────────────
echo [1/5] Node.js 확인...
node --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js 가 설치되어 있지 않습니다.
    echo         https://nodejs.org 에서 v22 이상 설치 후 다시 실행하세요.
    pause & exit /b 1
)
echo       Node.js:
node --version

:: ── Python 확인 ────────────────────────────────────────
echo.
echo [2/5] Python 확인...
python --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 이 설치되어 있지 않습니다.
    echo         https://python.org 에서 v3.10 이상 설치 후 다시 실행하세요.
    pause & exit /b 1
)
echo       Python:
python --version

:: ── Node.js 패키지 설치 ────────────────────────────────
echo.
echo [3/5] 서버 패키지 설치 중... (server/node_modules)
cd server
call npm install
if errorlevel 1 ( echo [ERROR] npm install 실패 & pause & exit /b 1 )
cd ..
echo       완료

:: ── Python 패키지 설치 ─────────────────────────────────
echo.
echo [4/5] Python 패키지 설치 중...
pip install fastapi uvicorn httpx python-multipart --quiet
if errorlevel 1 ( echo [ERROR] pip install 실패 & pause & exit /b 1 )
echo       완료

:: ── .env 파일 확인 ─────────────────────────────────────
echo.
echo [5/5] 환경 설정 확인...
if not exist "server\.env" (
    copy "server\.env.example" "server\.env" > nul
    echo [WARNING] server\.env 가 없어 .env.example 을 복사했습니다.
    echo           SUPABASE_URL 과 SUPABASE_SERVICE_KEY 를 반드시 입력하세요!
) else (
    echo       server\.env 파일 확인됨
)

:: ── uploads 폴더 생성 ──────────────────────────────────
if not exist "server\uploads" mkdir "server\uploads"
echo       uploads 폴더 확인됨

echo.
echo =====================================================
echo   설치 완료!
echo.
echo   다음 단계:
echo   1. server\.env 에 Supabase 키 입력
echo   2. Redis 실행 확인 (redis-cli ping → PONG)
echo   3. start.bat 실행
echo =====================================================
echo.
pause
