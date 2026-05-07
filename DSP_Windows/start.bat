@echo off
chcp 65001 > nul
echo.
echo =====================================================
echo   DSP API Server (Windows)
echo =====================================================
echo.

:: uploads 폴더 확인
if not exist "server\uploads" mkdir "server\uploads"

:: Redis 확인
redis-cli ping > nul 2>&1
if errorlevel 1 (
    echo [WARNING] Redis 가 실행 중이지 않습니다.
    echo           Redis 를 먼저 시작하세요: redis-server
    echo           Windows 서비스로 설치된 경우: net start Redis
    echo.
)

echo 3개 창을 엽니다:
echo   - API 서버        http://localhost:3000
echo   - 스캔 워커       백그라운드 스캔 처리
echo   - Python 스캐너   http://localhost:8000
echo.
timeout /t 2 > nul

:: API 서버 (새 창, 프로덕션 모드)
start "DSP API Server" cmd /k "cd /d %~dp0server && npm start"

:: 스캔 워커 (새 창)
start "DSP Scan Worker" cmd /k "cd /d %~dp0server && npm run worker"

:: Python 스캐너 (새 창)
start "DSP Python Scanner" cmd /k "cd /d %~dp0 && uvicorn python.scanner:app --host 0.0.0.0 --port 8000"

echo.
echo DSP 시작 완료
echo 웹 UI    : http://localhost:3000
echo 헬스체크 : http://localhost:3000/health
echo.
echo 종료하려면 kill-ports.bat 을 실행하세요.
pause
