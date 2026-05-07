@echo off
echo.
echo [Cleanup] Terminating Node.js, Python processes and clearing ports 3000, 8000...

:: Terminate processes by name
taskkill /f /im node.exe /t 2> nul
taskkill /f /im python.exe /t 2> nul

:: Find and terminate processes occupying specific ports
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000') do taskkill /f /pid %%a 2> nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000') do taskkill /f /pid %%a 2> nul

timeout /t 1 > nul
echo.
echo [Success] Cleanup complete. You can now run start.bat.
pause
