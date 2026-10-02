@echo off
rem Double-click to remove Edge, or pass switches such as -DryRun / -VerifyOnly.
rem Remove-Edge.ps1 handles elevation; read-only modes do not ask for UAC.
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Remove-Edge.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="4" (
    echo Work continues in the administrator PowerShell window.
) else (
    echo Finished with exit code %RC%.
    echo 0 = clean / dry run, 1 = remnants, 2 = prerequisites / elevation, 3 = error
)
pause
exit /b %RC%
