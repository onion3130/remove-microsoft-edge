@echo off
rem Double-click to remove Edge, or pass switches such as -DryRun / -VerifyOnly.
rem Remove-Edge.ps1 handles elevation; read-only modes do not ask for UAC.
setlocal

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=powershell.exe"
if not exist "%~dp0Remove-Edge.ps1" (
    echo Could not find "%~dp0Remove-Edge.ps1".
    echo Run this from the folder where you extracted the repository.
    pause
    exit /b 3
)

rem %* forwards the switches you typed. Remove-Edge.ps1 accepts switches only,
rem so nothing here can be turned into a command.
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Remove-Edge.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="4" (
    echo Work continues in the administrator PowerShell window.
    echo The report in that window is the real result.
) else (
    echo Finished with exit code %RC%.
    echo 0 = clean / dry run, 1 = remnants, 2 = prerequisites / elevation, 3 = error
)
pause
exit /b %RC%