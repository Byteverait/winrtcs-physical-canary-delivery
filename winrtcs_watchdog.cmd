@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem WINRTCS_WATCHDOG
rem Checks the continuity script hash before Watch.
rem Does not authenticate, execute a control command, or mint credentials.
set "ZD=C:\ProgramData\WinRTCS"
set "EXPECT=66fc3ace86e26471283f3cd02ac7e306da9ef87153889b253dd7d8fed335a4f3"
set "SCRIPT=%ZD%\winrtcs_continuity.ps1"
if not exist "%SCRIPT%" (
  call :Reject continuity-missing
  exit /b 0
)
set "GOT="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%SCRIPT%" SHA256 2^>nul') do (
  set "_h=%%H"
  set "_h=!_h: =!"
  if not defined GOT if "!_h:~63,1!" NEQ "" if "!_h:~64,1!"=="" set "GOT=!_h!"
)
if /I not "!GOT!"=="%EXPECT%" (
  call :Reject continuity-hash
  exit /b 0
)
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%SCRIPT%" -Action Watch
exit /b %ERRORLEVEL%

:Reject
> "%ZD%\continuity-status.txt" echo task=continuity-preexec
>> "%ZD%\continuity-status.txt" echo watchdog=rejected
>> "%ZD%\continuity-status.txt" echo tick_unix=0
>> "%ZD%\continuity-status.txt" echo failure=%~1
exit /b 0
