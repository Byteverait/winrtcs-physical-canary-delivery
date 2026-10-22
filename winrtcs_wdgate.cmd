@echo off
rem WINRTCS_WDGATE
rem The commit gate starts this file only after the watchdog hash matches.
rem This file does not read the manifest and does not decide trust.
set "ZD=C:\ProgramData\WinRTCS"
if not exist "%ZD%\winrtcs_watchdog.cmd" exit /b 4
call "%ZD%\winrtcs_watchdog.cmd"
exit /b %ERRORLEVEL%
