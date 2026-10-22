@echo off
rem WINRTCS_SENTINEL
rem Same repair as Guard. A partial cache set is left untouched.
set "CACHE=C:\ProgramData\Microsoft\WinRTCS\cache"
if not exist "%CACHE%\winrtcs_gen_commit.ps1" exit /b 0
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CACHE%\winrtcs_gen_commit.ps1" -Repair
exit /b 0
