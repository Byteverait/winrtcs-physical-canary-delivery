@echo off
rem WINRTCS_GUARD
rem Repairs only by asking the generation commit to publish the already-verified cache set.
rem Does not delete the live agent.
set "CACHE=C:\ProgramData\Microsoft\WinRTCS\cache"
if not exist "%CACHE%\winrtcs_gen_commit.ps1" exit /b 0
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CACHE%\winrtcs_gen_commit.ps1" -Repair
exit /b 0
