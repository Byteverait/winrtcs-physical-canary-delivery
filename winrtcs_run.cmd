@echo off
rem WINRTCS_RUN
rem Task entry. Starts the agent. Does not embed a bearer and does not fetch secrets.
set "ZD=C:\ProgramData\WinRTCS"
if exist "%ZD%\winrtcs_agent.cmd" call "%ZD%\winrtcs_agent.cmd"
exit /b 0
