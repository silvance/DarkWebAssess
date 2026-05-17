@echo off
REM DarkWebAssess one-stop Windows shim.
REM
REM Always runs `python -m app.main <args>` against the project's venv,
REM so you can't accidentally hit the system Python (which is what causes
REM "ModuleNotFoundError: No module named 'bs4'" and friends).
REM
REM Usage:
REM     dwa sync-config
REM     dwa collect
REM     dwa user create alice analyst
REM     dwa dashboard           (alias: launches the Streamlit UI)
REM     dwa tray                (system-tray launcher)
REM     dwa setup               (one-shot: venv + deps + init-db)
REM
REM If the venv doesn't exist yet, falls back to launch.py which will
REM create it for you.

setlocal
set "ROOT=%~dp0"
set "VENV_PY=%ROOT%.venv\Scripts\python.exe"

REM Special-case sub-shells that aren't `app.main` subcommands.
if /I "%~1"=="dashboard" goto :launch_dashboard
if /I "%~1"=="tray"      goto :launch_tray
if /I "%~1"=="setup"     goto :launch_setup
if /I "%~1"=="update"    goto :launch_setup

if exist "%VENV_PY%" (
    "%VENV_PY%" -m app.main %*
    set "RC=%ERRORLEVEL%"
) else (
    echo [dwa] No venv found at %VENV_PY%
    echo [dwa] Running first-time setup via launch.py ...
    call "%ROOT%run.bat" setup
    set "RC=%ERRORLEVEL%"
    if "%RC%"=="0" (
        if exist "%VENV_PY%" (
            "%VENV_PY%" -m app.main %*
            set "RC=%ERRORLEVEL%"
        )
    )
)
exit /b %RC%

:launch_dashboard
call "%ROOT%run.bat" dashboard
exit /b %ERRORLEVEL%

:launch_tray
if exist "%VENV_PY%" (
    "%VENV_PY%" -m app.entry tray
) else (
    call "%ROOT%run.bat" tray
)
exit /b %ERRORLEVEL%

:launch_setup
call "%ROOT%run.bat" setup
exit /b %ERRORLEVEL%
