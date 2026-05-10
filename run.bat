@echo off
REM One-shot launcher (Windows wrapper). See launch.py for full options.
setlocal

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo Python 3.10+ is required but no python interpreter was found on PATH.
        echo Install Python from https://www.python.org/downloads/ and try again.
        exit /b 1
    )
    set PY=py -3
) else (
    set PY=python
)

%PY% "%~dp0launch.py" %*
