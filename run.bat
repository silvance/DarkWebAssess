@echo off
REM One-shot launcher (Windows wrapper). See launch.py for full options.
setlocal

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo.
        echo Python 3.10 or later is required but no python interpreter was found on PATH.
        echo Install Python from https://www.python.org/downloads/ ^(check "Add to PATH"^)
        echo and run this script again.
        echo.
        pause
        exit /b 1
    )
    set "PY=py -3"
) else (
    set "PY=python"
)

%PY% "%~dp0launch.py" %*
set "RC=%ERRORLEVEL%"

REM Keep the console open on failure so a double-click user can read the error.
if not "%RC%"=="0" (
    echo.
    echo [run.bat] launch.py exited with code %RC%.
    echo %cmdcmdline% | find /I "/c" >nul && pause
)
exit /b %RC%
