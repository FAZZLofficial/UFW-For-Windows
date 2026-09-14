@echo off
setlocal
echo Compiling UFW Setup EXE...
set "ISCC_PATH=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" (
    echo [ERROR] Inno Setup compiler (ISCC.exe) not found.
    pause
    exit /b 1
)
"%ISCC_PATH%" "%~dp0installer.iss"
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] Setup created inside .\dist\ folder.
) else (
    echo [ERROR] Build failed!
)
pause
