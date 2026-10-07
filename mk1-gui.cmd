@echo off
setlocal
cd /d "%~dp0"
where wsl.exe >nul 2>nul
if errorlevel 1 (
    echo Windows launcher requires WSL with a Linux distribution, bash, a C compiler, and ncurses development files.
    exit /b 1
)
for /f "delims=" %%P in ('wsl.exe wslpath -u "%CD%" 2^>nul') do set "MK1_WSL_DIR=%%P"
if not defined MK1_WSL_DIR (
    echo Could not translate the current directory into the WSL filesystem.
    exit /b 1
)
wsl.exe --cd "%MK1_WSL_DIR%" bash ./mk1-panel.sh
exit /b %errorlevel%
