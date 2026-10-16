@echo off
setlocal
chcp 65001 >nul
title Seep Reverse Lab - Verifier
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\verify.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
pause
exit /b %EXIT_CODE%
