@echo off
chcp 65001 >nul
title Seep Reverse Lab - 一键无损更新 (Updater)
echo.
echo ================================================================================
echo          Seep Reverse Lab — 工作台一键更新程序 (双击运行)
echo ================================================================================
echo.
echo 正在启动 Seep 工作台增量更新...
echo （自动保护 models.json、auth.json 与自定义 MCP 配置，绝不覆盖个人数据）
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\update.ps1"
echo.
echo ================================================================================
echo 更新执行完毕。
echo 按任意键关闭窗口...
pause >nul
