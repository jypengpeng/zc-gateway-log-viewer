@echo off
chcp 65001 >nul
echo 正在启动 AI 网关日志浏览器...
echo 启动后请在浏览器打开: http://127.0.0.1:8787
echo 关闭此窗口即停止服务。
echo.
python "%~dp0gateway_tool.py"
pause
