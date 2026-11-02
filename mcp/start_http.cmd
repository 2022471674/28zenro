@echo off
rem ============================================================
rem cipherNest MCP - HTTP（streamable-http）模式启动脚本
rem
rem 用途：给「HTTP 连接器 / 远程客户端」用。stdio 模式不需要本脚本，
rem       宿主会自己拉起 server.py。
rem
rem 用法：双击本文件，或在终端执行 start_http.cmd [端口]
rem       Ctrl+C 停止服务
rem ============================================================
setlocal
cd /d "%~dp0"

set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

title cipherNest MCP (http://127.0.0.1:%PORT%/mcp)
echo.
echo   cipherNest MCP  HTTP 模式
echo   端点: http://127.0.0.1:%PORT%/mcp
echo   停止: Ctrl+C
echo.

python server.py --http --host 127.0.0.1 --port %PORT%

echo.
echo 服务已退出（退出码 %ERRORLEVEL%）。
pause
