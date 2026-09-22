@ECHO off
REM ---------------------------------------------------------------------------
REM  safe-launch.cmd  —  用这个启动 Pi（Safe Mode Layer 1）
REM
REM  先跑外部 bootstrap 做完整性校验 / 自动恢复镜像，通过后才启动 Pi。
REM  参数会原样转发给 pi.cmd。
REM
REM  校验失败时**不启动** Pi（exit 2）。若只想看报告（不修复、不写日志、不改任何文件）：
REM      powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -VerifyOnly
REM  想从规范副本恢复镜像（不带参数即默认行为）：
REM      powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -Fix
REM
REM  注意：本文件位于 D:\pi-agent\safe-mode\ 下，所以 Pi 的路径是 ..\current\pi.cmd
REM ---------------------------------------------------------------------------
SETLOCAL

SET "SAFE_HOME=%~dp0"
SET "SAFE_ROOT=%~dp0.."
SET "BOOTSTRAP=%SAFE_HOME%safe-bootstrap.ps1"
SET "PI_CMD=%SAFE_ROOT%\current\pi.cmd"

IF NOT EXIST "%BOOTSTRAP%" (
  ECHO [safe-launch] bootstrap script not found: "%BOOTSTRAP%"
  EXIT /B 2
)
IF NOT EXIST "%PI_CMD%" (
  ECHO [safe-launch] pi launcher not found: "%PI_CMD%"
  EXIT /B 2
)

REM 启动前校验 + 修复镜像（写 safe-integrity.log），失败则不启动 Pi
powershell -NoProfile -ExecutionPolicy Bypass -File "%BOOTSTRAP%"
IF ERRORLEVEL 1 (
  ECHO.
  ECHO [safe-launch] Safe Mode integrity check FAILED - Pi was NOT started.
  ECHO [safe-launch] Fix the items above, or run with -Force for a one-off diagnostic start.
  EXIT /B 2
)

"%PI_CMD%" %*
EXIT /B %ERRORLEVEL%
