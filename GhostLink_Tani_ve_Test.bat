@echo off
chcp 65001 >nul
title GhostLink - Sistem Tani ve Test Araci

echo ===================================================================
echo   GhostLink - 1-Click Sistem Tani, Test ve Dogrulama Araci
echo ===================================================================
echo.

set "BIN_DIR=C:\ProgramData\GhostLink\bin"
if not exist "%BIN_DIR%\ghostlink_cli.exe" (
    if exist "%~dp0bin\ghostlink_cli.exe" (
        set "BIN_DIR=%~dp0bin"
    ) else if exist "%~dp0src-tauri\target\release\ghostlink_cli.exe" (
        set "BIN_DIR=%~dp0src-tauri\target\release"
    )
)

echo [1/4] GhostLink Surec ve Servis Durumu:
echo -------------------------------------------------------------------
"%BIN_DIR%\ghostlink_cli.exe" status
echo.

echo [2/4] Aktif Windows Surecleri:
tasklist /FI "IMAGENAME eq ghostlink_daemon.exe" /NH 2>nul | findstr /I "ghostlink_daemon.exe" >nul && echo   * ghostlink_daemon.exe: [AKTIF] || echo   * ghostlink_daemon.exe: [KAPALI]
tasklist /FI "IMAGENAME eq winws.exe" /NH 2>nul | findstr /I "winws.exe" >nul && echo   * winws.exe (DPI Motoru): [AKTIF] || echo   * winws.exe (DPI Motoru): [KAPALI]
tasklist /FI "IMAGENAME eq ghostlink_tray.exe" /NH 2>nul | findstr /I "ghostlink_tray.exe" >nul && echo   * ghostlink_tray.exe (Tepsi): [AKTIF] || echo   * ghostlink_tray.exe (Tepsi): [KAPALI]
echo.

echo [3/4] Ag ve DNS Yapilandirmasi:
echo -------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { $d = (Get-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ', '; Write-Host ('  * Adaptor: ' + $_.InterfaceAlias + ' -> DNS: ' + $d) }"
echo.

echo [4/4] Canli Discord, YouTube ve Web Erisim Dogrulamasi:
echo -------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ep = @(('Discord Web/API', 'https://discord.com'), ('Discord Gateway API', 'https://discord.com/api/v10/gateway'), ('Discord Media/Avatar CDN', 'https://cdn.discordapp.com/embed/avatars/0.png'), ('YouTube Web', 'https://www.youtube.com'), ('WikiLeaks', 'https://www.wikileaks.org')); foreach ($item in $ep) { try { $req = [System.Net.HttpWebRequest]::Create($item[1]); $req.Timeout = 6000; $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'; $res = $req.GetResponse(); Write-Host ('  [BASARILI] ' + $item[0] + ' (HTTP ' + [int]$res.StatusCode + ')') -ForegroundColor Green; $res.Close() } catch { Write-Host ('  [HATA] ' + $item[0] + ' (' + $_.Exception.Message + ')') -ForegroundColor Red } }"
echo.

echo ===================================================================
echo   Tani ve Test Tamamlandi!
echo ===================================================================
echo.
pause
