@echo off
chcp 65001 >nul
title "GhostLink - Sistem Tani, Test & Otomatik Strateji Bulucu"

:: Self-elevation to administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Yonetici yetkisi isteniyor...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================================
echo   👻 GhostLink - 1-Click Sistem Tani, Test ve Otomatik Ayarlayici
echo ===================================================================
echo.

set "BIN_DIR=C:ProgramDataGhostLinkin"
if not exist "%BIN_DIR%\ghostlink_cli.exe" (
    if exist "%~dp0bin\ghostlink_cli.exe" (
        set "BIN_DIR=%~dp0bin"
    ) else if exist "%~dp0src-tauri\target\release\ghostlink_cli.exe" (
        set "BIN_DIR=%~dp0src-tauri\target\release"
    )
)

echo [1/5] GhostLink Surec ve Servis Durumu:
echo -------------------------------------------------------------------
"%BIN_DIR%\ghostlink_cli.exe" status
echo.

echo [2/5] Aktif Windows Surecleri:
tasklist /FI "IMAGENAME eq ghostlink_daemon.exe" /NH 2>nul | findstr /I "ghostlink_daemon.exe" >nul && echo   * ghostlink_daemon.exe: [AKTIF] || echo   * ghostlink_daemon.exe: [KAPALI]
tasklist /FI "IMAGENAME eq winws.exe" /NH 2>nul | findstr /I "winws.exe" >nul && echo   * winws.exe (DPI Motoru): [AKTIF] || echo   * winws.exe (DPI Motoru): [KAPALI]
tasklist /FI "IMAGENAME eq ghostlink_tray.exe" /NH 2>nul | findstr /I "ghostlink_tray.exe" >nul && echo   * ghostlink_tray.exe (Tepsi): [AKTIF] || echo   * ghostlink_tray.exe (Tepsi): [KAPALI]
echo.

echo [3/5] Ag ve DNS Yapilandirmasi:
echo -------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { $dns = (Get-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -AddressFamily IPv4).ServerAddresses -join ', '; Write-Host ('  * Adaptor: ' + $_.InterfaceAlias + ' (' + $_.InterfaceDescription + ') -> DNS: ' + $dns) }"
echo.

echo [4/5] Canli Internet Saglayici Otomatik Strateji Taramasi (AutoTune)...
echo       (Tum bypass stratejileri Discord ve YouTube uzerinde test ediliyor)
echo -------------------------------------------------------------------
"%BIN_DIR%\ghostlink_cli.exe" autotune
echo.

echo [5/5] Canli Discord ve YouTube Baglanti Dogrulamasi:
echo -------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "$test = { param($name, $url) try { $r = [System.Net.WebRequest]::Create($url); $r.Timeout = 5000; $resp = $r.GetResponse(); Write-Host ('  * ' + $name + ': [BASARILI] (HTTP ' + [int]$resp.StatusCode + ')') -ForegroundColor Green; $resp.Close() } catch { Write-Host ('  * ' + $name + ': [HATA] (' + $_.Exception.Message + ')') -ForegroundColor Red } }; &$test 'Discord Web/API' 'https://discord.com'; &$test 'Discord Gateway' 'https://gateway.discord.gg'; &$test 'Discord Updates' 'https://updates.discord.com'; &$test 'YouTube Video CDN' 'https://googlevideo.com'; &$test 'WikiLeaks' 'https://wikileaks.org'"
echo.

echo ===================================================================
echo   Tani ve Test Tamamlandi!
echo ===================================================================
echo.
pause
