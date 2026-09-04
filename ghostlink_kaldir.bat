@echo off
chcp 65001 >nul
title GhostLink - Tamamen Kaldir

echo ===============================================================
echo  GhostLink DPI Bypass - Kaldirma Araci
echo ===============================================================
echo.

:: Yonetici Yetkisi Kontrolu ve Otomatik Yetki Alma
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Yonetici yetkisi isteniyor...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [*] GhostLink islemleri durduruluyor...
schtasks /End /TN GhostLinkService >nul 2>&1
taskkill /F /IM ghostlink_tray.exe >nul 2>&1
taskkill /F /IM ghostlink_daemon.exe >nul 2>&1
taskkill /F /IM winws.exe >nul 2>&1

echo [*] Zamanlanmis gorev siliniyor...
schtasks /Delete /TN GhostLinkService /F >nul 2>&1

echo [*] Baslangic kaydi siliniyor...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "GhostLink" /f >nul 2>&1

echo [*] DNS ayarlari varsayilana donduruluyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue }" >nul 2>&1
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp >nul 2>&1
netsh interface ipv4 set dnsservers name="Wi-Fi" source=dhcp >nul 2>&1

echo [*] DNS onbellegi temizleniyor...
ipconfig /flushdns >nul 2>&1

echo [*] Hosts dosyasindan GhostLink yonetilen blok temizleniyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; if (Test-Path $h) { $c = Get-Content $h; $out = New-Object System.Collections.Generic.List[string]; $skip=$false; foreach ($ln in $c) { $t=$ln.Trim(); if ($t -eq '# >>> GhostLink managed hosts (do not edit inside this block) >>>') { $skip=$true; continue }; if ($t -eq '# <<< GhostLink managed hosts <<<') { $skip=$false; continue }; if ($t -eq '# GhostLink Clean Hosts Mappings') { continue }; if (-not $skip) { if ($t -match '^(162\.159\.|34\.126\.226\.51|51\.159\.197\.136)\s' -and $t -match 'discord|wikileaks') { continue }; $out.Add($ln) } }; Set-Content -Path $h -Value $out -Encoding ascii }" >nul 2>&1

echo [*] Dosyalar siliniyor...
rmdir /S /Q "C:\ProgramData\GhostLink" >nul 2>&1
rmdir /S /Q "%USERPROFILE%\.ghostlink" >nul 2>&1

echo.
echo ===============================================================
echo  ✅ GhostLink BASARIYLA KALDIRILDI
echo ===============================================================
echo.
pause
