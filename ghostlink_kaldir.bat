@echo off
chcp 65001 >nul
title GhostLink - Tamamen Kaldir

echo ===============================================================
echo  GhostLink DPI Bypass - Kaldirma Araci
echo ===============================================================
echo.

:: Yonetici Yetkisi Kontrolu
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] HATA: Bu islemi gerceklestirmek icin Yonetici Yetkisi gereklidir.
    echo [*] Lutfen bu dosyaya SAG TIKLAYIP "Yonetici olarak calistir" secenegini secin.
    echo.
    pause
    exit /b 1
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

echo [*] Hosts dosyasindan GhostLink satirlari temizleniyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; $c = Get-Content $h; $out = $c | Where-Object { $_ -notmatch 'GhostLink' -and $_ -notmatch '162.159.138.232' -and $_ -notmatch '51.159.197.136' }; Set-Content -Path $h -Value $out -Encoding ascii" >nul 2>&1

echo [*] Dosyalar siliniyor...
rmdir /S /Q "C:\ProgramData\GhostLink" >nul 2>&1
rmdir /S /Q "%USERPROFILE%\.ghostlink" >nul 2>&1

echo.
echo ===============================================================
echo  ✅ GhostLink BASARIYLA KALDIRILDI
echo ===============================================================
echo.
pause
