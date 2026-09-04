@echo off
chcp 65001 >nul
title GhostLink - Tamamen Kapat ve Durdur

echo ===============================================================
echo  👻 GhostLink DPI Bypass - Tamamen Kapatma ve Durdurma Araci
echo ===============================================================
echo.

:: Yonetici Yetkisi Kontrolu ve Otomatik Yetki Alma
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Yonetici yetkisi isteniyor...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [*] 1/4 GhostLink Sistem Servisi durduruluyor...
schtasks /End /TN GhostLinkService >nul 2>&1

echo [*] 2/4 Calisan GhostLink islemleri sonlandiriliyor...
taskkill /F /IM ghostlink_tray.exe >nul 2>&1
taskkill /F /IM ghostlink_daemon.exe >nul 2>&1
taskkill /F /IM winws.exe >nul 2>&1

echo [*] 3/4 DNS ayarlari temizleniyor ve varsayilana (DHCP) donduruluyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue }" >nul 2>&1
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp >nul 2>&1
netsh interface ipv4 set dnsservers name="Wi-Fi" source=dhcp >nul 2>&1
echo [*] Hosts dosyasindan GhostLink yonetilen blok temizleniyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$h = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; if (Test-Path $h) { $c = Get-Content $h; $out = New-Object System.Collections.Generic.List[string]; $skip=$false; foreach ($ln in $c) { $t=$ln.Trim(); if ($t -eq '# >>> GhostLink managed hosts (do not edit inside this block) >>>') { $skip=$true; continue }; if ($t -eq '# <<< GhostLink managed hosts <<<') { $skip=$false; continue }; if ($t -eq '# GhostLink Clean Hosts Mappings') { continue }; if (-not $skip) { if ($t -match '^(162\.159\.|34\.126\.226\.51|51\.159\.197\.136)\s' -and $t -match 'discord|wikileaks') { continue }; $out.Add($ln) } }; Set-Content -Path $h -Value $out -Encoding ascii }" >nul 2>&1

echo [*] 4/4 DNS onbellegi temizleniyor...
ipconfig /flushdns >nul 2>&1

echo.
echo ===============================================================
echo  ✅ GhostLink BASARIYLA TAMAMEN DURDURULDU VE KAPATILDI
echo ===============================================================
echo.
echo  • GhostLink DPI motoru (winws.exe) kapatildi.
echo  • Arka plan servisi (ghostlink_daemon.exe) durduruldu.
echo  • Sistem tepsisi simgesi (ghostlink_tray.exe) kapatildi.
echo  • DNS ve ag ayarlari tamamen varsayilana donduruldu.
echo.
echo  GhostLink artik bilgisayarinizda arka planda calismiyor.
echo  Tekrar baslatmak istediginizde 'ghostlink_admin_setup.bat'
echo  dosyasini Yonetici olarak calistirabilirsiniz.
echo ===============================================================
echo.
pause
