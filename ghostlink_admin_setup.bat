@echo off
:: GhostLink - 24/7 Service & Tray Administrator Setup
:: Right-click this file and select "Run as administrator"

echo ========================================================
echo   GhostLink - 24/7 Service Setup (Run as Admin)
echo ========================================================
echo.

:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] HATA: Bu dosya Yonetici olarak calistirilmalidir!
    echo [!] Lutfen dosyaya sag tiklayip 'Yonetici olarak calistir' secenegini secin.
    echo.
    pause
    exit /b 1
)

echo [*] Gecmis gorevler, islemler ve kilitli Discord surecleri durduruluyor...
schtasks /End /TN GhostLinkService >nul 2>&1
taskkill /F /IM ghostlink_tray.exe >nul 2>&1
taskkill /F /IM ghostlink_daemon.exe >nul 2>&1
taskkill /F /IM winws.exe >nul 2>&1
taskkill /F /IM Discord.exe >nul 2>&1
taskkill /F /IM Update.exe >nul 2>&1

echo [*] Dizinler hazirlaniyor: C:\ProgramData\GhostLink
if not exist "C:\ProgramData\GhostLink\bin" mkdir "C:\ProgramData\GhostLink\bin"
if not exist "C:\ProgramData\GhostLink\lists" mkdir "C:\ProgramData\GhostLink\lists"
if not exist "C:\ProgramData\GhostLink\logs" mkdir "C:\ProgramData\GhostLink\logs"

echo [*] En son surum ikilileri kopyalaniyor...
copy /Y "%~dp0src-tauri\target\release\ghostlink_daemon.exe" "C:\ProgramData\GhostLink\bin\ghostlink_daemon.exe"
copy /Y "%~dp0src-tauri\target\release\ghostlink_tray.exe" "C:\ProgramData\GhostLink\bin\ghostlink_tray.exe"
copy /Y "%~dp0src-tauri\target\release\ghostlink_cli.exe" "C:\ProgramData\GhostLink\bin\ghostlink_cli.exe"

echo [*] GhostLink 24/7 Sistem Servisi kaydediliyor (SYSTEM Yetkisi)...
schtasks /Create /TN GhostLinkService /TR "C:\ProgramData\GhostLink\bin\ghostlink_daemon.exe" /RL HIGHEST /SC ONSTART /RU "SYSTEM" /F

echo [*] Servis guvenilirlik ayarlari yapilandiriliyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t = Get-ScheduledTask -TaskName 'GhostLinkService'; $t.Settings.DisallowStartIfOnBatteries = $false; $t.Settings.StopIfGoingOnBatteries = $false; $t.Settings.ExecutionTimeLimit = 'PT0S'; $t.Settings.RestartCount = 999; $t.Settings.RestartInterval = 'PT1M'; $t.Settings.StartWhenAvailable = $true; Set-ScheduledTask -InputObject $t" >nul 2>&1

echo [*] DNS zehirlenmesine karsi temiz IP eslemeleri yapilandiriliyor (hosts)...
findstr /C:"discord.com" "%WINDIR%\System32\drivers\etc\hosts" >nul 2>&1
if %errorlevel% neq 0 (
    echo.>> "%WINDIR%\System32\drivers\etc\hosts"
    echo # GhostLink Clean Hosts Mappings>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discord.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discord.gg>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discordapp.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discordapp.net>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discord.media>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 discordcdn.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 gateway.discord.gg>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 cdn.discordapp.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 media.discordapp.net>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 status.discord.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 latency.discord.media>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 router.discordapp.net>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 fingerprint.discord.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 remote-auth-gateway.discord.gg>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 51.159.197.136 wikileaks.org>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 51.159.197.136 www.wikileaks.org>> "%WINDIR%\System32\drivers\etc\hosts"
)

echo [*] Windows 11 Guvenli Sifreli DNS (Cloudflare DoH) yapilandiriliyor...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -AutoUpgrade `$true -ErrorAction SilentlyContinue; Set-DnsClientDohServerAddress -ServerAddress '1.0.0.1' -AutoUpgrade `$true -ErrorAction SilentlyContinue; Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' } | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias `$_.InterfaceAlias -ServerAddresses ('1.1.1.1', '1.0.0.1') -ErrorAction SilentlyContinue }" >nul 2>&1
ipconfig /flushdns >nul 2>&1

echo [*] Varsayilan strateji [win-general] seciliyor...
echo win-general> "C:\ProgramData\GhostLink\selected_strategy.txt"
if not exist "%USERPROFILE%\.ghostlink" mkdir "%USERPROFILE%\.ghostlink"
echo win-general> "%USERPROFILE%\.ghostlink\selected_strategy.txt"

echo [*] GhostLink Servisi baslatiliyor...
schtasks /Run /TN GhostLinkService

echo [*] Baslangic kaydi yapiliyor (Sistem Tepsisi)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "GhostLink" /t REG_SZ /d "\"C:\ProgramData\GhostLink\bin\ghostlink_tray.exe\"" /f >nul 2>&1

echo [*] Sistem Tepsisi (ghostlink_tray.exe) baslatiliyor...
start "" "C:\ProgramData\GhostLink\bin\ghostlink_tray.exe"

timeout /t 3 /nobreak >nul

echo.
echo ========================================================
echo   GhostLink 24/7 Servisi ve Tepsisi Basariyla Kuruldu!
echo ========================================================
echo   * Arka Plan Servisi: AKTIF (SYSTEM yetkisiyle 7/24 calisir)
echo   * Sistem Tepsisi: Saatin yaninda simgesi gorunur
echo.
pause
