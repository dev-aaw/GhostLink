@echo off
:: GhostLink - 24/7 Service & Tray Administrator Setup
:: Right-click this file and select "Run as administrator"

echo ========================================================
echo   GhostLink - 24/7 Service Setup (Run as Admin)
echo ========================================================
echo.

:: Check for administrative privileges and self-elevate automatically
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Yonetici yetkisi isteniyor...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [*] Gecmis gorevler, islemler ve kilitli Discord surecleri durduruluyor...
schtasks /End /TN GhostLinkService >nul 2>&1
taskkill /F /IM ghostlink_tray.exe >nul 2>&1
taskkill /F /IM ghostlink_daemon.exe >nul 2>&1
taskkill /F /IM winws.exe >nul 2>&1
taskkill /F /IM Discord.exe >nul 2>&1
taskkill /F /IM Update.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo [*] Dizinler hazirlaniyor: C:\ProgramData\GhostLink
if not exist "C:\ProgramData\GhostLink\bin" mkdir "C:\ProgramData\GhostLink\bin"
if not exist "C:\ProgramData\GhostLink\lists" mkdir "C:\ProgramData\GhostLink\lists"
if not exist "C:\ProgramData\GhostLink\logs" mkdir "C:\ProgramData\GhostLink\logs"
echo [*] Dizin guvenlik izinleri ayarlaniyor (ACL kilitleme)...
icacls "C:\ProgramData\GhostLink" /inheritance:r /grant:r "SYSTEM":(OI)(CI)F /grant:r "Administrators":(OI)(CI)F /grant:r "Users":(OI)(CI)RX >nul 2>&1

set "BIN_SRC="
if exist "%~dp0bin\ghostlink_daemon.exe" (
    set "BIN_SRC=%~dp0bin"
) else if exist "%~dp0src-tauri\target\release\ghostlink_daemon.exe" (
    set "BIN_SRC=%~dp0src-tauri\target\release"
) else (
    echo [!] HATA: GhostLink calistirilabilir dosyalari bulunamadi!
    echo [*] Lutfen zip icindeki tum dosyalari bir klasore cikardiginizdan emin olun.
    pause
    exit /b 1
)

echo [*] En son surum ikilileri kopyalaniyor...
copy /Y "%BIN_SRC%\ghostlink_daemon.exe" "C:\ProgramData\GhostLink\bin\ghostlink_daemon.exe"
copy /Y "%BIN_SRC%\ghostlink_tray.exe" "C:\ProgramData\GhostLink\bin\ghostlink_tray.exe"
copy /Y "%BIN_SRC%\ghostlink_cli.exe" "C:\ProgramData\GhostLink\bin\ghostlink_cli.exe"

if exist "%~dp0bin\win32" (
    if not exist "C:\ProgramData\GhostLink\bin\win32" mkdir "C:\ProgramData\GhostLink\bin\win32"
    copy /Y "%~dp0bin\win32\*.*" "C:\ProgramData\GhostLink\bin\win32\" >nul 2>&1
)

if exist "%~dp0lists" (
    if not exist "C:\ProgramData\GhostLink\lists" mkdir "C:\ProgramData\GhostLink\lists"
    copy /Y "%~dp0lists\*.*" "C:\ProgramData\GhostLink\lists\" >nul 2>&1
)

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
    echo 162.159.138.232 updates.discord.com>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 dl2.discordapp.net>> "%WINDIR%\System32\drivers\etc\hosts"
    echo 162.159.138.232 stable.dl2.discordapp.net>> "%WINDIR%\System32\drivers\etc\hosts"
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

timeout /t 2 /nobreak >nul

:: Discord kurulu ise temizce baslat
if exist "%LOCALAPPDATA%\Discord\Update.exe" (
    echo [*] Discord temiz baglantiyla baslatiliyor...
    start "" "%LOCALAPPDATA%\Discord\Update.exe" --processStart Discord.exe
)

echo.
echo ========================================================
echo   GhostLink 24/7 Servisi ve Tepsisi Basariyla Kuruldu!
echo ========================================================
echo   * Arka Plan Servisi: AKTIF (SYSTEM yetkisiyle 7/24 calisir)
echo   * Sistem Tepsisi: Saatin yaninda simgesi gorunur
echo.
pause
