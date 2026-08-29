use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const FLOWSEAL_VERSION: &str = "1.9.9c";
pub const FLOWSEAL_ZIP_URL: &str = "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.9.9c/zapret-discord-youtube-1.9.9c.zip";
pub const FLOWSEAL_ZIP_SHA256: &str = "6064e4b26ed7358961a0b978fbb6263b119d8d7a5a06bb4a6454aeb855cf63e9";

pub const TPWS_MACOS_ARM64_URL: &str = "https://raw.githubusercontent.com/by-sonic/unblock-pro/main/bin/darwin/tpws_arm64";
pub const TPWS_MACOS_X64_URL: &str = "https://raw.githubusercontent.com/by-sonic/unblock-pro/main/bin/darwin/tpws_x64";
pub const TPWS_MACOS_UNIVERSAL_URL: &str = "https://raw.githubusercontent.com/by-sonic/unblock-pro/main/bin/darwin/tpws";

pub struct BinaryManager {
    bin_dir: PathBuf,
}

impl BinaryManager {
    pub fn new(base_dir: &Path) -> Self {
        let platform_sub = if cfg!(target_os = "macos") {
            "darwin"
        } else if cfg!(target_os = "windows") {
            "win32"
        } else {
            "linux"
        };
        Self {
            bin_dir: base_dir.join("bin").join(platform_sub),
        }
    }

    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// Returns the main executable path (tpws on macOS, winws.exe on Windows).
    pub fn get_executable_path(&self) -> PathBuf {
        if cfg!(target_os = "windows") {
            self.bin_dir.join("winws.exe")
        } else {
            self.bin_dir.join("tpws")
        }
    }

    /// Checks if required binaries exist on disk.
    pub fn is_installed(&self) -> bool {
        let exe = self.get_executable_path();
        if !exe.exists() {
            return false;
        }

        #[cfg(target_os = "windows")]
        {
            let divert_dll = self.bin_dir.join("WinDivert.dll");
            let divert_sys = self.bin_dir.join("WinDivert64.sys");
            if !divert_dll.exists() || !divert_sys.exists() {
                return false;
            }
        }

        true
    }

    /// Ensures that the platform binaries are present and executable.
    pub async fn ensure_binaries(&self) -> Result<PathBuf> {
        fs::create_dir_all(&self.bin_dir)
            .with_context(|| format!("Failed to create bin directory: {:?}", self.bin_dir))?;

        if self.is_installed() {
            #[cfg(unix)]
            self.set_executable_permissions(&self.get_executable_path())?;

            return Ok(self.get_executable_path());
        }

        println!("📦 Downloading verified binary dependencies...");

        #[cfg(target_os = "macos")]
        {
            self.download_macos_tpws().await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.download_windows_bundle().await?;
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            return Err(anyhow!("Unsupported OS for automatic binary provisioning"));
        }

        let exe = self.get_executable_path();
        if !exe.exists() {
            return Err(anyhow!("Binary executable not found after provisioning: {:?}", exe));
        }

        #[cfg(unix)]
        self.set_executable_permissions(&exe)?;

        Ok(exe)
    }

    #[cfg(unix)]
    fn set_executable_permissions(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    async fn download_macos_tpws(&self) -> Result<()> {
        let arch = std::env::consts::ARCH;
        let url = match arch {
            "aarch64" => TPWS_MACOS_ARM64_URL,
            "x86_64" => TPWS_MACOS_X64_URL,
            _ => TPWS_MACOS_UNIVERSAL_URL,
        };

        let target_path = self.get_executable_path();
        println!("⬇️  Downloading tpws ({}) from {}...", arch, url);

        let response = reqwest::get(url).await
            .with_context(|| format!("Failed to download tpws from {}", url))?;

        if !response.status().is_success() {
            // Fallback to universal binary
            println!("⚠️ Specific arch binary not found, trying universal tpws...");
            let fallback_resp = reqwest::get(TPWS_MACOS_UNIVERSAL_URL).await?;
            if !fallback_resp.status().is_success() {
                return Err(anyhow!("HTTP error downloading tpws: {}", fallback_resp.status()));
            }
            let bytes = fallback_resp.bytes().await?;
            fs::write(&target_path, bytes)?;
        } else {
            let bytes = response.bytes().await?;
            fs::write(&target_path, bytes)?;
        }

        #[cfg(unix)]
        self.set_executable_permissions(&target_path)?;

        println!("✅ tpws installed to {:?}", target_path);
        Ok(())
    }

    async fn download_windows_bundle(&self) -> Result<()> {
        println!("⬇️  Downloading Flowseal {} bundle from {}...", FLOWSEAL_VERSION, FLOWSEAL_ZIP_URL);
        let response = reqwest::get(FLOWSEAL_ZIP_URL).await
            .with_context(|| format!("Failed to download Flowseal zip from {}", FLOWSEAL_ZIP_URL))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error downloading Flowseal bundle: {}", response.status()));
        }

        let bytes = response.bytes().await?;

        // Verify SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());

        if hash.to_lowercase() != FLOWSEAL_ZIP_SHA256.to_lowercase() {
            return Err(anyhow!(
                "SHA-256 mismatch for Flowseal bundle! Expected {}, got {}",
                FLOWSEAL_ZIP_SHA256,
                hash
            ));
        }

        println!("🔒 SHA-256 verified successfully ({})", hash);

        // Extract required files from zip in-memory
        let reader = io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| anyhow!("Failed to read zip archive: {}", e))?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_name = match file.enclosed_name() {
                Some(p) => p.to_owned(),
                None => continue,
            };

            // Extract files in zapret-winws folder or root files like winws.exe, WinDivert*
            let name_str = file_name.to_string_lossy();
            if name_str.ends_with(".exe") || name_str.ends_with(".dll") || name_str.ends_with(".sys") || name_str.ends_with(".bin") {
                let base_name = file_name.file_name().unwrap();
                let outpath = self.bin_dir.join(base_name);
                let mut outfile = File::create(&outpath)?;
                io::copy(&mut file, &mut outfile)?;
            }
        }

        println!("✅ Windows Flowseal bundle extracted to {:?}", self.bin_dir);
        Ok(())
    }
}
