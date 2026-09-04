use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

pub const FLOWSEAL_VERSION: &str = "1.9.9c";
pub const FLOWSEAL_ZIP_URL: &str = "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.9.9c/zapret-discord-youtube-1.9.9c.zip";
pub const FLOWSEAL_ZIP_SHA256: &str = "6064e4b26ed7358961a0b978fbb6263b119d8d7a5a06bb4a6454aeb855cf63e9";

pub const ZAPRET_VERSION: &str = "v72.13";
pub const ZAPRET_MACOS_ZIP_URL: &str = "https://github.com/bol-van/zapret/releases/download/v72.13/zapret-v72.13.zip";
pub const ZAPRET_MACOS_ZIP_SHA256: &str = "c493e33a0dc4eba23a8686efdaba55f59755ad6ade3564aebd9d13f4c65e2e0c";

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

        // An interrupted earlier download can leave a zero-byte or partial
        // `tpws` that exists() reports as present; ensure_binaries() would then
        // just chmod +x it and start() would spawn a binary that crashes on
        // launch, with no re-fetch. Treat an implausibly small file as absent.
        #[cfg(target_os = "macos")]
        {
            match fs::metadata(&exe) {
                Ok(meta) if meta.len() >= 4096 => {}
                _ => return false,
            }
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

            // Portable install: integrity-check the pre-shipped binaries against the
            // bundled manifest if one is present. Warn-only — a drifted hash must
            // not brick a working install, but it should be visible in the log.
            self.verify_shipped_checksums();

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

    /// Verify pre-shipped binaries against `checksums.sha256` in the bin dir, if it
    /// exists. Lines are `<sha256hex>  <filename>` (sha256sum format). Logs a
    /// warning on any mismatch or missing file; never fails.
    fn verify_shipped_checksums(&self) {
        let manifest = self.bin_dir.join("checksums.sha256");
        let Ok(text) = fs::read_to_string(&manifest) else {
            return;
        };

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(expected), Some(name)) = (parts.next(), parts.next()) else {
                continue;
            };
            // `sha256sum` binary mode prefixes the name with '*'.
            let name = name.trim_start_matches('*');
            let path = self.bin_dir.join(name);
            let actual = match fs::read(&path) {
                Ok(bytes) => {
                    let mut h = Sha256::new();
                    h.update(&bytes);
                    hex::encode(h.finalize())
                }
                Err(_) => {
                    eprintln!("⚠️ [integrity] shipped binary missing: {}", name);
                    continue;
                }
            };
            if !actual.eq_ignore_ascii_case(expected) {
                eprintln!(
                    "⚠️ [integrity] checksum mismatch for {} (expected {}, got {}). Binary may be tampered or out of date.",
                    name, expected, actual
                );
            }
        }
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

    #[allow(dead_code)]
    async fn download_macos_tpws(&self) -> Result<()> {
        let target_path = self.get_executable_path();
        println!("⬇️  Downloading official zapret release ({}) for macOS from {}...", ZAPRET_VERSION, ZAPRET_MACOS_ZIP_URL);

        let response = reqwest::get(ZAPRET_MACOS_ZIP_URL).await
            .with_context(|| format!("Failed to download zapret from {}", ZAPRET_MACOS_ZIP_URL))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error downloading zapret: {}", response.status()));
        }

        let bytes = response.bytes().await?;

        // Security: Verify SHA-256 hash before extracting/executing anything
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());

        if ZAPRET_MACOS_ZIP_SHA256 == "MUST_BE_SET_BEFORE_RELEASE" {
            // First-run bootstrap: print the hash so the developer can hardcode it
            println!("🔒 SECURITY NOTICE: macOS zapret zip SHA256 = {}", hash);
            println!("   ⚠️ Please hardcode this hash into ZAPRET_MACOS_ZIP_SHA256 before release!");
        } else if hash.to_lowercase() != ZAPRET_MACOS_ZIP_SHA256.to_lowercase() {
            return Err(anyhow!(
                "SHA-256 mismatch for zapret macOS bundle! Expected {}, got {}. Download may be corrupted or tampered with.",
                ZAPRET_MACOS_ZIP_SHA256,
                hash
            ));
        } else {
            println!("🔒 SHA-256 verified successfully ({})", &hash[..16]);
        }

        let reader = io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| anyhow!("Failed to read zapret zip archive: {}", e))?;

        let mut found = false;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_name = match file.enclosed_name() {
                Some(p) => p.to_owned(),
                None => continue,
            };

            let name_str = file_name.to_string_lossy();
            if name_str.ends_with("binaries/mac64/tpws") || name_str.ends_with("mac64/tpws") {
                // Extract to a sibling temp file, then atomically rename into
                // place so an interrupted extraction never leaves a
                // usable-looking but truncated `tpws`.
                let tmp_path = target_path.with_extension("partial");
                let mut outfile = File::create(&tmp_path)?;
                let written = io::copy(&mut file, &mut outfile)?;
                outfile.sync_all().ok();
                drop(outfile);

                if written < 4096 {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(anyhow!("Extracted tpws is implausibly small ({} bytes); archive layout may have changed", written));
                }

                fs::rename(&tmp_path, &target_path)
                    .with_context(|| format!("Failed to move extracted tpws into place at {:?}", target_path))?;
                found = true;
                break;
            }
        }

        if !found {
            return Err(anyhow!("Could not locate binaries/mac64/tpws within zapret zip archive"));
        }

        #[cfg(unix)]
        self.set_executable_permissions(&target_path)?;

        println!("✅ tpws universal binary installed to {:?}", target_path);
        Ok(())
    }

    #[allow(dead_code)]
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
