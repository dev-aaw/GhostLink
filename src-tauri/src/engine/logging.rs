use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static GLOBAL_LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub struct Logger {
    component: String,
    log_file_path: PathBuf,
    file_handle: Mutex<Option<File>>,
    max_file_size: u64,
}

impl Logger {
    pub fn new(component: &str) -> Self {
        // Preferred location first, then a guaranteed user-writable fallback. The
        // SYSTEM daemon writes to %ProgramData%\GhostLink\logs; the CLI/tray run as
        // the standard user and, if that directory is locked down to read-only for
        // Users, transparently fall back to %LOCALAPPDATA% instead of silently
        // losing all file logging.
        let mut candidates: Vec<PathBuf> = Vec::new();
        #[cfg(target_os = "windows")]
        {
            if let Ok(pdata) = std::env::var("ProgramData") {
                candidates.push(PathBuf::from(pdata).join("GhostLink").join("logs"));
            }
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                candidates.push(PathBuf::from(local).join("GhostLink").join("logs"));
            }
            candidates.push(PathBuf::from(r"C:\ProgramData\GhostLink\logs"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            candidates.push(PathBuf::from(home).join(".ghostlink").join("logs"));
        }

        let (log_file_path, file) = candidates
            .iter()
            .find_map(|dir| {
                let _ = fs::create_dir_all(dir);
                let path = dir.join(format!("{}.log", component));
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .ok()
                    .map(|f| (path, Some(f)))
            })
            .unwrap_or_else(|| {
                let fallback = candidates
                    .first()
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(format!("{}.log", component));
                (fallback, None)
            });

        Self {
            component: component.to_string(),
            log_file_path,
            file_handle: Mutex::new(file),
            max_file_size: 10 * 1024 * 1024, // 10 MB per log file
        }
    }

    fn format_timestamp() -> String {
        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = duration.as_secs();

        let days = secs / 86400;
        let day_secs = secs % 86400;
        let hours = day_secs / 3600;
        let minutes = (day_secs % 3600) / 60;
        let seconds = day_secs % 60;

        let mut year = 1970;
        let mut rem_days = days;
        loop {
            let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            let days_in_year = if leap { 366 } else { 365 };
            if rem_days >= days_in_year {
                rem_days -= days_in_year;
                year += 1;
            } else {
                break;
            }
        }

        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let month_lengths = [
            31, if leap { 29 } else { 28 }, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31,
        ];
        let mut month = 1;
        for &mlen in &month_lengths {
            if rem_days >= mlen {
                rem_days -= mlen;
                month += 1;
            } else {
                break;
            }
        }
        let day = rem_days + 1;

        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            year, month, day, hours, minutes, seconds
        )
    }

    fn check_rotate(&self) {
        if let Ok(metadata) = fs::metadata(&self.log_file_path) {
            if metadata.len() > self.max_file_size {
                let mut handle = self.file_handle.lock().unwrap();
                *handle = None;

                let backup_path = self.log_file_path.with_extension("1.log");
                let _ = fs::rename(&self.log_file_path, &backup_path);

                *handle = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_file_path)
                    .ok();
            }
        }
    }

    pub fn write_entry(&self, level: &str, message: &str) {
        let ts = Self::format_timestamp();
        let line = format!("[{}] [{}] [{}] {}\n", ts, level, self.component, message);

        if level == "ERROR" {
            eprint!("{}", line);
        } else {
            print!("{}", line);
        }

        self.check_rotate();

        if let Ok(mut handle) = self.file_handle.lock() {
            if let Some(ref mut file) = *handle {
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
            }
        }
    }

    pub fn read_recent_lines(&self, max_lines: usize) -> Vec<String> {
        let file = match File::open(&self.log_file_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
        let total = lines.len();
        if total <= max_lines {
            lines
        } else {
            lines[total - max_lines..].to_vec()
        }
    }
}

pub fn init_logger(component: &str) {
    let mut logger = GLOBAL_LOGGER.lock().unwrap();
    *logger = Some(Logger::new(component));
}

pub fn log_msg(level: &str, message: &str) {
    if let Ok(guard) = GLOBAL_LOGGER.lock() {
        if let Some(ref logger) = *guard {
            logger.write_entry(level, message);
            return;
        }
    }
    let ts = Logger::format_timestamp();
    eprintln!("[{}] [{}] {}", ts, level, message);
}

pub fn get_recent_log_entries(max_lines: usize) -> Vec<String> {
    if let Ok(guard) = GLOBAL_LOGGER.lock() {
        if let Some(ref logger) = *guard {
            return logger.read_recent_lines(max_lines);
        }
    }
    Vec::new()
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::engine::logging::log_msg("INFO", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::engine::logging::log_msg("WARN", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::engine::logging::log_msg("ERROR", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::engine::logging::log_msg("DEBUG", &format!($($arg)*))
    };
}
