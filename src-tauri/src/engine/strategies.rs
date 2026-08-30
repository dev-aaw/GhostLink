use crate::engine::types::{Platform, Strategy};
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub struct StrategyManager {
    lists_dir: PathBuf,
}

impl StrategyManager {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            lists_dir: base_dir.join("lists"),
        }
    }

    pub fn ensure_lists(&self) -> Result<()> {
        fs::create_dir_all(&self.lists_dir)?;

        let general_list = self.lists_dir.join("list-general.txt");
        if !general_list.exists() {
            let content = r#"googlevideo.com
youtube.com
youtubekids.com
ytimg.com
youtu.be
youtubei.googleapis.com
yt4.ggpht.com
yt3.ggpht.com
yt2.ggpht.com
yt1.ggpht.com
gvt1.com
video.google.com
play.google.com
wide-youtube.l.google.com
redirector.googlevideo.com
jnn-pa.googleapis.com
discord.com
discord.gg
discordapp.com
discordapp.net
discord.media
discordcdn.com
gateway.discord.gg
cdn.discordapp.com
media.discordapp.net
status.discord.com
latency.discord.media
instagram.com
cdninstagram.com
fbcdn.net
twitter.com
x.com
t.co
twimg.com
wikileaks.org
www.wikileaks.org
"#;
            fs::write(general_list, content)?;
        }

        let google_list = self.lists_dir.join("list-google.txt");
        if !google_list.exists() {
            let content = r#"googlevideo.com
youtube.com
youtubekids.com
ytimg.com
youtu.be
youtubei.googleapis.com
yt4.ggpht.com
yt3.ggpht.com
yt2.ggpht.com
yt1.ggpht.com
gvt1.com
video.google.com
play.google.com
wide-youtube.l.google.com
redirector.googlevideo.com
jnn-pa.googleapis.com
"#;
            fs::write(google_list, content)?;
        }

        let discord_list = self.lists_dir.join("list-discord.txt");
        if !discord_list.exists() {
            let content = r#"discord.com
discord.gg
discordapp.com
discordapp.net
discord.media
discordcdn.com
gateway.discord.gg
cdn.discordapp.com
media.discordapp.net
status.discord.com
latency.discord.media
"#;
            fs::write(discord_list, content)?;
        }

        let exclude_list = self.lists_dir.join("list-exclude.txt");
        if !exclude_list.exists() {
            let content = r#"127.0.0.1
localhost
::1
router.asus.com
tplinkwifi.net
my.router
speedtest.net
fast.com
turktelekom.com.tr
turkcell.com.tr
vodafone.com.tr
"#;
            fs::write(exclude_list, content)?;
        }

        let ipset_all = self.lists_dir.join("ipset-all.txt");
        if !ipset_all.exists() {
            let content = r#"1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
"#;
            fs::write(ipset_all, content)?;
        }

        let ipset_exclude = self.lists_dir.join("ipset-exclude.txt");
        if !ipset_exclude.exists() {
            let content = r#"10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
"#;
            fs::write(ipset_exclude, content)?;
        }

        Ok(())
    }

    pub fn list_strategies(&self, bin_dir: &Path, socks_port: u16) -> Vec<Strategy> {
        #[cfg(target_os = "macos")]
        {
            self.get_macos_strategies(bin_dir, socks_port)
        }
        #[cfg(target_os = "windows")]
        {
            let _ = socks_port;
            self.get_windows_strategies(bin_dir)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = socks_port;
            let _ = bin_dir;
            Vec::new()
        }
    }

    #[cfg(target_os = "macos")]
    fn get_macos_strategies(&self, bin_dir: &Path, socks_port: u16) -> Vec<Strategy> {
        let q = |f: &str| bin_dir.join(f).to_string_lossy().to_string();
        let l = |f: &str| self.lists_dir.join(f).to_string_lossy().to_string();

        let tls_g = q("tls_clienthello_www_google_com.bin");
        let tls_4 = q("tls_clienthello_4pda_to.bin");
        let tls_m = q("tls_clienthello_max_ru.bin");

        let base_socks = format!("--socks=127.0.0.1:{}", socks_port);

        vec![
            Strategy {
                id: "mac-alt9".to_string(),
                name: "macOS ALT9 (Recommended)".to_string(),
                description: "Dual-tier TLS multi-split (Google/Discord 681B + General 664B) with TS fooling. Highest success rate for Turkish ISPs.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks.clone(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=681".to_string(),
                    format!("--split-seqovl-pattern={}", tls_g),
                    "--fooling=ts".to_string(),
                    "--new".to_string(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=664".to_string(),
                    format!("--split-seqovl-pattern={}", tls_m),
                    "--fooling=ts".to_string(),
                ],
            },
            Strategy {
                id: "mac-alt11".to_string(),
                name: "macOS ALT11".to_string(),
                description: "Multi-split TLS desync with TS fooling and 4pda pattern. Excellent fallback for YouTube and streaming.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks.clone(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=681".to_string(),
                    format!("--split-seqovl-pattern={}", tls_g),
                    "--fooling=ts".to_string(),
                    "--new".to_string(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=568".to_string(),
                    format!("--split-seqovl-pattern={}", tls_4),
                    "--fooling=ts".to_string(),
                ],
            },
            Strategy {
                id: "mac-general".to_string(),
                name: "macOS General".to_string(),
                description: "Standard multi-split TLS desync with 4pda pattern without TS fooling. Broad compatibility.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks.clone(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=681".to_string(),
                    format!("--split-seqovl-pattern={}", tls_g),
                    "--new".to_string(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                    "--split-seqovl=568".to_string(),
                    format!("--split-seqovl-pattern={}", tls_4),
                ],
            },
            Strategy {
                id: "mac-alt3".to_string(),
                name: "macOS ALT3 (SNI-Split)".to_string(),
                description: "SNI-based desynchronization splitting at SNI extension boundary with badsum fooling.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks.clone(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=sniext+1".to_string(),
                    "--split-seqovl=681".to_string(),
                    format!("--split-seqovl-pattern={}", tls_g),
                    "--fooling=badsum".to_string(),
                ],
            },
            Strategy {
                id: "mac-alt10".to_string(),
                name: "macOS ALT10 (SLD-Split)".to_string(),
                description: "Pure multi-split desync at second-level domain boundary. Clean bypass with zero fake packets.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks.clone(),
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=midsld".to_string(),
                ],
            },
            Strategy {
                id: "mac-simple-fake".to_string(),
                name: "macOS Simple Fake".to_string(),
                description: "Fast, low-overhead fake packet injection with TCP timestamp fooling.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    base_socks,
                    "--port=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                    "--fooling=ts".to_string(),
                ],
            },
        ]
    }

    fn get_windows_strategies(&self, bin_dir: &Path) -> Vec<Strategy> {
        let q = |f: &str| bin_dir.join(f).to_string_lossy().to_string();
        let l = |f: &str| self.lists_dir.join(f).to_string_lossy().to_string();

        let tls_g = q("tls_clienthello_www_google_com.bin");
        let tls_4 = q("tls_clienthello_4pda_to.bin");
        let quic_g = q("quic_initial_www_google_com.bin");
        let quic_d = q("quic_initial_dbankcloud_ru.bin");
        let stun = q("stun.bin");

        let wf_full = vec![
            "--wf-tcp=80,443,2053,2083,2087,2096,8443".to_string(),
            "--wf-udp=443,19294-19344,50000-50100".to_string(),
        ];

        // Flowseal standard 8-rule builder matching official release batch files exactly
        let build_windows_flowseal_rules = |r3: Vec<String>, r4: Vec<String>, r5: Vec<String>, r7: Vec<String>, r8: Vec<String>| -> Vec<String> {
            let mut args = wf_full.clone();
            // Rule 1: UDP 443 QUIC
            args.extend([
                "--filter-udp=443".to_string(),
                format!("--hostlist={}", l("list-general.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=6".to_string(),
                format!("--dpi-desync-fake-quic={}", quic_g),
                "--dpi-desync-cutoff=d2".to_string(),
                "--new".to_string(),
            ]);
            // Rule 2: UDP Discord Voice (STUN & WebRTC)
            args.extend([
                "--filter-udp=19294-19344,50000-50100".to_string(),
                "--filter-l7=discord,stun".to_string(),
                "--dpi-desync=fake".to_string(),
                format!("--dpi-desync-fake-discord={}", quic_d),
                format!("--dpi-desync-fake-stun={}", stun),
                "--dpi-desync-repeats=6".to_string(),
                "--dpi-desync-cutoff=d3".to_string(),
                "--new".to_string(),
            ]);
            // Rule 3: Discord Media TCP
            args.extend([
                "--filter-tcp=2053,2083,2087,2096,8443".to_string(),
                "--hostlist-domains=discord.media".to_string(),
            ]);
            args.extend(r3);
            args.push("--new".to_string());

            // Rule 4: Google/YouTube TCP 443
            args.extend([
                "--filter-tcp=443".to_string(),
                format!("--hostlist={}", l("list-google.txt")),
                "--ip-id=zero".to_string(),
            ]);
            args.extend(r4);
            args.push("--new".to_string());

            // Rule 5: General TCP (Discord Web, WikiLeaks, X, etc.)
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--hostlist={}", l("list-general.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
            ]);
            args.extend(r5);
            args.push("--new".to_string());

            // Rule 6: IP-set UDP Fallback
            args.extend([
                "--filter-udp=443".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=6".to_string(),
                format!("--dpi-desync-fake-quic={}", quic_g),
                "--dpi-desync-cutoff=d2".to_string(),
                "--new".to_string(),
            ]);

            // Rule 7: IP-set TCP Fallback
            args.extend([
                "--filter-tcp=80,443,8443".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
            ]);
            args.extend(r7);
            args.push("--new".to_string());

            // Rule 8: UDP Game / Catch-All
            args.extend([
                "--filter-udp=12".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=12".to_string(),
                "--dpi-desync-any-protocol=1".to_string(),
                format!("--dpi-desync-fake-unknown-udp={}", quic_d),
                "--dpi-desync-cutoff=d2".to_string(),
            ]);
            args.extend(r8);

            args
        };

        vec![
            Strategy {
                id: "win-general".to_string(),
                name: "Windows General (Flowseal Default - Recommended)".to_string(),
                description: "Official Flowseal multisplit 681/568 with ClientHello pattern matching. Zero connection resets, fully tested across ISPs.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    vec!["--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt".to_string(),
                name: "Windows ALT (SNI Ext Split)".to_string(),
                description: "Multi-split at SNI extension boundary with sequence overlap. Highly effective against deep packet inspection.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=568".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=568".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    vec!["--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt9".to_string(),
                name: "Windows ALT9 (Hostfakesplit)".to_string(),
                description: "Official Flowseal ALT9 hostfakesplit with google/ozon domain modifiers and timestamp fooling.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-hostfakesplit-mod=host=www.google.com".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-hostfakesplit-mod=host=www.google.com".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt11".to_string(),
                name: "Windows ALT11 (Pos 2 + SNI Ext)".to_string(),
                description: "Multi-split at position 2 and SNI extension + 1 with 679 byte pattern overlap.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=2,sniext+1".into(), "--dpi-desync-split-seqovl=679".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=2,sniext+1".into(), "--dpi-desync-split-seqovl=679".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=2,sniext+1".into(), "--dpi-desync-split-seqovl=679".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync=syndata".into()],
                    vec!["--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt3".to_string(),
                name: "Windows ALT3 (Fake + Hostfakesplit)".to_string(),
                description: "Fake TLS ClientHello + hostfakesplit with altorder modifier for resistant ISP nodes.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=fake,hostfakesplit".into(), "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com".into(), "--dpi-desync-hostfakesplit-mod=host=www.google.com,altorder=1".into(), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=fake,hostfakesplit".into(), "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com".into(), "--dpi-desync-hostfakesplit-mod=host=www.google.com,altorder=1".into(), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=fake,hostfakesplit".into(), "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru".into(), "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1".into(), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=fake,hostfakesplit".into(), "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru".into(), "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1".into(), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync-cutoff=n4".into()],
                ),
            },
            Strategy {
                id: "win-simple-fake".to_string(),
                name: "Windows Simple Fake (Fast Injection)".to_string(),
                description: "Lightweight fake TLS ClientHello injection with timestamp fooling.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_4)],
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_4)],
                    vec!["--dpi-desync-cutoff=n3".into()],
                ),
            },
        ]
    }
}

pub struct StrategyConfigManager;

impl StrategyConfigManager {
    /// List of paths to check for persistent strategy config (User home and ProgramData)
    pub fn config_paths() -> Vec<std::path::PathBuf> {
        let mut paths = Vec::new();

        // 1. User Home ~/.ghostlink/selected_strategy.txt
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        paths.push(std::path::PathBuf::from(home).join(".ghostlink").join("selected_strategy.txt"));

        // 2. Windows shared ProgramData
        #[cfg(target_os = "windows")]
        {
            let pdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
            paths.push(std::path::PathBuf::from(pdata).join("GhostLink").join("selected_strategy.txt"));
        }

        paths
    }

    /// Save the selected strategy ID persistently
    pub fn save_selected_strategy(strategy_id: &str) -> Result<()> {
        let trimmed = strategy_id.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        for path in Self::config_paths() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&path, trimmed);
        }

        Ok(())
    }

    /// Load the selected strategy ID, or return platform default
    pub fn load_selected_strategy() -> String {
        for path in Self::config_paths() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }

        // Platform default if never saved
        #[cfg(target_os = "windows")]
        {
            "win-general".to_string()
        }
        #[cfg(not(target_os = "windows"))]
        {
            "strategy-1".to_string()
        }
    }
}

