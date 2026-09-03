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

        let write_list = |filename: &str, content: &str| -> Result<()> {
            let path = self.lists_dir.join(filename);
            if !path.exists() {
                fs::write(&path, content)?;
            }
            Ok(())
        };

        // 1. YouTube / Googlevideo (Web, Video Streams, Thumbnails, Avatars)
        // NOTE: NEVER include generic 'googleapis.com' or '1e100.net' as it breaks Google OAuth / accounts / IDE APIs.
        write_list(
            "list-google.txt",
            "googlevideo.com\nyoutube.com\nyoutubekids.com\nytimg.com\ni.ytimg.com\nggpht.com\nyt.akamaized.net\nyoutu.be\nyoutubei.googleapis.com\nyoutube-nocookie.com\nyoutube-ui.l.google.com\nyt-video-upload.l.google.com\ngvt1.com\ngvt2.com\nvideo.google.com\nwide-youtube.l.google.com\nredirector.googlevideo.com\njnn-pa.googleapis.com\n",
        )?;

        // 2. Discord (Web, Desktop Gateway, Voice, Media, CDN)
        // NOTE: Exclude updates.discord.com and dl2.discordapp.net so Discord updater downloads without TLS session corruption.
        write_list(
            "list-discord.txt",
            "discord.com\ndiscord.gg\ndiscordapp.com\ndiscord.media\ndiscordcdn.com\ngateway.discord.gg\ncdn.discordapp.com\nmedia.discordapp.net\nstatus.discord.com\nlatency.discord.media\ndiscordapp.io\ndiscord.co\nfingerprint.discord.com\nremote-auth-gateway.discord.gg\n",
        )?;

        // 3. General Blocked Domains (WikiLeaks, Instagram, X/Twitter, etc.)
        write_list(
            "list-general.txt",
            "wikileaks.org\nwww.wikileaks.org\nwl-storage.org\nfile.wikileaks.org\ninstagram.com\ncdninstagram.com\nfbcdn.net\ntwitter.com\nx.com\nt.co\ntwimg.com\n",
        )?;

        // 4. Exclude Domains (Google OAuth/Accounts, Antigravity/Gemini APIs, Routers, Speedtest, ISP sites)
        write_list(
            "list-exclude.txt",
            "127.0.0.1\nlocalhost\n::1\noauth2.googleapis.com\naccounts.google.com\naccounts.youtube.com\nmyaccount.google.com\nidentitytoolkit.googleapis.com\nsecuretoken.googleapis.com\ncloudresourcemanager.googleapis.com\ngenerativelanguage.googleapis.com\nrouter.asus.com\ntplinkwifi.net\nmy.router\nspeedtest.net\nfast.com\nturktelekom.com.tr\nturkcell.com.tr\nvodafone.com.tr\n",
        )?;

        // 5. IP-set All (DNS Providers only - never put CDN ranges here)
        write_list(
            "ipset-all.txt",
            "1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n149.112.112.112\n",
        )?;

        // 6. IP-set Exclude (Private LAN)
        write_list(
            "ipset-exclude.txt",
            "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8\n",
        )?;

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
        let _tls_m = q("tls_clienthello_max_ru.bin");
        let quic_g = q("quic_initial_www_google_com.bin");
        let quic_d = q("quic_initial_dbankcloud_ru.bin");
        let stun = q("stun.bin");

        let wf_full = vec![
            "--wf-tcp=80,443".to_string(),
            "--wf-udp=443,19294-19344,50000-65535".to_string(),
        ];

        // Flowseal official multi-rule builder
        let build_windows_flowseal_rules = |r4_google: Vec<String>, r5_discord: Vec<String>, r6_general: Vec<String>, r7_ipset: Vec<String>| -> Vec<String> {
            let mut args = wf_full.clone();
            // Rule 1: UDP 443 QUIC (Google / YouTube) - force instant TCP fallback with 11 repeats
            args.extend([
                "--filter-udp=443".to_string(),
                format!("--hostlist={}", l("list-google.txt")),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=11".to_string(),
                format!("--dpi-desync-fake-quic={}", quic_g),
                "--dpi-desync-cutoff=d4".to_string(),
                "--new".to_string(),
            ]);
            // Rule 2: UDP Discord Voice (STUN & WebRTC)
            args.extend([
                "--filter-udp=19294-19344,50000-65535".to_string(),
                "--filter-l7=discord,stun".to_string(),
                "--dpi-desync=fake".to_string(),
                format!("--dpi-desync-fake-stun={}", stun),
                "--dpi-desync-repeats=2".to_string(),
                "--dpi-desync-cutoff=d3".to_string(),
                "--new".to_string(),
            ]);

            // Rule 4: Google/YouTube TCP 80,443
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--hostlist={}", l("list-google.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
            ]);
            args.extend(r4_google);
            args.push("--new".to_string());

            // Rule 5: Discord Web / App / CDN TCP 80,443
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--hostlist={}", l("list-discord.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
            ]);
            args.extend(r5_discord);
            args.push("--new".to_string());

            // Rule 6: General Blocked TCP 80,443 (WikiLeaks, Instagram, X/Twitter, etc.)
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--hostlist={}", l("list-general.txt")),
                format!("--hostlist-exclude={}", l("list-discord.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
            ]);
            args.extend(r6_general);
            args.push("--new".to_string());

            // Rule 7: IP-set TCP Fallback
            args.extend([
                "--filter-tcp=80,443,8443".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--hostlist-exclude={}", l("list-discord.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
            ]);
            args.extend(r7_ipset);
            args.push("--new".to_string());

            // Rule 8: UDP Game / Catch-All
            args.extend([
                "--filter-udp=12-65535".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=12".to_string(),
                "--dpi-desync-any-protocol=1".to_string(),
                format!("--dpi-desync-fake-unknown-udp={}", quic_d),
                "--dpi-desync-cutoff=d2".to_string(),
            ]);

            args
        };

        vec![
            Strategy {
                id: "win-general".to_string(),
                name: "Windows General (Flowseal Multi-Rule - Recommended)".to_string(),
                description: "Official multi-tier desync (Google/YouTube Multi-Split + Discord Multi-Split + General Hostfakesplit ozon.ru).".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-superonline".to_string(),
                name: "Windows Superonline (Datanoack + Split2)".to_string(),
                description: "Optimized for Turkcell Superonline DPI with datanoack fooling and fake packet injection.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=fake,split2".into(), "--dpi-desync-split-seqovl=1".into(), "--dpi-desync-fooling=datanoack".into(), "--dpi-desync-repeats=6".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=fake,split2".into(), "--dpi-desync-split-seqovl=1".into(), "--dpi-desync-fooling=datanoack".into(), "--dpi-desync-repeats=6".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-turktelekom".to_string(),
                name: "Windows Turk Telekom (Badseq + Midsld)".to_string(),
                description: "Optimized for Turk Telekom & Kablonet with badseq sequence fooling and mid-domain splitting.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=fake,multisplit".into(), "--dpi-desync-split-pos=1,midsld".into(), "--dpi-desync-fooling=badseq,md5sig".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=fake,multisplit".into(), "--dpi-desync-split-pos=1,midsld".into(), "--dpi-desync-fooling=badseq,md5sig".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt".to_string(),
                name: "Windows ALT (Hostfakesplit ozon.ru)".to_string(),
                description: "Hostfakesplit desync with ozon.ru host modifier and timestamp + md5sig fooling.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=fake".into(), "--dpi-desync-repeats=6".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt9".to_string(),
                name: "Windows ALT9 (Badsum Multi-Split)".to_string(),
                description: "Multi-split desynchronization with Badsum TCP checksum fooling.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=badsum".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=1,sniext+1".into(), "--dpi-desync-split-seqovl=681".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=badsum".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
                ),
            },
            Strategy {
                id: "win-alt11".to_string(),
                name: "Windows ALT11 (Pos 2 + SNI Ext)".to_string(),
                description: "Multi-split at position 2 and SNI extension + 1 with 679 byte pattern overlap.".to_string(),
                platform: Platform::Windows,
                args: build_windows_flowseal_rules(
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=2,sniext+1".into(), "--dpi-desync-split-seqovl=679".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-pos=2,sniext+1".into(), "--dpi-desync-split-seqovl=679".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), "--dpi-desync-fooling=ts".into()],
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
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
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
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
                    vec!["--dpi-desync=hostfakesplit".into(), "--dpi-desync-repeats=4".into(), "--dpi-desync-fooling=ts,md5sig".into(), "--dpi-desync-hostfakesplit-mod=host=ozon.ru".into()],
                    vec!["--dpi-desync=multisplit".into(), "--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4), "--dpi-desync-cutoff=n2".into()],
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
            "mac-alt9".to_string()
        }
    }
}

