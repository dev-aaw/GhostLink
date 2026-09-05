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

    /// Bump whenever the bundled domain lists below change so existing installs
    /// actually pick up the new content instead of keeping a stale first-run copy.
    pub const LISTS_VERSION: u32 = 3;

    pub fn ensure_lists(&self) -> Result<()> {
        fs::create_dir_all(&self.lists_dir)?;

        // Force a refresh of the managed lists when the bundled version is newer
        // than what's on disk (or the marker is missing). Below that threshold we
        // keep the "write only if absent" behaviour so nothing is churned needlessly.
        let version_path = self.lists_dir.join(".version");
        let on_disk_version: u32 = fs::read_to_string(&version_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let force = on_disk_version < Self::LISTS_VERSION;

        let write_list = |filename: &str, content: &str| -> Result<()> {
            let path = self.lists_dir.join(filename);
            if force || !path.exists() {
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

        // 2. Discord (Web, Desktop Gateway, Voice, Media, CDN, Updater)
        // NOTE: The Discord updater hosts (updates.discord.com, dl2.discordapp.net) MUST be desynced
        // here rather than DNS-pinned. Turkish ISPs inject TCP RST (WinError 10054) on the plaintext
        // ClientHello of these hosts; routing them through the DPI-desync rule is what actually fixes
        // the "Checking for updates" / "Update Failed" loop. Never add them to list-exclude.txt.
        write_list(
            "list-discord.txt",
            "discord.com\ndiscord.gg\ndiscordapp.com\ndiscordapp.net\ndiscord.media\ndiscordcdn.com\ngateway.discord.gg\ncdn.discordapp.com\nmedia.discordapp.net\nstatus.discord.com\nlatency.discord.media\ndiscordapp.io\ndiscord.co\nfingerprint.discord.com\nremote-auth-gateway.discord.gg\nupdates.discord.com\ndl2.discordapp.net\nstable.dl2.discordapp.net\nrouter.discordapp.net\n",
        )?;

        // 3. General Blocked Domains (WikiLeaks, Instagram, X/Twitter, etc.)
        write_list(
            "list-general.txt",
            "wikileaks.org\nwww.wikileaks.org\nwl-storage.org\nfile.wikileaks.org\ninstagram.com\ncdninstagram.com\nfbcdn.net\ntwitter.com\nx.com\nt.co\ntwimg.com\n",
        )?;

        // 4. Exclude Domains — never desync these.
        //    Google OAuth / account endpoints (desyncing them breaks sign-in on every Google app),
        //    LAN router admin panels, ISP speed-test and self-service sites (needed for captive-portal
        //    detection and for the user to pay their bill), and loopback.
        write_list(
            "list-exclude.txt",
            "127.0.0.1\nlocalhost\n::1\noauth2.googleapis.com\naccounts.google.com\naccounts.youtube.com\nmyaccount.google.com\nidentitytoolkit.googleapis.com\nsecuretoken.googleapis.com\ncloudresourcemanager.googleapis.com\nrouter.asus.com\ntplinkwifi.net\nmy.router\nspeedtest.net\nfast.com\nturktelekom.com.tr\nturkcell.com.tr\nvodafone.com.tr\nturknet.com.tr\nsuperonline.net\n",
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

        if force {
            let _ = fs::write(&version_path, Self::LISTS_VERSION.to_string());
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
    fn get_macos_strategies(&self, _bin_dir: &Path, socks_port: u16) -> Vec<Strategy> {
        let l = |f: &str| self.lists_dir.join(f).to_string_lossy().to_string();

        // tpws (this binary's real CLI grammar — see `tpws --help`) is a
        // userspace SOCKS/transparent proxy, NOT nfqws/winws (the netfilter/
        // WinDivert packet-level DPI-desync tools). It has no `--dpi-desync`
        // method selector and no packet-level "fooling"/sequence-overlap
        // concept at all — those are unique to operating on raw, not-yet-
        // established packets, which a listening proxy never sees. Phase A
        // mechanical fixes only (no strategy redesign):
        //   - `--socks` takes no value; the bind address/port are separate
        //     flags. `--bind-addr=127.0.0.1` and `--maxconn=512` existed in
        //     this codebase's original macOS strategies and were dropped when
        //     these were rewritten to (incorrectly) mirror nfqws syntax.
        //   - `--port=443` here meant "match traffic on port 443", which is
        //     `--filter-tcp=443` (tpws's MULTI-STRATEGY section) — tpws's own
        //     `--port` is the port *tpws itself* listens on ("only one port
        //     number for all binds is supported" per --help), so reusing it
        //     as a per-rule traffic filter also silently overrode the real
        //     SOCKS listen port.
        //   - `--split-seqovl(-pattern)=` and `--fooling=` do not exist in
        //     tpws at all (confirmed against a full `--help` dump); every
        //     strategy that referenced them failed to parse, printed usage,
        //     and exited without ever attempting to bind. Removed here with
        //     no replacement — redesigning what these strategies should
        //     actually do instead (using tpws's real tamper primitives:
        //     --disorder, --oob, --tlsrec, --hostcase family,
        //     --tamper-start/--tamper-cutoff) is a separate, deliberate
        //     follow-up, not a mechanical fix.
        // Net effect: mac-alt9/mac-alt11/mac-general only differed in the
        // (now-removed) seqovl/fooling values, so they collapse to identical
        // argv below — noted for follow-up, not resolved in this phase.
        let socks_args = |port: u16| -> Vec<String> {
            vec![
                "--socks".to_string(),
                "--bind-addr=127.0.0.1".to_string(),
                format!("--port={}", port),
                "--maxconn=512".to_string(),
            ]
        };

        vec![
            Strategy {
                id: "mac-alt9".to_string(),
                name: "macOS ALT9 (Recommended)".to_string(),
                description: "Dual-tier TCP split at position 1 (Google/Discord + General, port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--new".to_string(),
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                ]].concat(),
            },
            Strategy {
                id: "mac-alt11".to_string(),
                name: "macOS ALT11".to_string(),
                description: "Dual-tier TCP split at position 1 (Google/Discord + General, port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--new".to_string(),
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                ]].concat(),
            },
            Strategy {
                id: "mac-general".to_string(),
                name: "macOS General".to_string(),
                description: "Dual-tier TCP split at position 1 (Google/Discord + General, port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-google.txt")),
                    "--split-pos=1".to_string(),
                    "--new".to_string(),
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                ]].concat(),
            },
            Strategy {
                id: "mac-alt3".to_string(),
                name: "macOS ALT3 (SNI-Split)".to_string(),
                description: "Splits at the TLS SNI extension boundary (port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=sniext+1".to_string(),
                ]].concat(),
            },
            Strategy {
                id: "mac-alt10".to_string(),
                name: "macOS ALT10 (SLD-Split)".to_string(),
                description: "Splits at the second-level domain boundary (port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=midsld".to_string(),
                ]].concat(),
            },
            Strategy {
                id: "mac-simple-fake".to_string(),
                name: "macOS Simple Fake".to_string(),
                description: "Plain TCP split at position 1 (port 443).".to_string(),
                platform: Platform::MacOS,
                args: [socks_args(socks_port), vec![
                    "--filter-tcp=443".to_string(),
                    format!("--hostlist={}", l("list-general.txt")),
                    format!("--hostlist-exclude={}", l("list-exclude.txt")),
                    "--split-pos=1".to_string(),
                ]].concat(),
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

        // 0. Root daemon (launchd gives it no HOME, so the HOME-derived path
        //    below is relative and silently never round-trips): the same
        //    fixed system path EngineConfig::default(), ProcessHandle's
        //    engine.log, and Logger now use. Tried first so save/load actually
        //    persist the selected/auto-tuned strategy across daemon restarts
        //    instead of silently forgetting it every time.
        #[cfg(target_os = "macos")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if is_root {
                paths.push(std::path::PathBuf::from("/Library/Application Support/GhostLink/data/selected_strategy.txt"));
            }
        }

        // 1. User Home ~/.ghostlink/selected_strategy.txt (always user-writable, authoritative)
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        paths.push(std::path::PathBuf::from(home).join(".ghostlink").join("selected_strategy.txt"));

        // 2. Windows shared ProgramData. The user-writable `state\` subdir is the write
        //    target for the tray/CLI; the legacy root path is kept only as a read
        //    fallback so existing installs still pick up their saved strategy.
        #[cfg(target_os = "windows")]
        {
            let pdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
            let base = std::path::PathBuf::from(pdata).join("GhostLink");
            paths.push(base.join("state").join("selected_strategy.txt"));
            paths.push(base.join("selected_strategy.txt"));
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

