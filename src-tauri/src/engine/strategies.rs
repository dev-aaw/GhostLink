use crate::engine::types::{Platform, Strategy};
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub const HOST_LIST_GOOGLE: &str = r#"googlevideo.com
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
jnn-pa.googleapis.com"#;

pub const HOST_LIST_DISCORD: &str = r#"discord.com
discord.gg
discordapp.com
discordapp.net
discord.media
discordcdn.com
gateway.discord.gg
cdn.discordapp.com
media.discordapp.net
status.discord.com
latency.discord.media"#;

pub const HOST_LIST_GENERAL: &str = r#"googlevideo.com
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
twimg.com"#;

pub const HOST_LIST_EXCLUDE: &str = r#"yandex.ru
ya.ru
vk.com
mail.ru
gosuslugi.ru
ozon.ru
wildberries.ru
sberbank.ru
tinkoff.ru
t-bank.ru
avito.ru
rutube.ru
kinopoisk.ru
127.0.0.1
localhost"#;

pub const IPSET_ALL: &str = r#"162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
66.22.192.0/18
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
190.93.240.0/20"#;

pub const IPSET_EXCLUDE: &str = r#"10.0.0.0/8
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
fc00::/7
fe80::/10
::1/128"#;

pub struct StrategyManager {
    lists_dir: PathBuf,
}

impl StrategyManager {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            lists_dir: base_dir.join("lists"),
        }
    }

    pub fn lists_dir(&self) -> &Path {
        &self.lists_dir
    }

    pub fn ensure_lists(&self) -> Result<()> {
        fs::create_dir_all(&self.lists_dir)?;

        fs::write(self.lists_dir.join("list-google.txt"), HOST_LIST_GOOGLE)?;
        fs::write(self.lists_dir.join("list-discord.txt"), HOST_LIST_DISCORD)?;
        fs::write(self.lists_dir.join("list-general.txt"), HOST_LIST_GENERAL)?;
        fs::write(self.lists_dir.join("list-exclude.txt"), HOST_LIST_EXCLUDE)?;
        fs::write(self.lists_dir.join("ipset-all.txt"), IPSET_ALL)?;
        fs::write(self.lists_dir.join("ipset-exclude.txt"), IPSET_EXCLUDE)?;

        Ok(())
    }

    /// Returns the full list of strategies for the current platform in recommended testing order.
    pub fn get_strategies_for_platform(&self, platform: Platform, bin_dir: &Path, socks_port: u16) -> Vec<Strategy> {
        match platform {
            Platform::MacOS => self.get_macos_strategies(socks_port),
            Platform::Windows => self.get_windows_strategies(bin_dir),
            Platform::Linux => self.get_macos_strategies(socks_port),
        }
    }

    fn get_macos_strategies(&self, socks_port: u16) -> Vec<Strategy> {
        let general_list = self.lists_dir.join("list-general.txt").to_string_lossy().to_string();

        vec![
            Strategy {
                id: "mac-split-midsld".to_string(),
                name: "macOS TLS Split + Mid-SLD (Default)".to_string(),
                description: "Splits TLS ClientHello at domain middle with disordering. Very effective on macOS.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    format!("--port={}", socks_port),
                    "--socks".to_string(),
                    "--split-pos=1,midsld".to_string(),
                    "--disorder".to_string(),
                    format!("--hostlist={}", general_list),
                ],
            },
            Strategy {
                id: "mac-split-tls-sni".to_string(),
                name: "macOS TLS SNI Split".to_string(),
                description: "Splits TLS ClientHello right at the SNI extension boundary.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    format!("--port={}", socks_port),
                    "--socks".to_string(),
                    "--split-tls=sni".to_string(),
                    "--disorder".to_string(),
                    format!("--hostlist={}", general_list),
                ],
            },
            Strategy {
                id: "mac-split-pos-1".to_string(),
                name: "macOS Split Pos 1".to_string(),
                description: "Splits packet at 1st byte + disordering.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    format!("--port={}", socks_port),
                    "--socks".to_string(),
                    "--split-pos=1".to_string(),
                    "--disorder".to_string(),
                    format!("--hostlist={}", general_list),
                ],
            },
            Strategy {
                id: "mac-oob".to_string(),
                name: "macOS Out-Of-Band (OOB)".to_string(),
                description: "Injects out-of-band byte marker to desynchronize DPI state machine.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    format!("--port={}", socks_port),
                    "--socks".to_string(),
                    "--oob".to_string(),
                    format!("--hostlist={}", general_list),
                ],
            },
            Strategy {
                id: "mac-combo-tls-http".to_string(),
                name: "macOS Combo TLS+HTTP Split".to_string(),
                description: "Splits HTTP request method and TLS SNI concurrently.".to_string(),
                platform: Platform::MacOS,
                args: vec![
                    format!("--port={}", socks_port),
                    "--socks".to_string(),
                    "--split-http-req=method".to_string(),
                    "--split-tls=sni".to_string(),
                    format!("--hostlist={}", general_list),
                ],
            },
        ]
    }

    fn get_windows_strategies(&self, bin_dir: &Path) -> Vec<Strategy> {
        let q = |f: &str| bin_dir.join(f).to_string_lossy().to_string();
        let l = |f: &str| self.lists_dir.join(f).to_string_lossy().to_string();

        let tls_g = q("tls_clienthello_www_google_com.bin");
        let tls_4 = q("tls_clienthello_4pda_to.bin");
        let tls_m = q("tls_clienthello_max_ru.bin");
        let quic_g = q("quic_initial_www_google_com.bin");

        let wf_full = vec![
            "--wf-tcp=80,443,2053,2083,2087,2096,8443".to_string(),
            "--wf-udp=443,19294-19344,50000-50100".to_string(),
        ];

        let build_8rule = |method: &str, r3: Vec<String>, r4: Vec<String>, r5: Vec<String>, r7: Vec<String>, game_repeats: usize| -> Vec<String> {
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
                "--new".to_string(),
            ]);
            // Rule 2: UDP Discord Voice
            args.extend([
                "--filter-udp=19294-19344,50000-50100".to_string(),
                "--filter-l7=discord,stun".to_string(),
                "--dpi-desync=fake".to_string(),
                "--dpi-desync-repeats=6".to_string(),
                "--new".to_string(),
            ]);
            // Rule 3: Discord Media TCP
            args.extend([
                "--filter-tcp=2053,2083,2087,2096,8443".to_string(),
                "--hostlist-domains=discord.media".to_string(),
                format!("--dpi-desync={}", method),
            ]);
            args.extend(r3);
            args.push("--new".to_string());

            // Rule 4: Google/YouTube TCP 443
            args.extend([
                "--filter-tcp=443".to_string(),
                format!("--hostlist={}", l("list-google.txt")),
                "--ip-id=zero".to_string(),
                format!("--dpi-desync={}", method),
            ]);
            args.extend(r4);
            args.push("--new".to_string());

            // Rule 5: General TCP
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--hostlist={}", l("list-general.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                format!("--dpi-desync={}", method),
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
                "--new".to_string(),
            ]);

            // Rule 7: IP-set TCP Fallback
            args.extend([
                "--filter-tcp=80,443".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--hostlist-exclude={}", l("list-exclude.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                format!("--dpi-desync={}", method),
            ]);
            args.extend(r7);
            args.push("--new".to_string());

            // Rule 8: UDP Game Catch-All
            args.extend([
                "--filter-udp=12".to_string(),
                format!("--ipset={}", l("ipset-all.txt")),
                format!("--ipset-exclude={}", l("ipset-exclude.txt")),
                "--dpi-desync=fake".to_string(),
                format!("--dpi-desync-repeats={}", game_repeats),
                "--dpi-desync-any-protocol=1".to_string(),
                format!("--dpi-desync-fake-unknown-udp={}", quic_g),
                "--dpi-desync-cutoff=n4".to_string(),
            ]);

            args
        };

        vec![
            Strategy {
                id: "win-alt9".to_string(),
                name: "Windows ALT9 (Recommended First)".to_string(),
                description: "Multi-split with sequence overlap 681 and fake TLS pattern.".to_string(),
                platform: Platform::Windows,
                args: build_8rule(
                    "fake,multisplit",
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=664".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_m), format!("--dpi-desync-fake-http={}", tls_m)],
                    vec!["--dpi-desync-split-seqovl=664".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), format!("--dpi-desync-fake-tls={}", tls_m), format!("--dpi-desync-fake-http={}", tls_m)],
                    10,
                ),
            },
            Strategy {
                id: "win-alt11".to_string(),
                name: "Windows ALT11".to_string(),
                description: "High-repeat fake multisplit with TS fooling.".to_string(),
                platform: Platform::Windows,
                args: build_8rule(
                    "fake,multisplit",
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-repeats=8".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-repeats=8".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g), format!("--dpi-desync-fake-tls={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=664".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-repeats=8".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_m), format!("--dpi-desync-fake-tls={}", tls_m), format!("--dpi-desync-fake-http={}", tls_m)],
                    vec!["--dpi-desync-split-seqovl=664".into(), "--dpi-desync-split-pos=1".into(), "--dpi-desync-fooling=ts".into(), "--dpi-desync-repeats=8".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_m), format!("--dpi-desync-fake-tls={}", tls_m), format!("--dpi-desync-fake-http={}", tls_m)],
                    10,
                ),
            },
            Strategy {
                id: "win-general".to_string(),
                name: "Windows general (Flowseal Default)".to_string(),
                description: "Standard Flowseal multisplit 681/568 with pattern matching.".to_string(),
                platform: Platform::Windows,
                args: build_8rule(
                    "multisplit",
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=681".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_g)],
                    vec!["--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    vec!["--dpi-desync-split-seqovl=568".into(), "--dpi-desync-split-pos=1".into(), format!("--dpi-desync-split-seqovl-pattern={}", tls_4)],
                    12,
                ),
            },
        ]
    }
}
