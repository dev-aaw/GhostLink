use crate::engine::types::{ProbeResult, ProbeRule, ProbeSummary, ProbeTier};
use anyhow::Result;
use regex::Regex;
use std::time::{Duration, Instant};

pub const BLOCK_NOTICE_REGEX: &str = r"(?i)(access (to this (site|service|page) )?(is )?blocked|site (is )?blocked|erişimi? engellen|mahkeme kararı|5651 sayılı|доступ (к сайту )?ограничен|ресурс заблокирован|внесен в реестр)";
pub const PNG_MAGIC_HEX: &str = "89504e470d0a1a0a";

pub struct ProbeRunner {
    rules: Vec<ProbeRule>,
}

impl Default for ProbeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeRunner {
    pub fn new() -> Self {
        let rules = vec![
            // 1. YouTube Video / CDN Screening Probe
            ProbeRule {
                id: "youtube-video".to_string(),
                label: "YouTube Video Redirector".to_string(),
                url: "https://redirector.googlevideo.com/".to_string(),
                tier: ProbeTier::Screen,
                expected_statuses: vec![204, 404],
                required_body_pattern: None,
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
            // 2. Discord REST API Gateway Screening Probe
            ProbeRule {
                id: "discord-api".to_string(),
                label: "Discord Gateway API".to_string(),
                url: "https://discord.com/api/v10/gateway".to_string(),
                tier: ProbeTier::Screen,
                expected_statuses: vec![200],
                required_body_pattern: Some(r#""url"\s*:\s*"wss://"#.to_string()),
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
            // 3. YouTube Full Home Shell Probe
            ProbeRule {
                id: "youtube-home".to_string(),
                label: "YouTube Web Interface".to_string(),
                url: "https://www.youtube.com/".to_string(),
                tier: ProbeTier::Full,
                expected_statuses: vec![200],
                required_body_pattern: Some(r"(ytcfg|ytInitialData|<title>[^<]*YouTube)".to_string()),
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
            // 4. Discord CDN PNG Asset Probe
            ProbeRule {
                id: "discord-cdn".to_string(),
                label: "Discord CDN Media".to_string(),
                url: "https://cdn.discordapp.com/embed/avatars/0.png".to_string(),
                tier: ProbeTier::Full,
                expected_statuses: vec![200],
                required_body_pattern: None,
                reject_body_pattern: None,
                expected_hex_prefix: Some(PNG_MAGIC_HEX.to_string()),
            },
            // 5. WikiLeaks Probe
            ProbeRule {
                id: "wikileaks".to_string(),
                label: "WikiLeaks Portal".to_string(),
                url: "https://www.wikileaks.org/".to_string(),
                tier: ProbeTier::Full,
                expected_statuses: vec![200],
                required_body_pattern: Some(r"(?i)(wikileaks|<title>[^<]*wikileaks)".to_string()),
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
            // 6. Instagram Probe
            ProbeRule {
                id: "instagram".to_string(),
                label: "Instagram Portal".to_string(),
                url: "https://www.instagram.com/".to_string(),
                tier: ProbeTier::Full,
                expected_statuses: vec![200],
                required_body_pattern: Some(r"(?i)(instagram|<title>[^<]*instagram)".to_string()),
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
            // 7. X (Twitter) Probe
            ProbeRule {
                id: "x-twitter".to_string(),
                label: "X (Twitter) Portal".to_string(),
                url: "https://x.com/".to_string(),
                tier: ProbeTier::Full,
                expected_statuses: vec![200],
                required_body_pattern: Some(r"(?i)(x\.com|twitter|<title>[^<]*x)".to_string()),
                reject_body_pattern: Some(BLOCK_NOTICE_REGEX.to_string()),
                expected_hex_prefix: None,
            },
        ];

        Self { rules }
    }

    /// Build a reqwest Client optionally routed through the local SOCKS proxy (used for macOS tpws testing).
    pub fn build_client(&self, socks_proxy: Option<&str>, timeout: Duration) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        if let Some(proxy_url) = socks_proxy {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        Ok(builder.build()?)
    }

    /// Run a single probe rule with rigorous response body / status validation.
    pub async fn execute_probe(&self, client: &reqwest::Client, rule: &ProbeRule) -> ProbeResult {
        let start = Instant::now();

        match client.get(&rule.url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let latency_ms = start.elapsed().as_millis() as u64;

                // 1. Status Code Check
                if !rule.expected_statuses.contains(&status) {
                    return ProbeResult {
                        rule_id: rule.id.clone(),
                        label: rule.label.clone(),
                        url: rule.url.clone(),
                        success: false,
                        status_code: Some(status),
                        latency_ms,
                        error: Some(format!("Unexpected HTTP status: {}", status)),
                    };
                }

                // 2. Fetch body sample (up to 64KB)
                let bytes = match response.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return ProbeResult {
                            rule_id: rule.id.clone(),
                            label: rule.label.clone(),
                            url: rule.url.clone(),
                            success: false,
                            status_code: Some(status),
                            latency_ms: start.elapsed().as_millis() as u64,
                            error: Some(format!("Failed to read response body: {}", e)),
                        };
                    }
                };

                let sample_len = std::cmp::min(bytes.len(), 65536);
                let sample = &bytes[..sample_len];

                // 3. Hex prefix check (for PNG/binary files)
                if let Some(ref hex_prefix) = rule.expected_hex_prefix {
                    let actual_hex = hex::encode(&sample[..std::cmp::min(sample.len(), 8)]);
                    if !actual_hex.to_lowercase().starts_with(&hex_prefix.to_lowercase()) {
                        return ProbeResult {
                            rule_id: rule.id.clone(),
                            label: rule.label.clone(),
                            url: rule.url.clone(),
                            success: false,
                            status_code: Some(status),
                            latency_ms,
                            error: Some(format!("Hex header mismatch: expected {}, got {}", hex_prefix, actual_hex)),
                        };
                    }
                }

                let text_sample = String::from_utf8_lossy(sample);

                // 4. Reject body pattern check (e.g. ISP block warning page)
                if let Some(ref reject_pattern) = rule.reject_body_pattern {
                    if let Ok(re) = Regex::new(reject_pattern) {
                        if re.is_match(&text_sample) {
                            return ProbeResult {
                                rule_id: rule.id.clone(),
                                label: rule.label.clone(),
                                url: rule.url.clone(),
                                success: false,
                                status_code: Some(status),
                                latency_ms,
                                error: Some("Response matched ISP censorship/block page pattern".to_string()),
                            };
                        }
                    }
                }

                // 5. Required body pattern check
                if let Some(ref req_pattern) = rule.required_body_pattern {
                    if let Ok(re) = Regex::new(req_pattern) {
                        if !re.is_match(&text_sample) {
                            return ProbeResult {
                                rule_id: rule.id.clone(),
                                label: rule.label.clone(),
                                url: rule.url.clone(),
                                success: false,
                                status_code: Some(status),
                                latency_ms,
                                error: Some(format!("Required pattern '{}' not found in body", req_pattern)),
                            };
                        }
                    }
                }

                ProbeResult {
                    rule_id: rule.id.clone(),
                    label: rule.label.clone(),
                    url: rule.url.clone(),
                    success: true,
                    status_code: Some(status),
                    latency_ms,
                    error: None,
                }
            }
            Err(err) => ProbeResult {
                rule_id: rule.id.clone(),
                label: rule.label.clone(),
                url: rule.url.clone(),
                success: false,
                status_code: None,
                latency_ms: start.elapsed().as_millis() as u64,
                error: Some(err.to_string()),
            },
        }
    }

    /// Run screening rules first (cheap & fast). If all screen rules pass, run full rules.
    pub async fn run_suite(&self, strategy_id: &str, socks_proxy: Option<&str>) -> ProbeSummary {
        let client = match self.build_client(socks_proxy, Duration::from_millis(3500)) {
            Ok(c) => c,
            Err(e) => {
                return ProbeSummary {
                    strategy_id: strategy_id.to_string(),
                    success: false,
                    total_latency_ms: 0,
                    results: vec![ProbeResult {
                        rule_id: "init".to_string(),
                        label: "Client initialization".to_string(),
                        url: "".to_string(),
                        success: false,
                        status_code: None,
                        latency_ms: 0,
                        error: Some(e.to_string()),
                    }],
                };
            }
        };

        let mut results = Vec::new();
        let mut total_latency = 0;

        // 1. Run Screening probes first (fast fail)
        for rule in self.rules.iter().filter(|r| r.tier == ProbeTier::Screen) {
            let res = self.execute_probe(&client, rule).await;
            total_latency += res.latency_ms;
            let success = res.success;
            results.push(res);
            if !success {
                return ProbeSummary {
                    strategy_id: strategy_id.to_string(),
                    success: false,
                    total_latency_ms: total_latency,
                    results,
                };
            }
        }

        // 2. Run Full probes
        for rule in self.rules.iter().filter(|r| r.tier == ProbeTier::Full) {
            let res = self.execute_probe(&client, rule).await;
            total_latency += res.latency_ms;
            let success = res.success;
            results.push(res);
            if !success {
                return ProbeSummary {
                    strategy_id: strategy_id.to_string(),
                    success: false,
                    total_latency_ms: total_latency,
                    results,
                };
            }
        }

        ProbeSummary {
            strategy_id: strategy_id.to_string(),
            success: true,
            total_latency_ms: total_latency,
            results,
        }
    }
}
