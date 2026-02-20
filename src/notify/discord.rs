#![allow(dead_code)]
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Discord notification channel with webhook-based embed messages.
//!
//! Sends notifications and approval requests to a Discord channel via
//! incoming webhook URL. Messages use Discord's native embed format with
//! severity-based coloring.
//!
//! Interactive bot features (slash commands, button interactions) are not
//! yet implemented — approval responses must go through the TUI or API.

use async_trait::async_trait;
use serde_json::json;

use crate::approval::{ApprovalRequest, ApprovalResolution};
use crate::config::DiscordConfig;
use crate::core::alerts::Severity;
use super::{Notification, NotificationChannel};

/// Discord notification channel using webhook embeds.
///
/// Posts color-coded embed messages to a Discord channel via the configured
/// webhook URL. The webhook URL is bound to a specific channel at creation
/// time on Discord's side, so no channel ID is needed per-message.
pub struct DiscordChannel {
    webhook_url: String,
    enabled: bool,
    client: reqwest::Client,
}

impl DiscordChannel {
    /// Create a new Discord channel from configuration.
    ///
    /// The channel is considered enabled only when `config.enabled` is `true`
    /// **and** a non-empty `webhook_url` is provided.
    pub fn new(config: &DiscordConfig) -> Self {
        Self {
            webhook_url: config.webhook_url.clone(),
            enabled: config.enabled && !config.webhook_url.is_empty(),
            client: reqwest::Client::new(),
        }
    }

    /// POST a JSON payload to the Discord webhook URL.
    ///
    /// Returns an error if the request fails or the response status is not
    /// successful (2xx).
    async fn post_webhook(&self, payload: &serde_json::Value) -> anyhow::Result<()> {
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Discord webhook failed ({}): {}", status, body);
        }

        Ok(())
    }
}

/// Map a [`Severity`] to a Discord embed color (decimal u32).
///
/// These match the Slack attachment colors but as integers for Discord's API:
/// - Info: green (`0x36a64f` = `3581519`)
/// - Warning: goldenrod (`0xdaa520` = `14329120`)
/// - Critical: red (`0xdc3545` = `14431557`)
fn severity_color(severity: &Severity) -> u32 {
    match severity {
        Severity::Info => 0x36a64f,
        Severity::Warning => 0xdaa520,
        Severity::Critical => 0xdc3545,
    }
}

/// Build a Discord webhook payload with an embed for a notification.
///
/// Produces the standard Discord embed format:
/// ```json
/// {
///   "username": "ClawTower",
///   "embeds": [{
///     "title": "{emoji} {title}",
///     "description": "body text",
///     "color": 14431557,
///     "fields": [...],
///     "timestamp": "2026-02-20T12:00:00+00:00"
///   }]
/// }
/// ```
fn build_discord_embed(notification: &Notification) -> serde_json::Value {
    json!({
        "username": "ClawTower",
        "embeds": [{
            "title": format!("{} {}", notification.severity.emoji(), notification.title),
            "description": notification.body,
            "color": severity_color(&notification.severity),
            "fields": [
                { "name": "Severity", "value": notification.severity.to_string(), "inline": true },
                { "name": "Source", "value": notification.source, "inline": true },
            ],
            "timestamp": chrono::Utc::now().to_rfc3339()
        }]
    })
}

#[async_trait]
impl NotificationChannel for DiscordChannel {
    fn name(&self) -> &str {
        "discord"
    }

    fn is_available(&self) -> bool {
        self.enabled && !self.webhook_url.is_empty()
    }

    async fn send_approval_request(&self, request: &ApprovalRequest) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let payload = json!({
            "username": "ClawTower",
            "embeds": [{
                "title": format!("{} Approval Request", request.severity.emoji()),
                "description": format!("A command requires human approval before execution."),
                "color": severity_color(&request.severity),
                "fields": [
                    { "name": "Command", "value": format!("`{}`", request.command), "inline": false },
                    { "name": "Agent", "value": request.agent, "inline": true },
                    { "name": "Source", "value": request.source.to_string(), "inline": true },
                    { "name": "Context", "value": request.context, "inline": false },
                ],
                "footer": {
                    "text": "Respond via TUI or API \u{2014} Discord interactive buttons not yet supported."
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        self.post_webhook(&payload).await
    }

    async fn send_resolution(
        &self,
        request: &ApprovalRequest,
        resolution: &ApprovalResolution,
    ) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let (color, status_text, emoji) = match resolution {
            ApprovalResolution::Approved { .. } => (0x36a64f_u32, "Approved", "\u{2705}"),
            ApprovalResolution::Denied { .. } => (0xdc3545_u32, "Denied", "\u{274c}"),
            ApprovalResolution::TimedOut { .. } => (0xdaa520_u32, "Timed Out", "\u{23f0}"),
        };

        let payload = json!({
            "username": "ClawTower",
            "embeds": [{
                "title": format!("{} Request Resolved", emoji),
                "description": format!("{} for `{}`", resolution, request.command),
                "color": color,
                "fields": [
                    { "name": "Status", "value": status_text, "inline": true },
                    { "name": "Command", "value": format!("`{}`", request.command), "inline": true },
                ],
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        self.post_webhook(&payload).await
    }

    async fn send_notification(&self, notification: &Notification) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let payload = build_discord_embed(notification);
        self.post_webhook(&payload).await
    }
}

/// Verify a Discord interaction webhook signature.
///
/// This is a stub that always returns `false`. When the Discord bot is
/// implemented, this will use Ed25519 verification against the application
/// public key.
pub fn verify_discord_signature(
    _public_key: &str,
    _signature: &str,
    _timestamp: &str,
    _body: &str,
) -> bool {
    false // Not yet implemented
}

/// Parse a Discord interaction payload into an approval response.
///
/// This is a stub that always returns an error. When the Discord bot is
/// implemented, this will extract the request ID, approved/denied decision,
/// and the responding user from the interaction JSON.
///
/// # Returns
///
/// A tuple of `(request_id, approved, responder)` on success.
pub fn parse_discord_interaction(_body: &str) -> anyhow::Result<(String, bool, String)> {
    anyhow::bail!("Discord interactions not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use chrono::Utc;

    use crate::approval::ApprovalSource;
    use crate::core::alerts::Severity;

    /// Helper: create a test approval request.
    fn make_request() -> ApprovalRequest {
        ApprovalRequest::new(
            ApprovalSource::ClawSudo {
                policy_rule: Some("test-rule".to_string()),
            },
            "apt install curl".to_string(),
            "openclaw".to_string(),
            Severity::Warning,
            "test context".to_string(),
            Duration::from_secs(300),
        )
    }

    #[test]
    fn test_discord_channel_name() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        assert_eq!(channel.name(), "discord");
    }

    #[test]
    fn test_discord_not_available_disabled() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        assert!(!channel.is_available());
    }

    #[test]
    fn test_discord_available_with_webhook() {
        let mut config = DiscordConfig::default();
        config.enabled = true;
        config.webhook_url = "https://discord.com/api/webhooks/123/abc".to_string();
        let channel = DiscordChannel::new(&config);
        assert!(channel.is_available());
    }

    #[test]
    fn test_discord_not_available_without_webhook() {
        let mut config = DiscordConfig::default();
        config.enabled = true;
        // webhook_url remains empty
        let channel = DiscordChannel::new(&config);
        assert!(!channel.is_available());
    }

    #[tokio::test]
    async fn test_discord_send_is_noop_when_disabled() {
        let config = DiscordConfig::default();
        let channel = DiscordChannel::new(&config);
        let request = make_request();
        let resolution = ApprovalResolution::Approved {
            by: "admin".to_string(),
            via: "discord".to_string(),
            message: None,
            at: Utc::now(),
        };

        channel
            .send_approval_request(&request)
            .await
            .expect("send_approval_request should succeed when disabled");

        channel
            .send_resolution(&request, &resolution)
            .await
            .expect("send_resolution should succeed when disabled");

        let notification = Notification::new(
            Severity::Warning,
            "Test notification".to_string(),
            "Test body".to_string(),
            "test".to_string(),
        );
        channel
            .send_notification(&notification)
            .await
            .expect("send_notification should succeed when disabled");
    }

    #[test]
    fn test_discord_notification_payload_format() {
        let notification = Notification::new(
            Severity::Critical,
            "Privilege escalation detected".to_string(),
            "User 1000 ran sudo chattr".to_string(),
            "auditd".to_string(),
        );

        let payload = build_discord_embed(&notification);

        // Must have username
        assert_eq!(payload["username"], "ClawTower");

        // Must have embeds array with one embed
        let embeds = payload["embeds"].as_array().expect("embeds must be an array");
        assert_eq!(embeds.len(), 1);

        let embed = &embeds[0];

        // Title includes severity emoji and notification title
        let title = embed["title"].as_str().unwrap();
        assert!(title.contains("Privilege escalation detected"));

        // Description is the notification body
        assert_eq!(embed["description"], "User 1000 ran sudo chattr");

        // Color is Critical red
        assert_eq!(embed["color"], 0xdc3545_u32);

        // Fields: Severity and Source
        let fields = embed["fields"].as_array().expect("fields must be an array");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["name"], "Severity");
        assert_eq!(fields[0]["value"], "CRIT");
        assert_eq!(fields[0]["inline"], true);
        assert_eq!(fields[1]["name"], "Source");
        assert_eq!(fields[1]["value"], "auditd");
        assert_eq!(fields[1]["inline"], true);

        // Timestamp must be present (ISO 8601)
        assert!(embed["timestamp"].as_str().is_some());
    }

    #[test]
    fn test_discord_severity_colors() {
        assert_eq!(severity_color(&Severity::Info), 0x36a64f);
        assert_eq!(severity_color(&Severity::Warning), 0xdaa520);
        assert_eq!(severity_color(&Severity::Critical), 0xdc3545);
    }

    #[test]
    fn test_verify_discord_signature_always_false() {
        assert!(!verify_discord_signature("key", "sig", "ts", "body"));
    }

    #[test]
    fn test_parse_discord_interaction_always_errors() {
        let result = parse_discord_interaction("{}");
        assert!(result.is_err());
    }
}
