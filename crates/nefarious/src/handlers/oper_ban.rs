//! Oper-invoked network ban commands.
//!
//! Handles /GLINE /SHUN /ZLINE /JUPE. All four share the same shape:
//!
//! - No args → list all bans of that kind.
//! - `+<mask> [<target>] [<expire>] :<reason>` → add.
//! - `-<mask> [<target>]` → deactivate (peers keep the record so
//!   reactivation replays cleanly).
//! - Bare `<mask>` → show details of one entry.
//!
//! We only implement global bans (target = `*`) for now. Local
//! (per-server) bans need server-tree routing that hasn't landed.
//! Oper `+o` is required; full PRIV_GLINE-style priv gating will
//! come when the PRIVS table is hooked up end-to-end.

use std::sync::Arc;

use irc_proto::Message;
use tokio::sync::RwLock;

use crate::numeric::*;

use super::HandlerContext;

pub async fn handle_gline(ctx: &HandlerContext, msg: &Message) {
    handle_ban(ctx, msg, BanKind::Gline).await;
}

pub async fn handle_shun(ctx: &HandlerContext, msg: &Message) {
    handle_ban(ctx, msg, BanKind::Shun).await;
}

pub async fn handle_zline(ctx: &HandlerContext, msg: &Message) {
    handle_ban(ctx, msg, BanKind::Zline).await;
}

pub async fn handle_jupe(ctx: &HandlerContext, msg: &Message) {
    handle_ban(ctx, msg, BanKind::Jupe).await;
}

#[derive(Debug, Clone, Copy)]
enum BanKind {
    Gline,
    Shun,
    Zline,
    Jupe,
}

impl BanKind {
    fn name(self) -> &'static str {
        match self {
            BanKind::Gline => "GLINE",
            BanKind::Shun => "SHUN",
            BanKind::Zline => "ZLINE",
            BanKind::Jupe => "JUPE",
        }
    }

    fn token(self) -> &'static str {
        // P10 server-to-server tokens as defined in
        // nefarious2 include/msg.h.
        match self {
            BanKind::Gline => "GL",
            BanKind::Shun => "SU",
            BanKind::Zline => "ZL",
            BanKind::Jupe => "JU",
        }
    }

    /// Default expiry in seconds when the oper doesn't supply one.
    /// Matches nefarious2's FEAT_GLINE_MAX / FEAT_SHUN_MAX defaults
    /// (7 days). Conservative so accidental /GLINE doesn't lock out
    /// a whole ISP permanently.
    fn default_expire_secs(self) -> u64 {
        7 * 24 * 60 * 60
    }
}

async fn handle_ban(ctx: &HandlerContext, msg: &Message, kind: BanKind) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    // No args → list all entries. We emit one notice per entry then
    // a summary. Using NOTICE rather than a dedicated numeric keeps
    // the initial landing small; STATS G/S/Z/J will reuse the store
    // with proper numerics.
    if msg.params.is_empty() || msg.params[0].is_empty() {
        list_entries(ctx, kind).await;
        return;
    }

    let arg0 = &msg.params[0];

    // Parse leading action prefix. `!` is the oper-force marker;
    // we accept it but don't currently differentiate priv levels.
    let mut body = arg0.as_str();
    if let Some(rest) = body.strip_prefix('!') {
        body = rest;
    }
    let action = match body.chars().next() {
        Some('+') => {
            body = &body[1..];
            '+'
        }
        Some('-') => {
            body = &body[1..];
            '-'
        }
        _ => {
            // Bare mask → single-entry lookup (view mode).
            show_entry(ctx, kind, body).await;
            return;
        }
    };
    let mask = body;
    if mask.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec![kind.name().into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    // Global-only for now. If the oper supplied an explicit target
    // of '*' we consume it; anything else is treated as the start
    // of the expiry/reason tail, since per-server routing isn't
    // wired. `target` is always "*" in this pass.
    let rest = &msg.params[1..];
    let (target, rest) = match rest.split_first() {
        Some((first, tail)) if first == "*" => ("*", tail),
        _ => ("*", rest),
    };

    if action == '-' {
        deactivate_entry(ctx, kind, mask, target).await;
    } else {
        activate_entry(ctx, kind, mask, target, rest).await;
    }
}

async fn list_entries(ctx: &HandlerContext, kind: BanKind) {
    let nick = ctx.client.read().await.nick.clone();
    match kind {
        BanKind::Gline => {
            for entry in ctx.state.glines.iter() {
                let gl = entry.value().read().await;
                let active = if gl.active { "+" } else { "-" };
                notice(ctx, &format!(
                    "{active}{} set by {} at {}: {}",
                    gl.mask, gl.set_by, gl.set_at.to_rfc3339(), gl.reason
                )).await;
            }
        }
        BanKind::Shun => {
            for entry in ctx.state.shuns.iter() {
                let sh = entry.value().read().await;
                let active = if sh.active { "+" } else { "-" };
                notice(ctx, &format!(
                    "{active}{} set by {} at {}: {}",
                    sh.mask, sh.set_by, sh.set_at.to_rfc3339(), sh.reason
                )).await;
            }
        }
        BanKind::Zline => {
            for entry in ctx.state.zlines.iter() {
                let zl = entry.value().read().await;
                let active = if zl.active { "+" } else { "-" };
                notice(ctx, &format!(
                    "{active}{} set by {} at {}: {}",
                    zl.mask, zl.set_by, zl.set_at.to_rfc3339(), zl.reason
                )).await;
            }
        }
        BanKind::Jupe => {
            for entry in ctx.state.jupes.iter() {
                let ju = entry.value().read().await;
                let active = if ju.active { "+" } else { "-" };
                notice(ctx, &format!(
                    "{active}{} set by {} at {}: {}",
                    ju.server, ju.set_by, ju.set_at.to_rfc3339(), ju.reason
                )).await;
            }
        }
    }
    notice(ctx, &format!("End of /{} list for {nick}", kind.name())).await;
}

async fn show_entry(ctx: &HandlerContext, kind: BanKind, mask: &str) {
    let key = mask.to_ascii_lowercase();
    match kind {
        BanKind::Gline => {
            if let Some(e) = ctx.state.glines.get(&key) {
                let gl = e.read().await;
                notice(ctx, &format!(
                    "GLINE {} ({}active): {}",
                    gl.mask, if gl.active { "" } else { "in" }, gl.reason
                )).await;
                return;
            }
        }
        BanKind::Shun => {
            if let Some(e) = ctx.state.shuns.get(&key) {
                let sh = e.read().await;
                notice(ctx, &format!(
                    "SHUN {} ({}active): {}",
                    sh.mask, if sh.active { "" } else { "in" }, sh.reason
                )).await;
                return;
            }
        }
        BanKind::Zline => {
            if let Some(e) = ctx.state.zlines.get(&key) {
                let zl = e.read().await;
                notice(ctx, &format!(
                    "ZLINE {} ({}active): {}",
                    zl.mask, if zl.active { "" } else { "in" }, zl.reason
                )).await;
                return;
            }
        }
        BanKind::Jupe => {
            if let Some(e) = ctx.state.jupes.get(&key) {
                let ju = e.read().await;
                notice(ctx, &format!(
                    "JUPE {} ({}active): {}",
                    ju.server, if ju.active { "" } else { "in" }, ju.reason
                )).await;
                return;
            }
        }
    }
    notice(ctx, &format!("No {} matches {mask}", kind.name())).await;
}

async fn activate_entry(
    ctx: &HandlerContext,
    kind: BanKind,
    mask: &str,
    target: &str,
    rest: &[String],
) {
    // Expiry parsing. Accept either a bare integer (absolute epoch
    // is not supported locally — treat all inputs as relative
    // seconds), or a unit-suffixed interval like `3d`. Missing
    // expiry defaults to the kind's built-in max.
    let (expire_secs, reason) = parse_expire_and_reason(rest, kind.default_expire_secs());

    let now = chrono::Utc::now();
    let expires_at = if expire_secs > 0 {
        Some(now + chrono::Duration::seconds(expire_secs as i64))
    } else {
        None
    };
    let lastmod = now.timestamp() as u64;
    let set_by = ctx.client.read().await.prefix();

    let key = mask.to_ascii_lowercase();
    match kind {
        BanKind::Gline => {
            let gl = crate::gline::Gline {
                mask: mask.to_string(),
                reason: reason.clone(),
                expires_at,
                set_by: set_by.clone(),
                set_at: now,
                lastmod,
                lifetime: None,
                active: true,
            };
            ctx.state.glines.insert(key, Arc::new(RwLock::new(gl)));
            // Kick any local matches immediately.
            kick_matches_gline(ctx, mask, &reason).await;
        }
        BanKind::Shun => {
            let sh = crate::shun::Shun {
                mask: mask.to_string(),
                reason: reason.clone(),
                expires_at,
                set_by: set_by.clone(),
                set_at: now,
                lastmod,
                lifetime: None,
                active: true,
            };
            ctx.state.shuns.insert(key, Arc::new(RwLock::new(sh)));
        }
        BanKind::Zline => {
            let zl = crate::zline::Zline {
                mask: mask.to_string(),
                reason: reason.clone(),
                expires_at,
                set_by: set_by.clone(),
                set_at: now,
                lastmod,
                lifetime: None,
                active: true,
            };
            ctx.state.zlines.insert(key, Arc::new(RwLock::new(zl)));
            kick_matches_zline(ctx, mask, &reason).await;
        }
        BanKind::Jupe => {
            let ju = crate::jupe::Jupe {
                server: mask.to_string(),
                reason: reason.clone(),
                expires_at,
                set_by: set_by.clone(),
                set_at: now,
                lastmod,
                active: true,
            };
            ctx.state.jupes.insert(key, Arc::new(RwLock::new(ju)));
        }
    }

    // Propagate to every S2S peer. Origin is our server name — C's
    // forward_gline uses the setting user's numeric for oper-
    // originated adds, but our wire format accepts either; server-
    // origin is simpler and stays valid even if the oper logs out
    // before the update propagates.
    let origin = ctx.state.server_name.clone();
    let wire = match kind {
        BanKind::Jupe => format!(
            "{origin} {token} {target} +{mask} {expire_secs} {lastmod} :{reason}",
            token = kind.token(),
        ),
        _ => format!(
            "{origin} {token} {target} +{mask} {expire_secs} {lastmod} 0 :{reason}",
            token = kind.token(),
        ),
    };
    for entry in ctx.state.links.iter() {
        entry.value().send_line(wire.clone()).await;
    }

    notice(
        ctx,
        &format!("Added {} +{mask} expiring in {expire_secs}s", kind.name()),
    )
    .await;
}

async fn deactivate_entry(
    ctx: &HandlerContext,
    kind: BanKind,
    mask: &str,
    target: &str,
) {
    let key = mask.to_ascii_lowercase();
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let mut removed = false;
    match kind {
        BanKind::Gline => {
            if let Some(e) = ctx.state.glines.get(&key) {
                let mut gl = e.write().await;
                gl.active = false;
                gl.lastmod = now_secs;
                removed = true;
            }
        }
        BanKind::Shun => {
            if let Some(e) = ctx.state.shuns.get(&key) {
                let mut sh = e.write().await;
                sh.active = false;
                sh.lastmod = now_secs;
                removed = true;
            }
        }
        BanKind::Zline => {
            if let Some(e) = ctx.state.zlines.get(&key) {
                let mut zl = e.write().await;
                zl.active = false;
                zl.lastmod = now_secs;
                removed = true;
            }
        }
        BanKind::Jupe => {
            if let Some(e) = ctx.state.jupes.get(&key) {
                let mut ju = e.write().await;
                ju.active = false;
                ju.lastmod = now_secs;
                removed = true;
            }
        }
    }
    if !removed {
        notice(ctx, &format!("No {} matches {mask}", kind.name())).await;
        return;
    }

    let origin = ctx.state.server_name.clone();
    let wire = format!(
        "{origin} {token} {target} -{mask} {now_secs}",
        token = kind.token(),
    );
    for entry in ctx.state.links.iter() {
        entry.value().send_line(wire.clone()).await;
    }
    notice(ctx, &format!("Deactivated {} -{mask}", kind.name())).await;
}

fn parse_expire_and_reason(rest: &[String], default_secs: u64) -> (u64, String) {
    // Two shapes we accept:
    //   [<expire>] [:<reason>]
    //   [:<reason>]  (no expire → default)
    // We consume up to one leading param as expire if it parses
    // as a plain integer or an interval string.
    if rest.is_empty() {
        return (default_secs, "No reason".into());
    }
    let first = &rest[0];
    let parsed_secs = crate::gline::parse_interval(first);
    if parsed_secs > 0 && !first.contains(' ') {
        // First param is expiry — reason is everything else.
        let reason = if rest.len() > 1 {
            rest[1..].join(" ")
        } else {
            "No reason".into()
        };
        (parsed_secs, reason)
    } else {
        // No expiry — default, whole rest is reason.
        (default_secs, rest.join(" "))
    }
}

async fn kick_matches_gline(ctx: &HandlerContext, mask: &str, reason: &str) {
    let mut victims = Vec::new();
    for entry in ctx.state.clients.iter() {
        let c = entry.value().read().await;
        if c.is_registered() {
            let ip = c.addr.ip();
            if crate::gline::user_host_mask_matches(mask, &c.user, &c.host, ip) {
                victims.push(entry.key().clone());
            }
        }
    }
    for id in victims {
        if let Some(arc) = ctx.state.clients.get(&id) {
            arc.read()
                .await
                .request_disconnect(format!("G-lined: {reason}"));
        }
    }
}

async fn kick_matches_zline(ctx: &HandlerContext, mask: &str, reason: &str) {
    let mut victims = Vec::new();
    for entry in ctx.state.clients.iter() {
        let c = entry.value().read().await;
        if c.is_registered() {
            if crate::gline::ip_mask_matches(mask, c.addr.ip()) {
                victims.push(entry.key().clone());
            }
        }
    }
    for id in victims {
        if let Some(arc) = ctx.state.clients.get(&id) {
            arc.read()
                .await
                .request_disconnect(format!("Z-lined: {reason}"));
        }
    }
}

async fn notice(ctx: &HandlerContext, text: &str) {
    let c = ctx.client.read().await;
    c.send(irc_proto::Message::with_source(
        &ctx.state.server_name,
        irc_proto::Command::Notice,
        vec![c.nick.clone(), text.to_string()],
    ));
}
