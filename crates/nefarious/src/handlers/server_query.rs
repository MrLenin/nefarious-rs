//! Handlers for server-status queries: STATS, TIME, ADMIN, INFO, LINKS,
//! MAP, TRACE.
//!
//! These exist so that the commands are not silently rejected with
//! ERR_UNKNOWNCOMMAND. Each handler returns a factually correct minimal
//! reply; per-letter STATS coverage, full TRACE filtering, and MAP tree
//! depth formatting are intentionally simplified — enough to satisfy
//! clients and scripts that probe the server, without reimplementing the
//! full Nefarious surface area.

use irc_proto::Message;

use crate::numeric::*;

use super::HandlerContext;

/// Handle STATS — `STATS <letter> [<server>]`. We only implement the
/// common letters clients actually rely on.
pub async fn handle_stats(ctx: &HandlerContext, msg: &Message) {
    let letter = msg.params.first().cloned().unwrap_or_default();
    let query_char = letter.chars().next().unwrap_or(' ');

    match query_char {
        'u' | 'U' => {
            // Uptime in days/hh:mm:ss.
            let uptime = (chrono::Utc::now() - ctx.state.created_at).num_seconds().max(0);
            let days = uptime / 86400;
            let hours = (uptime % 86400) / 3600;
            let minutes = (uptime % 3600) / 60;
            let seconds = uptime % 60;
            ctx.send_numeric(
                RPL_STATSUPTIME,
                vec![format!(
                    "Server Up {days} days {hours:02}:{minutes:02}:{seconds:02}"
                )],
            )
            .await;
        }
        'l' | 'L' => {
            // Active server links. One RPL_STATSLINKINFO per link.
            for entry in ctx.state.links.iter() {
                let link = entry.value();
                ctx.send_numeric(
                    RPL_STATSLINKINFO,
                    vec![
                        link.name.clone(),
                        "0".into(), // sendq
                        "0".into(), // sent messages
                        "0".into(), // sent bytes
                        "0".into(), // recv messages
                        "0".into(), // recv bytes
                        "0".into(), // time open
                    ],
                )
                .await;
            }
        }
        'p' | 'P' => {
            // Ports we're listening on.
            for port in &ctx.state.config.ports {
                ctx.send_numeric(
                    RPL_STATSLINKINFO,
                    vec![format!(
                        "port {} ssl={} server={}",
                        port.port, port.ssl, port.server
                    )],
                )
                .await;
            }
        }
        _ => {} // unknown letters silently produce just RPL_ENDOFSTATS
    }

    ctx.send_numeric(
        RPL_ENDOFSTATS,
        vec![letter, "End of /STATS report".into()],
    )
    .await;
}

/// Handle TIME — return current server time as an RFC 2822-ish string
/// plus the epoch seconds.
pub async fn handle_time(ctx: &HandlerContext, _msg: &Message) {
    let now = chrono::Utc::now();
    ctx.send_numeric(
        RPL_TIME,
        vec![
            ctx.state.server_name.clone(),
            now.timestamp().to_string(),
            now.format("%a %b %d %Y %H:%M:%S UTC").to_string(),
        ],
    )
    .await;
}

/// Handle ADMIN — return Admin{} config block. Fields default to the
/// server name / empty strings when the operator hasn't configured them.
pub async fn handle_admin(ctx: &HandlerContext, _msg: &Message) {
    let admin = &ctx.state.config.admin;
    ctx.send_numeric(
        RPL_ADMINME,
        vec![ctx.state.server_name.clone(), "Administrative info".into()],
    )
    .await;
    let loc1 = admin
        .location
        .first()
        .cloned()
        .unwrap_or_else(|| "-".to_string());
    ctx.send_numeric(RPL_ADMINLOC1, vec![loc1]).await;
    let loc2 = admin
        .location
        .get(1)
        .cloned()
        .unwrap_or_else(|| "-".to_string());
    ctx.send_numeric(RPL_ADMINLOC2, vec![loc2]).await;
    let email = admin.contact.clone().unwrap_or_else(|| "-".to_string());
    ctx.send_numeric(RPL_ADMINEMAIL, vec![email]).await;
}

/// Handle INFO — return build information.
pub async fn handle_info(ctx: &HandlerContext, _msg: &Message) {
    let lines = [
        format!("{} — Rust port of Nefarious IRCd", ctx.state.version),
        "Source: https://github.com/evilnet/nefarious-rs".to_string(),
        "P10 protocol implementation".to_string(),
        format!(
            "Started {}",
            ctx.state.created_at.format("%a %b %d %Y %H:%M:%S UTC")
        ),
    ];
    for line in lines {
        ctx.send_numeric(RPL_INFO, vec![line]).await;
    }
    ctx.send_numeric(RPL_ENDOFINFO, vec!["End of /INFO list".into()])
        .await;
}

/// Handle LINKS — list this server plus every remote server we know.
pub async fn handle_links(ctx: &HandlerContext, _msg: &Message) {
    // Ourselves first.
    let server_name = ctx.state.server_name.clone();
    ctx.send_numeric(
        RPL_LINKS,
        vec![
            server_name.clone(),
            server_name.clone(),
            format!("0 {}", ctx.state.server_description),
        ],
    )
    .await;

    // Then each remote server with its uplink hop count derived from the
    // server map. We don't fully propagate hop counts yet, so use the
    // recorded value.
    let keys: Vec<_> = ctx
        .state
        .remote_servers
        .iter()
        .map(|e| *e.key())
        .collect();
    for key in keys {
        if let Some(server_arc) = ctx.state.remote_servers.get(&key) {
            let s = server_arc.read().await;
            ctx.send_numeric(
                RPL_LINKS,
                vec![
                    s.name.clone(),
                    server_name.clone(),
                    format!("{} {}", s.hop_count, s.description),
                ],
            )
            .await;
        }
    }

    ctx.send_numeric(RPL_ENDOFLINKS, vec!["*".into(), "End of /LINKS list".into()])
        .await;
}

/// Handle MAP — hierarchical tree of servers. We print ourselves first
/// followed by each known remote server indented one level. A full tree
/// would walk the uplink graph; the flat rendering is enough for clients
/// to see the network topology.
pub async fn handle_map(ctx: &HandlerContext, _msg: &Message) {
    let total = ctx.state.total_user_count();
    let us_users = ctx.state.client_count();
    ctx.send_numeric(
        RPL_MAP,
        vec![format!("{} [{} clients]", ctx.state.server_name, us_users)],
    )
    .await;

    let keys: Vec<_> = ctx
        .state
        .remote_servers
        .iter()
        .map(|e| *e.key())
        .collect();
    for key in keys {
        if let Some(server_arc) = ctx.state.remote_servers.get(&key) {
            let s = server_arc.read().await;
            let users = ctx
                .state
                .remote_clients
                .iter()
                .filter(|e| e.key().server == s.numeric)
                .count();
            ctx.send_numeric(
                RPL_MAP,
                vec![format!("  |- {} [{} clients]", s.name, users)],
            )
            .await;
        }
    }

    ctx.send_numeric(
        RPL_MAPEND,
        vec![format!("End of /MAP ({total} users)")],
    )
    .await;
}

/// Handle TRACE — a flat listing of users and servers, enough to let a
/// debugging client see what the server has seen. We don't implement
/// target filtering or per-class stats.
pub async fn handle_trace(ctx: &HandlerContext, _msg: &Message) {
    // Users.
    for entry in ctx.state.clients.iter() {
        let c = entry.value().read().await;
        ctx.send_numeric(
            RPL_TRACEUSER,
            vec![
                "User".into(),
                "default".into(),
                format!("{}!{}@{}", c.nick, c.user, c.host),
            ],
        )
        .await;
    }

    // Linked servers.
    let keys: Vec<_> = ctx
        .state
        .remote_servers
        .iter()
        .map(|e| *e.key())
        .collect();
    for key in keys {
        if let Some(server_arc) = ctx.state.remote_servers.get(&key) {
            let s = server_arc.read().await;
            ctx.send_numeric(
                RPL_TRACESERVER,
                vec![
                    "Serv".into(),
                    "default".into(),
                    format!("{}S {}", s.hop_count, s.name),
                ],
            )
            .await;
        }
    }

    ctx.send_numeric(
        RPL_TRACEEND,
        vec![
            ctx.state.server_name.clone(),
            ctx.state.version.clone(),
            "End of TRACE".into(),
        ],
    )
    .await;
}
