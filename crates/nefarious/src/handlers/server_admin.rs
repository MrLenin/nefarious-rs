//! Server-admin commands: /REHASH, /RESTART, /DIE.
//!
//! All three are oper-gated and are extremely disruptive, so they
//! sit behind the +o check and log prominently. Only /REHASH
//! implements a live code path today; RESTART and DIE emit a
//! protocol-correct refusal instead of actually restarting the
//! process, since neither has a clean shutdown path landed yet.

use irc_proto::Message;

use crate::numeric::*;

use super::HandlerContext;

/// Reply numeric for a successful /REHASH acknowledgement. Sent to
/// the requesting oper; bystanders see nothing.
const RPL_REHASHING: u16 = 382;

pub async fn handle_rehash(ctx: &HandlerContext, _msg: &Message) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    // Which config file to cite in the reply. C nefarious2 sends
    // "<path> :Rehashing" but we don't currently track the config
    // path on state; use a descriptive placeholder.
    let cfg_label = "ircd.conf";
    ctx.send_numeric(
        RPL_REHASHING,
        vec![cfg_label.to_string(), "Rehashing".into()],
    )
    .await;

    // MOTD is the currently-reloadable piece. Future rehash work
    // would swap the whole Config Arc and re-read operator blocks,
    // kill lines, features, etc.
    match ctx.state.reload_motd() {
        Ok(n) => {
            tracing::info!(
                "/REHASH by {nick}: MOTD reloaded ({n} lines)",
                nick = ctx.client.read().await.nick,
            );
            let notice_text = format!("MOTD reloaded: {n} lines");
            notice(ctx, &notice_text).await;
        }
        Err(e) => {
            tracing::warn!("/REHASH by oper: MOTD reload failed: {e}");
            notice(ctx, &format!("MOTD reload failed: {e}")).await;
        }
    }
}

pub async fn handle_restart(ctx: &HandlerContext, _msg: &Message) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }
    // We don't implement actual restart — a tokio runtime can't
    // safely re-exec itself, and the wrapper responsibility belongs
    // to the orchestrator (systemd/docker/k8s). Emit a notice
    // explaining and log the attempt.
    tracing::warn!(
        "/RESTART attempted by {}; not implemented — ignoring",
        ctx.client.read().await.nick
    );
    notice(
        ctx,
        "RESTART is not implemented — signal the orchestrator (systemd/docker) instead",
    )
    .await;
}

/// Oper-invoked /CONNECT — open an outbound S2S link to a
/// configured peer. Syntax:
///   `CONNECT <server_name> [<port>] [<target>]`
/// Target routing (the third param) isn't supported; we only
/// initiate from *this* server for now.
pub async fn handle_connect(ctx: &HandlerContext, msg: &Message) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }
    let name = match msg.params.first() {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["CONNECT".into(), "Not enough parameters".into()],
            )
            .await;
            return;
        }
    };
    let port = msg.params.get(1).and_then(|s| s.parse::<u16>().ok());

    notice(ctx, &format!("Initiating outbound link to {name}")).await;

    // Spawn — the handshake + link handling live for the life of
    // the connection. The oper's /CONNECT returns immediately;
    // result is reported asynchronously via server log and, on
    // failure, a NOTICE back to the oper if we can snapshot their
    // send channel.
    let state = ctx.state.clone();
    let send_ch = ctx.client.read().await.sender.clone();
    let server_name = ctx.state.server_name.clone();
    let nick = ctx.client.read().await.nick.clone();
    tokio::spawn(async move {
        match crate::server::initiate_server_connection(state, name.clone(), port).await {
            Ok(()) => {
                tracing::info!("/CONNECT {name}: link established");
            }
            Err(e) => {
                tracing::warn!("/CONNECT {name}: {e}");
                let _ = send_ch
                    .send(irc_proto::Message::with_source(
                        &server_name,
                        irc_proto::Command::Notice,
                        vec![nick, format!("CONNECT {name} failed: {e}")],
                    ))
                    .await;
            }
        }
    });
}

pub async fn handle_die(ctx: &HandlerContext, _msg: &Message) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }
    tracing::warn!(
        "/DIE attempted by {}; not implemented — ignoring",
        ctx.client.read().await.nick
    );
    notice(
        ctx,
        "DIE is not implemented — send SIGTERM to the process instead",
    )
    .await;
}

async fn notice(ctx: &HandlerContext, text: &str) {
    let c = ctx.client.read().await;
    c.send(irc_proto::Message::with_source(
        &ctx.state.server_name,
        irc_proto::Command::Notice,
        vec![c.nick.clone(), text.to_string()],
    ));
}
