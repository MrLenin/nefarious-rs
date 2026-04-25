
use irc_proto::{Command, Message};

use crate::numeric::*;

use super::HandlerContext;

/// Handle WALLOPS — broadcast an operator-originated message to every
/// user that has set mode `+w` (wallops-receiver) and forward it onto
/// the linked server so remote wallops-receivers also see it.
///
/// Restricted to local operators because WALLOPS is a trusted channel
/// for cross-network admin announcements.
pub async fn handle_wallops(ctx: &HandlerContext, msg: &Message) {
    let text = match msg.params.first() {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["WALLOPS".into(), "Not enough parameters".into()],
            )
            .await;
            return;
        }
    };

    // Operator check.
    let (prefix, is_oper) = {
        let c = ctx.client.read().await;
        (c.prefix(), c.modes.contains(&'o'))
    };
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    let wallops_msg = Message::with_source(&prefix, Command::Wallops, vec![text.clone()]);
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);

    // Deliver to every local +w user.
    for entry in ctx.state.clients.iter() {
        let c = entry.value().read().await;
        if c.modes.contains(&'w') {
            c.send_from(wallops_msg.clone(), &src);
        }
    }

    // Route to the linked server so remote +w users get it too.
    if let Some(link) = ctx.state.get_link() {
        let client_id = ctx.client_id().await;
        let numeric = crate::s2s::routing::local_numeric(&ctx.state, client_id);
        link.send_line(format!("{numeric} WA :{text}")).await;
    }
}

/// Handle KILL — operator-forced disconnect of a user.
///
/// `/KILL <nick> :<reason>` routes to the user's home server via
/// the P10 `D` token when they're remote, or teardowns locally and
/// announces QUIT across the network when they're one of ours.
/// Opers only. A wallops-style server notice lets every +w user
/// know a kill just happened, which matches nefarious2
/// m_kill.c:mo_kill — operator transparency is part of the kill
/// contract.
pub async fn handle_kill(ctx: &HandlerContext, msg: &Message) {
    let target = match msg.params.first() {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["KILL".into(), "Not enough parameters".into()],
            )
            .await;
            return;
        }
    };

    let (killer_prefix, killer_nick, is_oper) = {
        let c = ctx.client.read().await;
        (c.prefix(), c.nick.clone(), c.modes.contains(&'o'))
    };
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    // Reason is the last param; if absent, synthesize the
    // nefarious2 default so peers see a non-empty string.
    let raw_reason = msg
        .params
        .get(1)
        .cloned()
        .unwrap_or_else(|| "No reason".to_string());
    // Prefix the reason with "<our_server>!<killer>" so everyone
    // downstream knows who issued the kill. Matches the
    // "path!nick (reason)" tail C emits.
    let stamped_reason = format!(
        "{server}!{killer} ({raw_reason})",
        server = ctx.state.server_name,
        killer = killer_nick,
    );

    // Local target first — short-circuit if we own the victim.
    if let Some(victim_arc) = ctx.state.find_client_by_nick(&target) {
        let (victim_nick, victim_numeric) = {
            let v = victim_arc.read().await;
            let numeric = crate::s2s::routing::local_numeric(&ctx.state, v.id);
            (v.nick.clone(), numeric)
        };

        // Announce to the network first, before the local client
        // drops — peers need to learn of the death regardless of
        // whether our QUIT fan-out races the disconnect.
        let killer_numeric_wire = {
            let c = ctx.client.read().await;
            crate::s2s::routing::local_numeric(&ctx.state, c.id)
        };
        let kill_wire = format!(
            "{killer_numeric_wire} D {victim_numeric} :{stamped_reason}"
        );
        for entry in ctx.state.links.iter() {
            entry.value().send_line(kill_wire.clone()).await;
        }

        // Local teardown — request_disconnect drives the normal
        // QUIT broadcast so every local channel-mate sees them
        // leave, same shape as a self-initiated /QUIT.
        victim_arc
            .read()
            .await
            .request_disconnect(format!("Killed ({stamped_reason})"));

        // Server notice to +w users (local only — the remote side
        // will see its own copy when they process the D token).
        announce_kill(ctx, &killer_prefix, &victim_nick, &stamped_reason).await;
        return;
    }

    // Remote target — route the kill token via S2S. We use the
    // target's numeric when we have it; otherwise fall back to the
    // raw nick and let peers resolve.
    if let Some(remote_arc) = ctx.state.find_remote_by_nick(&target) {
        let r = remote_arc.read().await;
        let victim_numeric = r.numeric;
        let victim_nick = r.nick.clone();
        drop(r);

        let killer_numeric_wire = {
            let c = ctx.client.read().await;
            crate::s2s::routing::local_numeric(&ctx.state, c.id)
        };
        let kill_wire = format!(
            "{killer_numeric_wire} D {victim_numeric} :{stamped_reason}"
        );
        for entry in ctx.state.links.iter() {
            entry.value().send_line(kill_wire.clone()).await;
        }

        // Drop from our own remote_clients table so we don't keep
        // stale state until the peer's QUIT echoes back.
        ctx.state.remove_remote_client(victim_numeric).await;

        announce_kill(ctx, &killer_prefix, &victim_nick, &stamped_reason).await;
        return;
    }

    // No such user on either side.
    ctx.send_numeric(
        ERR_NOSUCHNICK,
        vec![target, "No such nick/channel".into()],
    )
    .await;
}

/// Emit a local +w server notice so every wallops-subscriber sees
/// the kill. This is informational only (not propagated) — remote
/// opers see the same notice when their own server processes the
/// D token.
async fn announce_kill(
    ctx: &HandlerContext,
    killer_prefix: &str,
    victim_nick: &str,
    reason: &str,
) {
    let notice = Message::with_source(
        &ctx.state.server_name,
        Command::Wallops,
        vec![format!(
            "Received KILL message for {victim_nick} from {killer_prefix}: {reason}"
        )],
    );
    let src = crate::tags::SourceInfo::now();
    for entry in ctx.state.clients.iter() {
        let c = entry.value().read().await;
        if c.modes.contains(&'w') {
            c.send_from(notice.clone(), &src);
        }
    }
}

/// Handle PRIVMSG command.
pub async fn handle_privmsg(ctx: &HandlerContext, msg: &Message) {
    handle_message(ctx, msg, Command::Privmsg).await;
}

/// Handle NOTICE command.
pub async fn handle_notice(ctx: &HandlerContext, msg: &Message) {
    handle_message(ctx, msg, Command::Notice).await;
}

async fn handle_message(ctx: &HandlerContext, msg: &Message, cmd: Command) {
    if msg.params.len() < 2 {
        if cmd == Command::Privmsg {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["PRIVMSG".into(), "Not enough parameters".into()],
            )
            .await;
        }
        // NOTICE errors are silently dropped per RFC
        return;
    }

    let target = &msg.params[0];
    let text = &msg.params[1];

    // FEAT_NOMULTITARGETS: refuse PRIVMSG/NOTICE that list more
    // than one target. Mirrors nefarious2 ircd_relay.c:413/574.
    // Implementation detail: we don't currently dispatch
    // multi-target messages either way (target is treated as a
    // single name), so a comma here would otherwise just produce
    // ERR_NOSUCHNICK. The explicit ERR_TOOMANYTARGETS gives the
    // correct diagnostic while leaving multi-target dispatch
    // unimplemented behind the same gate.
    if target.contains(',') && ctx.state.config().nomultitargets() {
        if cmd == Command::Privmsg {
            ctx.send_numeric(
                ERR_TOOMANYTARGETS,
                vec![target.clone(), "Too many targets".into()],
            )
            .await;
        }
        return;
    }

    let prefix = ctx.prefix().await;
    let client_id = ctx.client_id().await;

    // SHUN: the sender is silenced network-wide. Drop silently —
    // nefarious2 m_message.c handles this at the send path so the
    // sender sees no error but their message never reaches anyone.
    // PRIVMSG to server-services (first-char '$') bypasses shun.
    let (user, host, ip) = {
        let c = ctx.client.read().await;
        (c.user.clone(), c.host.clone(), c.addr.ip())
    };
    if !target.starts_with('$') && ctx.state.is_shunned(&user, &host, ip).await {
        return;
    }

    let out_msg = Message::with_source(&prefix, cmd.clone(), vec![target.clone(), text.clone()]);
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);

    if target.starts_with('#') || target.starts_with('&') {
        // Channel message
        let channel = match ctx.state.get_channel(target) {
            Some(c) => c,
            None => {
                if cmd == Command::Privmsg {
                    ctx.send_numeric(
                        ERR_NOSUCHCHANNEL,
                        vec![target.clone(), "No such channel".into()],
                    )
                    .await;
                }
                return;
            }
        };

        let chan = channel.read().await;
        let is_account = ctx.client.read().await.account.is_some();

        // Check if client can send to channel
        if !chan.can_send(&client_id, is_account) {
            if cmd == Command::Privmsg {
                ctx.send_numeric(
                    ERR_CANNOTSENDTOCHAN,
                    vec![target.clone(), "Cannot send to channel".into()],
                )
                .await;
            }
            return;
        }

        // Content-aware gates (+C no-CTCP, +N no-notice, +c no-colour).
        // Ops bypass per channel.rs::check_content. Refusal emits 404
        // for PRIVMSG; NOTICE drops silently per RFC.
        if let Err(reason) = chan.check_content(&client_id, cmd == Command::Notice, text) {
            if cmd == Command::Privmsg {
                ctx.send_numeric(
                    ERR_CANNOTSENDTOCHAN,
                    vec![target.clone(), reason.into()],
                )
                .await;
            }
            return;
        }

        // Send to every other local channel member first.
        // If SILENCE_CHANMSGS is enabled, each recipient's silence
        // list filters our sender out — same rule as private
        // messages, just applied per-recipient here since channel
        // fan-out hits many users with different filter lists.
        let silence_on_chanmsgs = ctx.state.config.load().silence_chanmsgs();
        for (&member_id, _) in &chan.members {
            if member_id == client_id {
                continue;
            }
            if let Some(member) = ctx.state.clients.get(&member_id) {
                let m = member.read().await;
                if silence_on_chanmsgs && m.is_silenced(&prefix) {
                    continue;
                }
                m.send_from(out_msg.clone(), &src);
            }
        }

        // Then echo-message: self-copy carrying the same user-event tags
        // plus the reply-path tags (notably @batch) for labeled-response.
        let echo = ctx
            .client
            .read()
            .await
            .has_cap(crate::capabilities::Capability::EchoMessage);
        if echo {
            ctx.reply_from(out_msg.clone(), &src).await;
        }

        // Route to S2S link if there are remote members
        if !chan.remote_members.is_empty() {
            drop(chan);
            crate::s2s::routing::route_privmsg(
                &ctx.state,
                client_id,
                target,
                text,
                cmd == Command::Notice,
                &src,
            )
            .await;
        }
    } else {
        // Private message to a user — check local first, then remote
        if let Some(target_client) = ctx.state.find_client_by_nick(target) {
            let tc = target_client.read().await;
            // SILENCE: drop before delivery if the sender matches a
            // filter on the recipient. PRIVMSG is dropped silently
            // (no error) to mirror C forward_silences' quiet drop;
            // clients that want feedback can /SILENCE themselves.
            if tc.is_silenced(&prefix) {
                return;
            }
            tc.send_from(out_msg.clone(), &src);
            drop(tc);
            // echo-message: send the sender a labeled copy.
            if ctx
                .client
                .read()
                .await
                .has_cap(crate::capabilities::Capability::EchoMessage)
            {
                ctx.reply_from(out_msg, &src).await;
            }
        } else if ctx.state.find_remote_by_nick(target).is_some() {
            // Route to S2S link
            crate::s2s::routing::route_privmsg(
                &ctx.state,
                client_id,
                target,
                text,
                cmd == Command::Notice,
                &src,
            )
            .await;
        } else if cmd == Command::Privmsg {
            ctx.send_numeric(
                ERR_NOSUCHNICK,
                vec![target.clone(), "No such nick/channel".into()],
            )
            .await;
        }
    }
}
