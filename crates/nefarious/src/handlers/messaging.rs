
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

    let prefix = ctx.prefix().await;
    let client_id = ctx.client_id().await;

    // SHUN: the sender is silenced network-wide. Drop silently —
    // nefarious2 m_message.c handles this at the send path so the
    // sender sees no error but their message never reaches anyone.
    // PRIVMSG to server-services (first-char '$') bypasses shun.
    let sender_user_host = {
        let c = ctx.client.read().await;
        format!("{}@{}", c.user, c.host)
    };
    if !target.starts_with('$') && ctx.state.is_shunned(&sender_user_host).await {
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

        // Send to every other local channel member first.
        for (&member_id, _) in &chan.members {
            if member_id == client_id {
                continue;
            }
            if let Some(member) = ctx.state.clients.get(&member_id) {
                let m = member.read().await;
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
