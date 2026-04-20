
use irc_proto::{Command, Message};

use crate::numeric::*;

use super::HandlerContext;

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

    let out_msg = Message::with_source(&prefix, cmd.clone(), vec![target.clone(), text.clone()]);

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

        // Check if client can send to channel
        if !chan.can_send(&client_id) {
            if cmd == Command::Privmsg {
                ctx.send_numeric(
                    ERR_CANNOTSENDTOCHAN,
                    vec![target.clone(), "Cannot send to channel".into()],
                )
                .await;
            }
            return;
        }

        // Send to all local channel members except the sender
        for (&member_id, _) in &chan.members {
            if member_id == client_id {
                continue;
            }
            if let Some(member) = ctx.state.clients.get(&member_id) {
                let m = member.read().await;
                m.send(out_msg.clone());
            }
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
            )
            .await;
        }
    } else {
        // Private message to a user — check local first, then remote
        if let Some(target_client) = ctx.state.find_client_by_nick(target) {
            let tc = target_client.read().await;
            tc.send(out_msg);
        } else if ctx.state.find_remote_by_nick(target).is_some() {
            // Route to S2S link
            crate::s2s::routing::route_privmsg(
                &ctx.state,
                client_id,
                target,
                text,
                cmd == Command::Notice,
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
