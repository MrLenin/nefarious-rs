use irc_proto::{Command, Message};

use crate::channel::BanEntry;
use crate::numeric::*;

use super::HandlerContext;
use super::channel::send_to_channel;

/// Handle MODE command (both user and channel modes).
pub async fn handle_mode(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["MODE".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let target = &msg.params[0];

    if target.starts_with('#') || target.starts_with('&') {
        handle_channel_mode(ctx, msg).await;
    } else {
        handle_user_mode(ctx, msg).await;
    }
}

async fn handle_channel_mode(ctx: &HandlerContext, msg: &Message) {
    let chan_name = &msg.params[0];

    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => {
            ctx.send_numeric(
                ERR_NOSUCHCHANNEL,
                vec![chan_name.clone(), "No such channel".into()],
            )
            .await;
            return;
        }
    };

    // Query mode — no mode string given
    if msg.params.len() == 1 {
        let chan = channel.read().await;
        ctx.send_numeric(
            RPL_CHANNELMODEIS,
            vec![chan_name.clone(), chan.modes.to_mode_string()],
        )
        .await;
        ctx.send_numeric(
            RPL_CREATIONTIME,
            vec![
                chan_name.clone(),
                chan.created_at.timestamp().to_string(),
            ],
        )
        .await;
        return;
    }

    let client_id = ctx.client_id().await;

    // Check operator permission
    {
        let chan = channel.read().await;
        if !chan.is_op(&client_id) {
            ctx.send_numeric(
                ERR_CHANOPRIVSNEEDED,
                vec![chan_name.clone(), "You're not channel operator".into()],
            )
            .await;
            return;
        }
    }

    let mode_str = &msg.params[1];
    let mut param_idx = 2;
    let mut adding = true;

    // Track changes for the MODE message we'll broadcast
    let mut applied_add = String::new();
    let mut applied_remove = String::new();
    let mut applied_params: Vec<String> = Vec::new();

    let prefix = ctx.prefix().await;

    for c in mode_str.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,

            // Simple boolean modes
            'n' | 't' | 'm' | 'i' | 's' | 'p' => {
                let mut chan = channel.write().await;
                let flag = match c {
                    'n' => &mut chan.modes.no_external,
                    't' => &mut chan.modes.topic_ops_only,
                    'm' => &mut chan.modes.moderated,
                    'i' => &mut chan.modes.invite_only,
                    's' => &mut chan.modes.secret,
                    'p' => &mut chan.modes.private,
                    _ => unreachable!(),
                };
                *flag = adding;
                if adding {
                    applied_add.push(c);
                } else {
                    applied_remove.push(c);
                }
            }

            // Key (+k)
            'k' => {
                let mut chan = channel.write().await;
                if adding {
                    if let Some(key) = msg.params.get(param_idx) {
                        chan.modes.key = Some(key.clone());
                        applied_add.push('k');
                        applied_params.push(key.clone());
                        param_idx += 1;
                    }
                } else {
                    chan.modes.key = None;
                    applied_remove.push('k');
                    // Consume the parameter even on removal (some clients send it)
                    if msg.params.get(param_idx).is_some() {
                        param_idx += 1;
                    }
                }
            }

            // Limit (+l)
            'l' => {
                let mut chan = channel.write().await;
                if adding {
                    if let Some(limit_str) = msg.params.get(param_idx) {
                        if let Ok(limit) = limit_str.parse::<u32>() {
                            chan.modes.limit = Some(limit);
                            applied_add.push('l');
                            applied_params.push(limit_str.clone());
                        }
                        param_idx += 1;
                    }
                } else {
                    chan.modes.limit = None;
                    applied_remove.push('l');
                }
            }

            // Op (+o)
            'o' => {
                if let Some(nick) = msg.params.get(param_idx) {
                    param_idx += 1;
                    if let Some(target) = ctx.state.find_client_by_nick(nick) {
                        let target_id = target.read().await.id;
                        let mut chan = channel.write().await;
                        if let Some(flags) = chan.members.get_mut(&target_id) {
                            flags.op = adding;
                            if adding {
                                applied_add.push('o');
                            } else {
                                applied_remove.push('o');
                            }
                            applied_params.push(nick.clone());
                        }
                    }
                }
            }

            // Voice (+v)
            'v' => {
                if let Some(nick) = msg.params.get(param_idx) {
                    param_idx += 1;
                    if let Some(target) = ctx.state.find_client_by_nick(nick) {
                        let target_id = target.read().await.id;
                        let mut chan = channel.write().await;
                        if let Some(flags) = chan.members.get_mut(&target_id) {
                            flags.voice = adding;
                            if adding {
                                applied_add.push('v');
                            } else {
                                applied_remove.push('v');
                            }
                            applied_params.push(nick.clone());
                        }
                    }
                }
            }

            // Ban (+b)
            'b' => {
                if adding {
                    if let Some(mask) = msg.params.get(param_idx) {
                        param_idx += 1;
                        let mut chan = channel.write().await;
                        chan.bans.push(BanEntry {
                            mask: mask.clone(),
                            set_by: prefix.clone(),
                            set_at: chrono::Utc::now(),
                        });
                        applied_add.push('b');
                        applied_params.push(mask.clone());
                    } else {
                        // Query ban list
                        let chan = channel.read().await;
                        for ban in &chan.bans {
                            ctx.send_numeric(
                                367,
                                vec![
                                    chan_name.clone(),
                                    ban.mask.clone(),
                                    ban.set_by.clone(),
                                    ban.set_at.timestamp().to_string(),
                                ],
                            )
                            .await;
                        }
                        ctx.send_numeric(
                            368,
                            vec![chan_name.clone(), "End of channel ban list".into()],
                        )
                        .await;
                    }
                } else if let Some(mask) = msg.params.get(param_idx) {
                    param_idx += 1;
                    let mut chan = channel.write().await;
                    chan.bans.retain(|b| b.mask != *mask);
                    applied_remove.push('b');
                    applied_params.push(mask.clone());
                }
            }

            other => {
                ctx.send_numeric(
                    ERR_UNKNOWNMODE,
                    vec![
                        other.to_string(),
                        "is unknown mode char to me".into(),
                    ],
                )
                .await;
            }
        }
    }

    // Broadcast the mode change
    let mut mode_change = String::new();
    if !applied_add.is_empty() {
        mode_change.push('+');
        mode_change.push_str(&applied_add);
    }
    if !applied_remove.is_empty() {
        mode_change.push('-');
        mode_change.push_str(&applied_remove);
    }

    if !mode_change.is_empty() {
        let mut params = vec![chan_name.clone(), mode_change];
        params.extend(applied_params);
        let mode_msg = Message::with_source(&prefix, Command::Mode, params);
        send_to_channel(ctx, chan_name, &mode_msg).await;
    }
}

async fn handle_user_mode(ctx: &HandlerContext, msg: &Message) {
    let target_nick = &msg.params[0];
    let nick = ctx.nick().await;

    // Can only change your own modes
    if !target_nick.eq_ignore_ascii_case(&nick) {
        ctx.send_numeric(
            ERR_USERSDONTMATCH,
            vec!["Can't change mode for other users".into()],
        )
        .await;
        return;
    }

    if msg.params.len() == 1 {
        // Query modes
        let client = ctx.client.read().await;
        let modes: String = client.modes.iter().collect();
        let mode_str = if modes.is_empty() {
            "+".to_string()
        } else {
            format!("+{modes}")
        };
        ctx.send_numeric(
            221, // RPL_UMODEIS
            vec![mode_str],
        )
        .await;
        return;
    }

    let mode_str = &msg.params[1];
    let mut adding = true;
    let mut applied_add = String::new();
    let mut applied_remove = String::new();

    for c in mode_str.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            // User modes: i (invisible), w (wallops)
            'i' | 'w' => {
                let mut client = ctx.client.write().await;
                if adding {
                    client.modes.insert(c);
                    applied_add.push(c);
                } else {
                    client.modes.remove(&c);
                    applied_remove.push(c);
                }
            }
            // Oper mode can only be set by OPER command, not MODE
            'o' => {
                if !adding {
                    let mut client = ctx.client.write().await;
                    client.modes.remove(&'o');
                    applied_remove.push('o');
                }
            }
            _ => {
                ctx.send_numeric(
                    ERR_UMODEUNKNOWNFLAG,
                    vec!["Unknown MODE flag".into()],
                )
                .await;
            }
        }
    }

    let mut mode_change = String::new();
    if !applied_add.is_empty() {
        mode_change.push('+');
        mode_change.push_str(&applied_add);
    }
    if !applied_remove.is_empty() {
        mode_change.push('-');
        mode_change.push_str(&applied_remove);
    }

    if !mode_change.is_empty() {
        let client = ctx.client.read().await;
        client.send(Message::with_source(
            &nick,
            Command::Mode,
            vec![nick.clone(), mode_change],
        ));
    }
}
