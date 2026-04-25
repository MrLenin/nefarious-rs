use irc_proto::{Command, Message, irc_eq};

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

    // Track changes for the MODE message we'll broadcast.
    //
    // `applied_params` carries nicks for the local client broadcast;
    // `applied_params_s2s` carries the same parameters in their S2S form
    // — specifically, o/v/h targets rendered as P10 numerics (local users
    // get their YYXXX; remote users get their existing YYXXX). The two
    // diverge only for membership modes where the wire format differs
    // between the IRC client side and the S2S side.
    let mut applied_add = String::new();
    let mut applied_remove = String::new();
    let mut applied_params: Vec<String> = Vec::new();
    let mut applied_params_s2s: Vec<String> = Vec::new();

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
                        applied_params_s2s.push(key.clone());
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
                            applied_params_s2s.push(limit_str.clone());
                        }
                        param_idx += 1;
                    }
                } else {
                    chan.modes.limit = None;
                    applied_remove.push('l');
                }
            }

            // Op/Voice/Halfop — target can be local OR remote. Resolve the
            // nick, apply to the matching membership map, and record the
            // nick for the client broadcast plus the P10 numeric for the
            // S2S routing.
            'o' | 'v' | 'h' => {
                let flag = c;
                if let Some(nick) = msg.params.get(param_idx).cloned() {
                    param_idx += 1;
                    let applied = apply_membership_mode(
                        ctx,
                        &channel,
                        &nick,
                        flag,
                        adding,
                    )
                    .await;
                    if let Some(numeric) = applied {
                        if adding {
                            applied_add.push(flag);
                        } else {
                            applied_remove.push(flag);
                        }
                        applied_params.push(nick);
                        applied_params_s2s.push(numeric);
                    }
                }
            }

            // Ban (+b)
            'b' => {
                if adding {
                    if let Some(mask) = msg.params.get(param_idx) {
                        param_idx += 1;
                        let max_bans = ctx.state.config.load().max_bans() as usize;
                        let mut chan = channel.write().await;
                        // Per-channel ban cap. 478 ERR_BANLISTFULL
                        // lets the op know the set rolled off the
                        // end; mirrors nefarious2 channel.c cap
                        // check at set_ban_list.
                        if chan.bans.len() >= max_bans {
                            drop(chan);
                            ctx.send_numeric(
                                478, // ERR_BANLISTFULL
                                vec![
                                    chan_name.clone(),
                                    mask.clone(),
                                    "Channel ban list is full".into(),
                                ],
                            )
                            .await;
                            continue;
                        }
                        // Skip duplicates — no point adding a ban
                        // that already matches the exact mask.
                        if chan.bans.iter().any(|b| b.mask == *mask) {
                            continue;
                        }
                        let extban = crate::channel::ExtBan::parse(
                            mask,
                            &ctx.state.config(),
                        );
                        chan.bans.push(BanEntry {
                            mask: mask.clone(),
                            set_by: prefix.clone(),
                            set_at: chrono::Utc::now(),
                            extban,
                        });
                        applied_add.push('b');
                        applied_params.push(mask.clone());
                        applied_params_s2s.push(mask.clone());
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
                    applied_params_s2s.push(mask.clone());
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
        let mut params = vec![chan_name.clone(), mode_change.clone()];
        params.extend(applied_params.clone());
        let mode_msg = Message::with_source(&prefix, Command::Mode, params);
        let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);
        send_to_channel(ctx, chan_name, &mode_msg, &src).await;

        // Route to S2S so peers see the same mode change. The S2S variant
        // of `applied_params` carries o/v/h targets as P10 numerics,
        // which is what peers expect on the wire.
        crate::s2s::routing::route_mode(
            &ctx.state,
            client_id,
            chan_name,
            &mode_change,
            &applied_params_s2s,
            &src,
        )
        .await;
    }
}

/// Resolve a nick target for o/v/h mode, apply the flag to whichever
/// membership map holds them (local or remote), and return the target's
/// P10 numeric as a string for S2S routing. Returns `None` if the nick
/// doesn't resolve, or if the user isn't a member of the channel — in
/// either case the mode bit is not applied, not broadcast, and not
/// routed, matching the C server's silent-ignore behaviour for targets
/// that aren't on the channel.
async fn apply_membership_mode(
    ctx: &HandlerContext,
    channel: &std::sync::Arc<tokio::sync::RwLock<crate::channel::Channel>>,
    nick: &str,
    flag: char,
    adding: bool,
) -> Option<String> {
    let set_flag = |mf: &mut crate::channel::MembershipFlags| match flag {
        'o' => mf.op = adding,
        'v' => mf.voice = adding,
        'h' => mf.halfop = adding,
        _ => {}
    };

    if let Some(client_arc) = ctx.state.find_client_by_nick(nick) {
        let target_id = client_arc.read().await.id;
        let mut chan = channel.write().await;
        if let Some(flags) = chan.members.get_mut(&target_id) {
            set_flag(flags);
            let numeric = ctx.state.numeric_for(target_id).unwrap_or(0);
            return Some(
                p10_proto::ClientNumeric {
                    server: ctx.state.numeric,
                    client: numeric,
                }
                .to_string(),
            );
        }
        return None;
    }

    if let Some(remote_arc) = ctx.state.find_remote_by_nick(nick) {
        let target_numeric = remote_arc.read().await.numeric;
        let mut chan = channel.write().await;
        if let Some(flags) = chan.remote_members.get_mut(&target_numeric) {
            set_flag(flags);
            return Some(target_numeric.to_string());
        }
    }
    None
}

async fn handle_user_mode(ctx: &HandlerContext, msg: &Message) {
    let target_nick = &msg.params[0];
    let nick = ctx.nick().await;

    // Can only change your own modes
    if !irc_eq(target_nick, &nick) {
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
        {
            let client = ctx.client.read().await;
            client.send(Message::with_source(
                &nick,
                Command::Mode,
                vec![nick.clone(), mode_change.clone()],
            ));
        }

        // Propagate to S2S so peers see the user-mode change
        // (nefarious2 send_umode_out in ircd/s_user.c). The M token
        // is shared with channel MODE; the receiving side disambiguates
        // on whether the first param starts with `#`/`&`.
        let (client_id, src) = {
            let c = ctx.client.read().await;
            (c.id, crate::tags::SourceInfo::from_local(&c))
        };
        crate::s2s::routing::route_user_mode(
            &ctx.state,
            client_id,
            &nick,
            &mode_change,
            &src,
        )
        .await;
    }
}
