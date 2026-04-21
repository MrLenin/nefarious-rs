use irc_proto::Message;

use crate::numeric::*;

use super::HandlerContext;

/// Handle WHO command.
pub async fn handle_who(ctx: &HandlerContext, msg: &Message) {
    let mask = msg.params.first().map(|s| s.as_str()).unwrap_or("*");
    let multi_prefix = ctx
        .client
        .read()
        .await
        .has_cap(crate::capabilities::Capability::MultiPrefix);

    if mask.starts_with('#') || mask.starts_with('&') {
        // WHO for a channel — include both local and remote members.
        if let Some(channel) = ctx.state.get_channel(mask) {
            let chan = channel.read().await;
            for (&member_id, flags) in &chan.members {
                if let Some(member) = ctx.state.clients.get(&member_id) {
                    let m = member.read().await;
                    let status = who_status(flags, multi_prefix);
                    ctx.send_numeric(
                        RPL_WHOREPLY,
                        vec![
                            mask.to_string(),
                            m.user.clone(),
                            m.host.clone(),
                            ctx.state.server_name.clone(),
                            m.nick.clone(),
                            status,
                            format!("0 {}", m.realname),
                        ],
                    )
                    .await;
                }
            }
            for (&numeric, flags) in &chan.remote_members {
                if let Some(remote) = ctx.state.remote_clients.get(&numeric) {
                    let r = remote.read().await;
                    // Aliases are network-invisible (see send_names).
                    if r.is_alias {
                        continue;
                    }
                    let server_name = ctx
                        .state
                        .remote_servers
                        .get(&r.server)
                        .map(|s| s.value().clone());
                    let server_display = if let Some(s) = server_name {
                        s.read().await.name.clone()
                    } else {
                        ctx.state.server_name.clone()
                    };
                    let status = who_status(flags, multi_prefix);
                    ctx.send_numeric(
                        RPL_WHOREPLY,
                        vec![
                            mask.to_string(),
                            r.user.clone(),
                            r.host.clone(),
                            server_display,
                            r.nick.clone(),
                            status,
                            format!("1 {}", r.realname),
                        ],
                    )
                    .await;
                }
            }
        }
    } else if let Some(target) = ctx.state.find_client_by_nick(mask) {
        let m = target.read().await;
        ctx.send_numeric(
            RPL_WHOREPLY,
            vec![
                "*".to_string(),
                m.user.clone(),
                m.host.clone(),
                ctx.state.server_name.clone(),
                m.nick.clone(),
                "H".to_string(),
                format!("0 {}", m.realname),
            ],
        )
        .await;
    } else if let Some(remote) = ctx.state.find_remote_by_nick(mask) {
        let r = remote.read().await;
        let server_display = ctx
            .state
            .remote_servers
            .get(&r.server)
            .map(|s| s.value().clone());
        let server_name = if let Some(s) = server_display {
            s.read().await.name.clone()
        } else {
            ctx.state.server_name.clone()
        };
        ctx.send_numeric(
            RPL_WHOREPLY,
            vec![
                "*".to_string(),
                r.user.clone(),
                r.host.clone(),
                server_name,
                r.nick.clone(),
                "H".to_string(),
                format!("1 {}", r.realname),
            ],
        )
        .await;
    }

    ctx.send_numeric(
        RPL_ENDOFWHO,
        vec![mask.to_string(), "End of /WHO list".into()],
    )
    .await;
}

/// Build the "status" field of an RPL_WHOREPLY row. `multi_prefix`
/// means the requester negotiated the cap and wants every active
/// prefix rather than just the highest one.
fn who_status(flags: &crate::channel::MembershipFlags, multi_prefix: bool) -> String {
    let prefix = if multi_prefix {
        flags.all_prefixes()
    } else {
        flags.highest_prefix().to_string()
    };
    format!("H{prefix}")
}

/// Handle WHOIS command.
pub async fn handle_whois(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NONICKNAMEGIVEN,
            vec!["No nickname given".into()],
        )
        .await;
        return;
    }

    // Handle optional server parameter: WHOIS [server] nick
    let nick = if msg.params.len() > 1 {
        &msg.params[1]
    } else {
        &msg.params[0]
    };

    // Try local first, then fall back to remote users seen via P10 burst.
    if let Some(target) = ctx.state.find_client_by_nick(nick) {
        let t = target.read().await;
        ctx.send_numeric(
            RPL_WHOISUSER,
            vec![
                t.nick.clone(),
                t.user.clone(),
                t.host.clone(),
                "*".to_string(),
                t.realname.clone(),
            ],
        )
        .await;
        ctx.send_numeric(
            RPL_WHOISSERVER,
            vec![
                t.nick.clone(),
                ctx.state.server_name.clone(),
                ctx.state.server_description.clone(),
            ],
        )
        .await;
        if !t.channels.is_empty() {
            let mut chan_list = Vec::new();
            for chan_name in &t.channels {
                if let Some(channel) = ctx.state.get_channel(chan_name) {
                    let chan = channel.read().await;
                    if let Some(flags) = chan.members.get(&t.id) {
                        chan_list.push(format!("{}{}", flags.highest_prefix(), chan_name));
                    }
                }
            }
            if !chan_list.is_empty() {
                ctx.send_numeric(
                    RPL_WHOISCHANNELS,
                    vec![t.nick.clone(), chan_list.join(" ")],
                )
                .await;
            }
        }
        let idle_secs = (chrono::Utc::now() - t.last_active).num_seconds().max(0);
        ctx.send_numeric(
            RPL_WHOISIDLE,
            vec![
                t.nick.clone(),
                idle_secs.to_string(),
                t.connected_at.timestamp().to_string(),
                "seconds idle, signon time".to_string(),
            ],
        )
        .await;
        ctx.send_numeric(
            RPL_ENDOFWHOIS,
            vec![t.nick.clone(), "End of /WHOIS list".into()],
        )
        .await;
    } else if let Some(remote) = ctx.state.find_remote_by_nick(nick) {
        // Remote user WHOIS: no idle time (we don't track remote activity)
        // and the server line reports the remote's home server.
        let r = remote.read().await;
        ctx.send_numeric(
            RPL_WHOISUSER,
            vec![
                r.nick.clone(),
                r.user.clone(),
                r.host.clone(),
                "*".to_string(),
                r.realname.clone(),
            ],
        )
        .await;
        let server_info = ctx
            .state
            .remote_servers
            .get(&r.server)
            .map(|e| e.value().clone());
        let (server_name, server_desc) = if let Some(s) = server_info {
            let s = s.read().await;
            (s.name.clone(), s.description.clone())
        } else {
            (ctx.state.server_name.clone(), String::new())
        };
        ctx.send_numeric(
            RPL_WHOISSERVER,
            vec![r.nick.clone(), server_name, server_desc],
        )
        .await;
        if !r.channels.is_empty() {
            let channels: Vec<String> = r.channels.iter().cloned().collect();
            ctx.send_numeric(
                RPL_WHOISCHANNELS,
                vec![r.nick.clone(), channels.join(" ")],
            )
            .await;
        }
        if let Some(ref account) = r.account {
            ctx.send_numeric(
                RPL_WHOISACCOUNT,
                vec![
                    r.nick.clone(),
                    account.clone(),
                    "is logged in as".to_string(),
                ],
            )
            .await;
        }
        ctx.send_numeric(
            RPL_ENDOFWHOIS,
            vec![r.nick.clone(), "End of /WHOIS list".into()],
        )
        .await;
    } else {
        ctx.send_numeric(
            ERR_NOSUCHNICK,
            vec![nick.clone(), "No such nick/channel".into()],
        )
        .await;
        ctx.send_numeric(
            RPL_ENDOFWHOIS,
            vec![nick.clone(), "End of /WHOIS list".into()],
        )
        .await;
    }
}

/// Handle MOTD command.
pub async fn handle_motd(ctx: &HandlerContext, _msg: &Message) {
    if ctx.state.motd.is_empty() {
        ctx.send_numeric(ERR_NOMOTD, vec!["MOTD File is missing".into()])
            .await;
        return;
    }

    ctx.send_numeric(
        RPL_MOTDSTART,
        vec![format!("- {} Message of the Day -", ctx.state.server_name)],
    )
    .await;

    for line in &ctx.state.motd {
        ctx.send_numeric(RPL_MOTD, vec![format!("- {line}")]).await;
    }

    ctx.send_numeric(RPL_ENDOFMOTD, vec!["End of /MOTD command".into()])
        .await;
}

/// Handle LUSERS command.
pub async fn handle_lusers(ctx: &HandlerContext, _msg: &Message) {
    send_lusers(ctx.client.clone(), &ctx.state).await;
}

/// Emit the LUSERS reply block to the given client. Shared between the
/// post-registration welcome burst and the LUSERS command so the numbers
/// match.
pub async fn send_lusers(
    client: std::sync::Arc<tokio::sync::RwLock<crate::client::Client>>,
    state: &crate::state::ServerState,
) {
    let total_users = state.total_user_count();
    let invisible = state.invisible_count().await;
    let visible = total_users.saturating_sub(invisible);
    let operators = state.operator_count().await;
    let channels = state.channel_count();
    let servers = state.server_count();
    let local_clients = state.client_count();

    let server_name = state.server_name.clone();
    let c = client.read().await;

    c.send_numeric(
        &server_name,
        RPL_LUSERCLIENT,
        vec![format!(
            "There are {visible} users and {invisible} invisible on {servers} servers"
        )],
    );

    c.send_numeric(
        &server_name,
        RPL_LUSEROP,
        vec![operators.to_string(), "operator(s) online".into()],
    );

    c.send_numeric(
        &server_name,
        RPL_LUSERCHANNELS,
        vec![channels.to_string(), "channels formed".into()],
    );

    c.send_numeric(
        &server_name,
        RPL_LUSERME,
        vec![format!(
            "I have {local_clients} clients and {} servers",
            servers.saturating_sub(1)
        )],
    );
}

/// Handle AWAY command. With no argument clears away state; with an
/// argument sets it. RPL_UNAWAY / RPL_NOWAWAY is sent to the client,
/// and (when our peers have `away-notify`) an AWAY message is
/// broadcast to everyone sharing a channel with us.
pub async fn handle_away(ctx: &HandlerContext, msg: &Message) {
    let new_state = msg.params.first().cloned().filter(|s| !s.is_empty());
    let mut client = ctx.client.write().await;
    client.away_message = new_state.clone();
    let prefix = client.prefix();
    let channels: std::collections::HashSet<String> = client.channels.iter().cloned().collect();
    let client_id = client.id;
    drop(client);

    // IRCv3 away-notify: notify everyone sharing a channel with us.
    let away_params = match &new_state {
        Some(msg) => vec![msg.clone()],
        None => Vec::new(),
    };
    let away_msg = irc_proto::Message::with_source(&prefix, irc_proto::Command::Away, away_params);
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);
    broadcast_to_shared_channels(
        &ctx.state,
        client_id,
        &channels,
        crate::capabilities::Capability::AwayNotify,
        &away_msg,
        &src,
    )
    .await;

    // Propagate to S2S so remote servers can drive their own
    // away-notify emissions (and so /WHOIS on a remote side shows
    // the 301 "away" numeric). Matches nefarious2 m_away.c:260-326
    // which always emits CMD_AWAY to every peer on state change.
    crate::s2s::routing::route_away(&ctx.state, client_id, new_state.as_deref()).await;

    if new_state.is_some() {
        ctx.send_numeric(
            RPL_NOWAWAY,
            vec!["You have been marked as being away".into()],
        )
        .await;
    } else {
        ctx.send_numeric(RPL_UNAWAY, vec!["You are no longer marked as being away".into()])
            .await;
    }
}

/// Handle SETNAME — `SETNAME :<realname>`. Updates the sender's
/// realname and broadcasts the change to any local user sharing a
/// channel with them who has `setname` enabled.
pub async fn handle_setname(ctx: &HandlerContext, msg: &Message) {
    let name = match msg.params.first() {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["SETNAME".into(), "Not enough parameters".into()],
            )
            .await;
            return;
        }
    };

    // 390 chars is the C-reference maximum realname length; match it.
    if name.len() > 390 {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["SETNAME".into(), "Realname is too long".into()],
        )
        .await;
        return;
    }

    let (prefix, channels, client_id) = {
        let mut c = ctx.client.write().await;
        c.realname = name.clone();
        (
            c.prefix(),
            c.channels.iter().cloned().collect::<std::collections::HashSet<_>>(),
            c.id,
        )
    };

    let setname_msg = Message::with_source(&prefix, irc_proto::Command::Setname, vec![name.clone()]);
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);
    broadcast_to_shared_channels(
        &ctx.state,
        client_id,
        &channels,
        crate::capabilities::Capability::Setname,
        &setname_msg,
        &src,
    )
    .await;

    // Propagate to S2S so peers can refresh their remote_client
    // realname and fan setname-notify out to their own channel peers.
    // Matches nefarious2 m_setname.c which emits CMD_SETNAME to servers
    // on every realname change.
    crate::s2s::routing::route_setname(&ctx.state, client_id, &name).await;
}

/// Handle CHGHOST — `CHGHOST <target> <newuser> <newhost>`. Operator-
/// only; changes the target's visible user+host and broadcasts the
/// change to any local user sharing a channel with the target who
/// has `chghost` enabled.
pub async fn handle_chghost(ctx: &HandlerContext, msg: &Message) {
    if msg.params.len() < 3 {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["CHGHOST".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    // Operator check — matches nefarious2 CHGHOST's privilege guard.
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    let target_nick = &msg.params[0];
    let new_user = msg.params[1].clone();
    let new_host = msg.params[2].clone();

    let target = match ctx.state.find_client_by_nick(target_nick) {
        Some(t) => t,
        None => {
            ctx.send_numeric(
                ERR_NOSUCHNICK,
                vec![target_nick.clone(), "No such nick/channel".into()],
            )
            .await;
            return;
        }
    };

    // Update target's visible identity and capture the OLD prefix so
    // the broadcast message shows where they were before the change.
    let (old_prefix, target_id, channels) = {
        let mut tc = target.write().await;
        let old_prefix = tc.prefix();
        tc.user = new_user.clone();
        tc.host = new_host.clone();
        let channels: std::collections::HashSet<String> = tc.channels.iter().cloned().collect();
        (old_prefix, tc.id, channels)
    };

    let chghost_msg = Message::with_source(
        &old_prefix,
        irc_proto::Command::Chghost,
        vec![new_user, new_host],
    );
    let src = crate::tags::SourceInfo::from_local(&*target.read().await);
    broadcast_to_shared_channels(
        &ctx.state,
        target_id,
        &channels,
        crate::capabilities::Capability::Chghost,
        &chghost_msg,
        &src,
    )
    .await;

    // Echo the change to the target so their client sees the new
    // identity even without chghost cap (matches C behaviour).
    target.read().await.send(chghost_msg);
}

/// Deliver `msg` to every local user (other than `source_id`) who
/// shares at least one of `source_channels` with the source AND has
/// `cap` enabled. Per-recipient tag injection is applied via
/// `send_from`. Used by away-notify, chghost, setname, etc.
async fn broadcast_to_shared_channels(
    state: &crate::state::ServerState,
    source_id: crate::client::ClientId,
    source_channels: &std::collections::HashSet<String>,
    cap: crate::capabilities::Capability,
    msg: &Message,
    src: &crate::tags::SourceInfo,
) {
    let mut seen: std::collections::HashSet<crate::client::ClientId> = std::collections::HashSet::new();
    for chan_name in source_channels {
        if let Some(channel) = state.get_channel(chan_name) {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if member_id == source_id || !seen.insert(member_id) {
                    continue;
                }
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    if m.has_cap(cap) {
                        m.send_from(msg.clone(), src);
                    }
                }
            }
        }
    }
}

/// Handle USERHOST — `USERHOST <nick> [<nick>...]`. Returns a single
/// 302 reply containing `nick[*]=+|-user@host` tokens for each online user.
pub async fn handle_userhost(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["USERHOST".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let mut tokens = Vec::new();
    for nick in msg.params.iter().take(5) {
        if let Some(client) = ctx.state.find_client_by_nick(nick) {
            let c = client.read().await;
            let oper_mark = if c.modes.contains(&'o') { "*" } else { "" };
            let away_mark = if c.away_message.is_some() { "-" } else { "+" };
            tokens.push(format!("{}{oper_mark}={away_mark}{}@{}", c.nick, c.user, c.host));
        } else if let Some(remote) = ctx.state.find_remote_by_nick(nick) {
            let r = remote.read().await;
            let oper_mark = if r.modes.contains(&'o') { "*" } else { "" };
            tokens.push(format!("{}{oper_mark}=+{}@{}", r.nick, r.user, r.host));
        }
    }

    ctx.send_numeric(RPL_USERHOST, vec![tokens.join(" ")]).await;
}

/// Handle ISON — `ISON <nick> [<nick>...]`. Returns a single 303 reply
/// with the space-separated subset of the queried nicks that are online.
pub async fn handle_ison(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["ISON".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    // Params can be `nick1 nick2 ...` across multiple params or one
    // space-separated param; accept both.
    let mut present = Vec::new();
    for p in &msg.params {
        for nick in p.split_whitespace() {
            if ctx.state.nick_in_use(nick) {
                present.push(nick.to_string());
            }
        }
    }

    ctx.send_numeric(RPL_ISON, vec![present.join(" ")]).await;
}

/// Handle OPER — `OPER <name> <password>`. Matches against Operator
/// config blocks and grants user mode +o on success. Password comparison
/// is plaintext for now; the C server supports bcrypt/pbkdf2 but that
/// belongs in the auth phase.
pub async fn handle_oper(ctx: &HandlerContext, msg: &Message) {
    if msg.params.len() < 2 {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["OPER".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let name = &msg.params[0];
    let password = &msg.params[1];

    let matched = ctx
        .state
        .config
        .operators
        .iter()
        .find(|op| op.name == *name && op.password == *password);

    if matched.is_none() {
        ctx.send_numeric(ERR_PASSWDMISMATCH, vec!["Password incorrect".into()])
            .await;
        return;
    }

    {
        let mut client = ctx.client.write().await;
        client.modes.insert('o');
    }

    ctx.send_numeric(RPL_YOUREOPER, vec!["You are now an IRC operator".into()])
        .await;

    // Echo the mode change back to the client.
    let nick = ctx.nick().await;
    let client = ctx.client.read().await;
    client.send(Message::with_source(
        &nick,
        irc_proto::Command::Mode,
        vec![nick.clone(), "+o".into()],
    ));
}

/// Handle VERSION command.
pub async fn handle_version(ctx: &HandlerContext, _msg: &Message) {
    ctx.send_numeric(
        351, // RPL_VERSION
        vec![
            ctx.state.version.clone(),
            ctx.state.server_name.clone(),
            "Rust IRC server".to_string(),
        ],
    )
    .await;
}
