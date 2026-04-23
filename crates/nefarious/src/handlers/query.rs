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
/// Handle MONITOR per IRCv3 spec.
///
/// Subcommands:
///   `+ <nick>[,<nick>...]` — add to watch list; immediately emit
///       730 for any that are online and 731 for any offline so the
///       client gets a synchronous snapshot.
///   `- <nick>[,<nick>...]` — remove.
///   `C` — clear entire list.
///   `L` — emit 732 with the current list, then 733.
///   `S` — emit 730/731 summary of current list (status).
///
/// Per-client size is capped at `FEAT_MAXWATCHS` (default 128), the
/// same limit WATCH uses; overflow on `+` emits 734 ERR_MONLISTFULL
/// and stops processing the rest of that request.
pub async fn handle_monitor(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["MONITOR".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let sub = msg.params[0].to_ascii_uppercase();
    let client_id = ctx.client_id().await;

    match sub.as_str() {
        "+" => {
            let Some(list) = msg.params.get(1) else { return };
            // Split nicks, report online/offline status, update
            // state. Both the numerics we emit back use comma-joined
            // targets — batch the walk.
            let nicks: Vec<String> =
                list.split(',').filter(|n| !n.is_empty()).map(|n| n.to_string()).collect();
            let max = ctx.state.config.max_watchs() as usize;
            let mut online_prefixes: Vec<String> = Vec::new();
            let mut offline_nicks: Vec<String> = Vec::new();
            let mut overflow_nick: Option<String> = None;
            for nick in &nicks {
                // Cap on pre-insert count matches m_monitor.c: we
                // refuse the request that would push the watch count
                // past the limit, flushing what we've already staged
                // before emitting 734. Subsequent nicks in this batch
                // are skipped so the client sees a single overflow
                // error rather than a trickle.
                let current = {
                    if let Some(arc) = ctx.state.clients.get(&client_id) {
                        arc.read().await.monitored.len()
                    } else {
                        0
                    }
                };
                if current >= max {
                    overflow_nick = Some(nick.clone());
                    break;
                }
                ctx.state.monitor_add(client_id, nick).await;
                // Online check — local first, then remote.
                if let Some(arc) = ctx.state.find_client_by_nick(nick) {
                    let c = arc.read().await;
                    online_prefixes.push(c.prefix());
                } else if let Some(remote) = ctx.state.find_remote_by_nick(nick) {
                    let r = remote.read().await;
                    online_prefixes.push(r.prefix());
                } else {
                    offline_nicks.push(nick.clone());
                }
            }
            if !online_prefixes.is_empty() {
                ctx.send_numeric(RPL_MONONLINE, vec![online_prefixes.join(",")]).await;
            }
            if !offline_nicks.is_empty() {
                ctx.send_numeric(RPL_MONOFFLINE, vec![offline_nicks.join(",")]).await;
            }
            if let Some(nick) = overflow_nick {
                ctx.send_numeric(
                    ERR_MONLISTFULL,
                    vec![max.to_string(), nick, "Monitor list is full".into()],
                )
                .await;
            }
        }
        "-" => {
            let Some(list) = msg.params.get(1) else { return };
            for nick in list.split(',').filter(|n| !n.is_empty()) {
                ctx.state.monitor_remove(client_id, nick).await;
            }
        }
        "C" => {
            ctx.state.monitor_clear(client_id).await;
        }
        "L" => {
            let list: Vec<String> = {
                if let Some(arc) = ctx.state.clients.get(&client_id) {
                    let c = arc.read().await;
                    c.monitored.iter().cloned().collect()
                } else {
                    Vec::new()
                }
            };
            if !list.is_empty() {
                ctx.send_numeric(RPL_MONLIST, vec![list.join(",")]).await;
            }
            ctx.send_numeric(RPL_ENDOFMONLIST, vec!["End of MONITOR list".into()]).await;
        }
        "S" => {
            let nicks: Vec<String> = {
                if let Some(arc) = ctx.state.clients.get(&client_id) {
                    let c = arc.read().await;
                    c.monitored.iter().cloned().collect()
                } else {
                    Vec::new()
                }
            };
            let mut online_prefixes: Vec<String> = Vec::new();
            let mut offline_nicks: Vec<String> = Vec::new();
            for nick in &nicks {
                if let Some(arc) = ctx.state.find_client_by_nick(nick) {
                    let c = arc.read().await;
                    online_prefixes.push(c.prefix());
                } else if let Some(remote) = ctx.state.find_remote_by_nick(nick) {
                    let r = remote.read().await;
                    online_prefixes.push(r.prefix());
                } else {
                    offline_nicks.push(nick.clone());
                }
            }
            if !online_prefixes.is_empty() {
                ctx.send_numeric(RPL_MONONLINE, vec![online_prefixes.join(",")]).await;
            }
            if !offline_nicks.is_empty() {
                ctx.send_numeric(RPL_MONOFFLINE, vec![offline_nicks.join(",")]).await;
            }
        }
        _ => {
            // Silently ignore unknown subcommands — IRCv3 spec says
            // the server MAY do this; clients self-heal by retrying
            // with a known subcommand.
        }
    }
}

/// Handle WHOWAS — replay historical records for nicks that have
/// since disconnected. `WHOWAS <nick>[,<nick>...] [<count>]` per
/// RFC2812 §3.6.3; `count` is an optional cap on how many records
/// to return per nick (we serve the most recent first). When
/// `count` is omitted we emit every match.
///
/// Responses:
///   314 RPL_WHOWASUSER    — one per matching record
///   312 RPL_WHOISSERVER   — pinned to the record's server at quit
///   406 ERR_WASNOSUCHNICK — when the nick has no history
///   369 RPL_ENDOFWHOWAS   — sentinel after each nick
pub async fn handle_whowas(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NONICKNAMEGIVEN,
            vec!["No nickname given".into()],
        )
        .await;
        return;
    }

    let nicks: Vec<String> = msg.params[0]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    let count: Option<usize> = msg
        .params
        .get(1)
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n > 0);

    // Snapshot the ring so we don't hold the mutex across awaits.
    let records: Vec<crate::state::WhowasEntry> = {
        ctx.state.whowas.lock().await.iter().cloned().collect()
    };

    for nick in &nicks {
        let folded = irc_proto::irc_casefold(nick);
        // Walk newest-first so the most recent record comes out on
        // top — matches the C behaviour where WHOWAS returns the
        // latest quit for a nick before any older reuses.
        let matches: Vec<&crate::state::WhowasEntry> = records
            .iter()
            .rev()
            .filter(|e| irc_proto::irc_casefold(&e.nick) == folded)
            .take(count.unwrap_or(usize::MAX))
            .collect();

        if matches.is_empty() {
            ctx.send_numeric(
                ERR_WASNOSUCHNICK,
                vec![nick.clone(), "There was no such nickname".into()],
            )
            .await;
        } else {
            for entry in &matches {
                ctx.send_numeric(
                    RPL_WHOWASUSER,
                    vec![
                        entry.nick.clone(),
                        entry.user.clone(),
                        entry.host.clone(),
                        "*".to_string(),
                        entry.realname.clone(),
                    ],
                )
                .await;
                // 312 shows which server the user was on when they
                // quit; the trailing field carries the quit time as
                // an ISO-8601 string so clients can render "…quit at X".
                ctx.send_numeric(
                    RPL_WHOISSERVER,
                    vec![
                        entry.nick.clone(),
                        entry.server.clone(),
                        entry
                            .quit_at
                            .format("%a %b %d %Y at %H:%M:%S UTC")
                            .to_string(),
                    ],
                )
                .await;
            }
        }
        ctx.send_numeric(
            RPL_ENDOFWHOWAS,
            vec![nick.clone(), "End of /WHOWAS list".into()],
        )
        .await;
    }
}

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

    // Whether the requester gets to see unhidden info. Opers always
    // see real hosts/server names; a user WHOIS'ing themselves also
    // does (so their own /WHOIS shows their real IP and server).
    let show_real = {
        let c = ctx.client.read().await;
        c.modes.contains(&'o') || irc_proto::irc_eq(&c.nick, nick)
    };

    // Try local first, then fall back to remote users seen via P10 burst.
    if let Some(target) = ctx.state.find_client_by_nick(nick) {
        let t = target.read().await;
        let host = if show_real { t.host.clone() } else { t.visible_host(&ctx.state.config) };
        ctx.send_numeric(
            RPL_WHOISUSER,
            vec![
                t.nick.clone(),
                t.user.clone(),
                host,
                "*".to_string(),
                t.realname.clone(),
            ],
        )
        .await;
        if let Some(ref away) = t.away_message {
            ctx.send_numeric(RPL_AWAY, vec![t.nick.clone(), away.clone()]).await;
        }
        let (srv_name, srv_desc) = if show_real {
            (ctx.state.server_name.clone(), ctx.state.server_description.clone())
        } else {
            (
                ctx.state.config.his_servername().unwrap_or(&ctx.state.server_name).to_string(),
                ctx.state.config.his_serverinfo().unwrap_or(&ctx.state.server_description).to_string(),
            )
        };
        ctx.send_numeric(
            RPL_WHOISSERVER,
            vec![t.nick.clone(), srv_name, srv_desc],
        )
        .await;
        if t.modes.contains(&'o') {
            ctx.send_numeric(
                RPL_WHOISOPERATOR,
                vec![t.nick.clone(), "is an IRC operator".into()],
            )
            .await;
        }
        if t.tls {
            ctx.send_numeric(
                RPL_WHOISSSL,
                vec![t.nick.clone(), "is using a secure connection (SSL)".into()],
            )
            .await;
        }
        if !t.channels.is_empty() {
            let requester_id = ctx.client_id().await;
            let mut chan_list = Vec::new();
            for chan_name in &t.channels {
                if let Some(channel) = ctx.state.get_channel(chan_name) {
                    let chan = channel.read().await;
                    // 319 info leak: skip secret/private channels the
                    // requester isn't on. Non-members shouldn't be able
                    // to discover membership of hidden channels via
                    // WHOIS. Matches standard IRC behaviour.
                    let hidden = chan.modes.secret || chan.modes.private;
                    let requester_on = chan.members.contains_key(&requester_id);
                    if hidden && !requester_on {
                        continue;
                    }
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
        if let Some(ref away) = r.away_message {
            ctx.send_numeric(RPL_AWAY, vec![r.nick.clone(), away.clone()]).await;
        }
        let (server_name, server_desc) = if show_real {
            let server_info = ctx
                .state
                .remote_servers
                .get(&r.server)
                .map(|e| e.value().clone());
            if let Some(s) = server_info {
                let s = s.read().await;
                (s.name.clone(), s.description.clone())
            } else {
                (ctx.state.server_name.clone(), String::new())
            }
        } else {
            // Non-oper, not self: hide the remote user's home server
            // if HIS_SERVERNAME is configured. Fall back to the real
            // server name if not (matches C behaviour when the
            // feature is unset).
            let server_info = ctx
                .state
                .remote_servers
                .get(&r.server)
                .map(|e| e.value().clone());
            let real_name = if let Some(s) = server_info {
                s.read().await.name.clone()
            } else {
                ctx.state.server_name.clone()
            };
            (
                ctx.state.config.his_servername().unwrap_or(&real_name).to_string(),
                ctx.state.config.his_serverinfo().unwrap_or("").to_string(),
            )
        };
        ctx.send_numeric(
            RPL_WHOISSERVER,
            vec![r.nick.clone(), server_name, server_desc],
        )
        .await;
        if r.modes.contains(&'o') {
            ctx.send_numeric(
                RPL_WHOISOPERATOR,
                vec![r.nick.clone(), "is an IRC operator".into()],
            )
            .await;
        }
        // Remote users don't carry a direct TLS flag — nefarious2
        // marks SSL-connected users with umode +z, carried in
        // RemoteClient.modes.
        if r.modes.contains(&'z') {
            ctx.send_numeric(
                RPL_WHOISSSL,
                vec![r.nick.clone(), "is using a secure connection (SSL)".into()],
            )
            .await;
        }
        if !r.channels.is_empty() {
            let requester_id = ctx.client_id().await;
            let mut chan_list = Vec::new();
            for chan_name in &r.channels {
                if let Some(channel) = ctx.state.get_channel(chan_name) {
                    let chan = channel.read().await;
                    // Same +s/+p leak gate as the local-target path.
                    let hidden = chan.modes.secret || chan.modes.private;
                    let requester_on = chan.members.contains_key(&requester_id);
                    if hidden && !requester_on {
                        continue;
                    }
                    // Prefix comes from chan.remote_members for a
                    // remote user; otherwise no prefix (plain member).
                    let prefix = chan
                        .remote_members
                        .get(&r.numeric)
                        .map(|f| f.highest_prefix().to_string())
                        .unwrap_or_default();
                    chan_list.push(format!("{prefix}{chan_name}"));
                }
            }
            if !chan_list.is_empty() {
                ctx.send_numeric(
                    RPL_WHOISCHANNELS,
                    vec![r.nick.clone(), chan_list.join(" ")],
                )
                .await;
            }
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

    // RPL_LUSERUNKNOWN (253) — unknown connections. We don't track
    // registration-in-progress connections in state, so baseline-emit 0.
    // Matches the C block ordering between LUSERCHANNELS and LUSERME.
    c.send_numeric(
        &server_name,
        RPL_LUSERUNKNOWN,
        vec!["0".to_string(), "unknown connection(s)".into()],
    );

    c.send_numeric(
        &server_name,
        RPL_LUSERME,
        vec![format!(
            "I have {local_clients} clients and {} servers",
            servers.saturating_sub(1)
        )],
    );

    // RPL_LOCALUSERS (265) / RPL_GLOBALUSERS (266) — the current
    // plus historical peak counts. We don't track peaks yet, so
    // repeat the current number for both. Typical clients display
    // "Current local users N, max N / Current global users M,
    // max M".
    c.send_numeric(
        &server_name,
        RPL_LOCALUSERS,
        vec![
            local_clients.to_string(),
            local_clients.to_string(),
            format!("Current local users {local_clients}, max {local_clients}"),
        ],
    );
    c.send_numeric(
        &server_name,
        RPL_GLOBALUSERS,
        vec![
            total_users.to_string(),
            total_users.to_string(),
            format!("Current global users {total_users}, max {total_users}"),
        ],
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
    crate::s2s::routing::route_away(&ctx.state, client_id, new_state.as_deref(), &src).await;

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
    crate::s2s::routing::route_setname(&ctx.state, client_id, &name, &src).await;
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

/// Handle USERIP — `USERIP <nick> [<nick>...]`. Similar shape to
/// USERHOST but reports the user's IP (not hostname) per token.
/// Only opers should see real IPs for cloaked users; non-opers see
/// the same cloaked host they'd see elsewhere. Matches nefarious2
/// m_userip.c's non-oper behaviour.
///
/// Wire: `302 :nick[*]=+|-user@ip-or-host[ nick[*]=...]`
pub async fn handle_userip(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["USERIP".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let requester_is_oper = ctx.client.read().await.modes.contains(&'o');

    let mut tokens = Vec::new();
    for nick in msg.params.iter().take(5) {
        if let Some(client) = ctx.state.find_client_by_nick(nick) {
            let c = client.read().await;
            let oper_mark = if c.modes.contains(&'o') { "*" } else { "" };
            let away_mark = if c.away_message.is_some() { "-" } else { "+" };
            // Oper sees real host (which is the IP for us unless
            // rev-DNS resolved); non-oper sees the cloaked form.
            let host = if requester_is_oper {
                c.host.clone()
            } else {
                c.visible_host(&ctx.state.config)
            };
            tokens.push(format!("{}{oper_mark}={away_mark}{}@{host}", c.nick, c.user));
        } else if let Some(remote) = ctx.state.find_remote_by_nick(nick) {
            let r = remote.read().await;
            let oper_mark = if r.modes.contains(&'o') { "*" } else { "" };
            let away_mark = if r.away_message.is_some() { "-" } else { "+" };
            // Remote user's `host` is already the visible (cloaked)
            // form thanks to the NICK-burst ingestion path. The real
            // IP (as base64) lives on `ip_base64` but we don't expose
            // it from here without S2S WHOIS resolution.
            tokens.push(format!("{}{oper_mark}={away_mark}{}@{}", r.nick, r.user, r.host));
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

    let oper_config = match matched {
        Some(op) => op.clone(),
        None => {
            ctx.send_numeric(ERR_PASSWDMISMATCH, vec!["Password incorrect".into()])
                .await;
            return;
        }
    };

    // Resolve privileges from the Operator block's `privs` line. If
    // unspecified, fall back to the baseline global-oper set (roughly
    // mirrors nefarious2's default_global_priv_list without the
    // administrative ones like DIE/RESTART).
    let privs: std::collections::HashSet<String> = match &oper_config.privs {
        Some(s) => s
            .split_whitespace()
            .map(|p| p.to_uppercase())
            .collect(),
        None => DEFAULT_OPER_PRIVS.iter().map(|s| s.to_string()).collect(),
    };

    let client_id = {
        let mut client = ctx.client.write().await;
        client.modes.insert('o');
        client.privs = privs.clone();
        client.id
    };

    ctx.send_numeric(RPL_YOUREOPER, vec!["You are now an IRC operator".into()])
        .await;

    // Echo the mode change back to the client.
    let nick = ctx.nick().await;
    {
        let client = ctx.client.read().await;
        client.send(Message::with_source(
            &nick,
            irc_proto::Command::Mode,
            vec![nick.clone(), "+o".into()],
        ));
    }

    // Propagate to S2S: first the +o umode, then the PRIVS token so
    // peers can enforce/display the user's granted privileges.
    // Matches nefarious2 m_oper.c which calls send_umode_out followed
    // by client_sendtoserv_privs.
    let src = {
        let c = ctx.client.read().await;
        crate::tags::SourceInfo::from_local(&c)
    };
    crate::s2s::routing::route_user_mode(&ctx.state, client_id, &nick, "+o", &src).await;
    let priv_refs: Vec<&str> = privs.iter().map(|s| s.as_str()).collect();
    crate::s2s::routing::route_privs(&ctx.state, client_id, &priv_refs).await;
}

/// Baseline priv set granted to an /OPER with no `privs =` config
/// line. Roughly mirrors nefarious2's default_global_priv_list with
/// the administrative privileges (DIE, RESTART, JUPE/local variants,
/// SET) held back so a default oper is capable but not catastrophic.
/// Operator blocks with an explicit `privs = "..."` override this
/// entirely.
const DEFAULT_OPER_PRIVS: &[&str] = &[
    "CHAN_LIMIT",
    "SHOW_INVIS",
    "SHOW_ALL_INVIS",
    "KILL",
    "LOCAL_KILL",
    "REHASH",
    "OPMODE",
    "WHOX",
    "SEE_CHAN",
    "PROPAGATE",
    "DISPLAY",
    "SEE_OPERS",
    "LIST_CHAN",
    "FORCE_OPMODE",
    "CHECK",
];

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

/// Handle SILENCE — per-client filter list that drops inbound private
/// PRIVMSG/NOTICE from any sender matching a non-exception entry.
/// Entries starting with `~` are exceptions (positive matches that
/// override a silencing match).
///
/// Forms:
///   `SILENCE`              → view our own list (271/272)
///   `SILENCE <nick>`       → view a remote user's list (allowed only
///                             for opers / channel services in C —
///                             we mirror the C behaviour of silently
///                             emitting just the 272 sentinel for
///                             unprivileged queries)
///   `SILENCE +<mask>`      → add a silencing entry
///   `SILENCE +~<mask>`     → add an exception entry
///   `SILENCE -<mask>`      → remove the matching entry (by mask)
///   `SILENCE <mask>`       → same as `+<mask>` (bare mask implies add)
///
/// Comma-separated mask lists are accepted on +/-.
///
/// S2S forwarding of silence updates is a follow-up — the initial
/// landing enforces silence only for PRIVMSG/NOTICE whose delivery
/// happens on this server (local→local and remote→local). Until
/// peers receive our updates, remote servers will keep sending us
/// messages that we then filter locally; that's correct but wastes
/// bandwidth until the forward path lands.
pub async fn handle_silence(ctx: &HandlerContext, msg: &Message) {
    // No params — view own list.
    if msg.params.is_empty() || msg.params[0].is_empty() {
        let (nick, entries) = {
            let c = ctx.client.read().await;
            (c.nick.clone(), c.silence.clone())
        };
        for entry in &entries {
            let sigil = if entry.exception { "~" } else { "" };
            ctx.send_numeric(
                RPL_SILELIST,
                vec![nick.clone(), format!("{sigil}{}", entry.mask)],
            )
            .await;
        }
        ctx.send_numeric(
            RPL_ENDOFSILELIST,
            vec![nick, "End of SILENCE list".into()],
        )
        .await;
        return;
    }

    let arg = &msg.params[0];
    let first = arg.chars().next().unwrap();

    // View form: bare nick (no +/-/~ prefix and no mask characters).
    // Nefarious only reveals a non-self user's silence list to opers
    // or ChannelService users; we don't yet distinguish, so emit just
    // the sentinel for unprivileged lookups. Querying our own nick is
    // equivalent to the no-params form.
    if first != '+' && first != '-' && first != '~' && !arg.contains('!') && !arg.contains('@') {
        let own_nick = ctx.client.read().await.nick.clone();
        if arg.eq_ignore_ascii_case(&own_nick) {
            let entries = ctx.client.read().await.silence.clone();
            for entry in &entries {
                let sigil = if entry.exception { "~" } else { "" };
                ctx.send_numeric(
                    RPL_SILELIST,
                    vec![own_nick.clone(), format!("{sigil}{}", entry.mask)],
                )
                .await;
            }
        }
        ctx.send_numeric(
            RPL_ENDOFSILELIST,
            vec![arg.clone(), "End of SILENCE list".into()],
        )
        .await;
        return;
    }

    // Update form: comma-separated list of `[+-]?~?<mask>` tokens.
    let max_siles = ctx.state.config.max_siles() as usize;
    let mut echo_updates: Vec<String> = Vec::new();
    {
        let mut c = ctx.client.write().await;
        for raw in arg.split(',').filter(|t| !t.is_empty()) {
            let mut token = raw;
            let mut adding = true;
            if let Some(rest) = token.strip_prefix('-') {
                adding = false;
                token = rest;
            } else if let Some(rest) = token.strip_prefix('+') {
                token = rest;
            }
            let exception = token.starts_with('~');
            let mask = if exception { &token[1..] } else { token };
            if mask.is_empty() {
                continue;
            }

            if adding {
                if c.silence.iter().any(|e| e.mask == mask && e.exception == exception) {
                    continue;
                }
                if c.silence.len() >= max_siles {
                    let owner = c.nick.clone();
                    // Drop the write lock before sending so the
                    // recipient's Client::send doesn't contend with
                    // anything on the same RwLock.
                    drop(c);
                    ctx.send_numeric(
                        ERR_SILELISTFULL,
                        vec![owner, mask.to_string(), "Your silence list is full".into()],
                    )
                    .await;
                    return;
                }
                c.silence.push(crate::client::SilenceEntry {
                    mask: mask.to_string(),
                    exception,
                });
                let sigil = if exception { "~" } else { "" };
                echo_updates.push(format!("+{sigil}{mask}"));
            } else {
                let before = c.silence.len();
                c.silence.retain(|e| !(e.mask == mask && e.exception == exception));
                if c.silence.len() != before {
                    let sigil = if exception { "~" } else { "" };
                    echo_updates.push(format!("-{sigil}{mask}"));
                }
            }
        }
    }

    // Echo the accepted updates back so clients can confirm the list
    // changed. C nefarious2 forward_silences does this via
    // CMD_SILENCE to the source; we mirror its `SILENCE` form.
    if !echo_updates.is_empty() {
        let c = ctx.client.read().await;
        let prefix = c.prefix();
        let joined = echo_updates.join(",");
        let out = Message::with_source(&prefix, irc_proto::Command::Silence, vec![joined]);
        c.send(out);
    }
}
