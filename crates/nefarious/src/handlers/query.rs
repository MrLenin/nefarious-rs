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
/// argument sets it. RPL_UNAWAY / RPL_NOWAWAY is sent to the client.
pub async fn handle_away(ctx: &HandlerContext, msg: &Message) {
    let new_state = msg.params.first().cloned().filter(|s| !s.is_empty());
    let mut client = ctx.client.write().await;
    client.away_message = new_state.clone();
    drop(client);

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
