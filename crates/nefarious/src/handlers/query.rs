use irc_proto::Message;

use crate::numeric::*;

use super::HandlerContext;

/// Handle WHO command.
pub async fn handle_who(ctx: &HandlerContext, msg: &Message) {
    let mask = msg.params.first().map(|s| s.as_str()).unwrap_or("*");

    if mask.starts_with('#') || mask.starts_with('&') {
        // WHO for a channel
        if let Some(channel) = ctx.state.get_channel(mask) {
            let chan = channel.read().await;
            for (&member_id, flags) in &chan.members {
                if let Some(member) = ctx.state.clients.get(&member_id) {
                    let m = member.read().await;
                    let status = format!(
                        "H{}",
                        if flags.op {
                            "@"
                        } else if flags.voice {
                            "+"
                        } else {
                            ""
                        }
                    );
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
        }
    } else {
        // WHO for a nick
        if let Some(target) = ctx.state.find_client_by_nick(mask) {
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
        }
    }

    ctx.send_numeric(
        RPL_ENDOFWHO,
        vec![mask.to_string(), "End of /WHO list".into()],
    )
    .await;
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

    let target = match ctx.state.find_client_by_nick(nick) {
        Some(t) => t,
        None => {
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
            return;
        }
    };

    let t = target.read().await;

    // 311 RPL_WHOISUSER
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

    // 312 RPL_WHOISSERVER
    ctx.send_numeric(
        RPL_WHOISSERVER,
        vec![
            t.nick.clone(),
            ctx.state.server_name.clone(),
            ctx.state.server_description.clone(),
        ],
    )
    .await;

    // 319 RPL_WHOISCHANNELS — show channels the target is in
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

    // 317 RPL_WHOISIDLE
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

    // 318 RPL_ENDOFWHOIS
    ctx.send_numeric(
        RPL_ENDOFWHOIS,
        vec![t.nick.clone(), "End of /WHOIS list".into()],
    )
    .await;
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
    let clients = ctx.state.client_count();
    let channels = ctx.state.channel_count();

    ctx.send_numeric(
        RPL_LUSERCLIENT,
        vec![format!(
            "There are {clients} users and 0 invisible on 1 servers"
        )],
    )
    .await;

    ctx.send_numeric(RPL_LUSEROP, vec!["0".into(), "operator(s) online".into()])
        .await;

    ctx.send_numeric(
        RPL_LUSERCHANNELS,
        vec![channels.to_string(), "channels formed".into()],
    )
    .await;

    ctx.send_numeric(
        RPL_LUSERME,
        vec![format!("I have {clients} clients and 0 servers")],
    )
    .await;
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
