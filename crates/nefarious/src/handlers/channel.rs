
use irc_proto::{Command, Message};

use crate::channel::{JoinCheck, MembershipFlags};
use crate::numeric::*;

use super::HandlerContext;

/// Handle JOIN command.
pub async fn handle_join(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["JOIN".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let channels_param = &msg.params[0];
    let keys_param = msg.params.get(1);

    let channels: Vec<&str> = channels_param.split(',').collect();
    let keys: Vec<&str> = keys_param
        .map(|k| k.split(',').collect())
        .unwrap_or_default();

    let client_id = ctx.client_id().await;
    let prefix = ctx.prefix().await;

    for (i, chan_name) in channels.iter().enumerate() {
        let chan_name = chan_name.trim();
        if !chan_name.starts_with('#') && !chan_name.starts_with('&') {
            ctx.send_numeric(
                ERR_NOSUCHCHANNEL,
                vec![chan_name.to_string(), "No such channel".into()],
            )
            .await;
            continue;
        }

        let key = keys.get(i).copied();

        let channel = ctx.state.get_or_create_channel(chan_name);
        let is_new;

        {
            let mut chan = channel.write().await;

            // Check join eligibility
            match chan.can_join(&client_id, &prefix, key) {
                JoinCheck::Ok => {}
                JoinCheck::AlreadyMember => continue,
                JoinCheck::Banned => {
                    ctx.send_numeric(
                        ERR_BANNEDFROMCHAN,
                        vec![chan_name.to_string(), "Cannot join channel (+b)".into()],
                    )
                    .await;
                    continue;
                }
                JoinCheck::InviteOnly => {
                    ctx.send_numeric(
                        ERR_INVITEONLYCHAN,
                        vec![chan_name.to_string(), "Cannot join channel (+i)".into()],
                    )
                    .await;
                    continue;
                }
                JoinCheck::BadKey => {
                    ctx.send_numeric(
                        ERR_BADCHANNELKEY,
                        vec![
                            chan_name.to_string(),
                            "Cannot join channel (+k)".into(),
                        ],
                    )
                    .await;
                    continue;
                }
                JoinCheck::Full => {
                    ctx.send_numeric(
                        ERR_CHANNELISFULL,
                        vec![chan_name.to_string(), "Cannot join channel (+l)".into()],
                    )
                    .await;
                    continue;
                }
            }

            is_new = chan.members.is_empty();

            // Add the member — first member gets ops
            let flags = MembershipFlags {
                op: is_new,
                ..Default::default()
            };
            chan.add_member(client_id, flags);
        }

        // Track on client side
        {
            let mut client = ctx.client.write().await;
            client.channels.insert(chan_name.to_string());
        }

        // Notify all channel members (including the joiner)
        let join_msg =
            Message::with_source(&prefix, Command::Join, vec![chan_name.to_string()]);
        send_to_channel(ctx, chan_name, &join_msg).await;

        // Send topic
        send_topic(ctx, chan_name).await;

        // Send NAMES
        send_names(ctx, chan_name).await;
    }
}

/// Handle PART command.
pub async fn handle_part(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["PART".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let channels: Vec<&str> = msg.params[0].split(',').collect();
    let reason = msg.params.get(1).cloned().unwrap_or_default();

    let client_id = ctx.client_id().await;
    let prefix = ctx.prefix().await;

    for chan_name in channels {
        let chan_name = chan_name.trim();

        let channel = match ctx.state.get_channel(chan_name) {
            Some(c) => c,
            None => {
                ctx.send_numeric(
                    ERR_NOSUCHCHANNEL,
                    vec![chan_name.to_string(), "No such channel".into()],
                )
                .await;
                continue;
            }
        };

        {
            let chan = channel.read().await;
            if !chan.is_member(&client_id) {
                ctx.send_numeric(
                    ERR_NOTONCHANNEL,
                    vec![chan_name.to_string(), "You're not on that channel".into()],
                )
                .await;
                continue;
            }
        }

        // Notify channel before removing
        let mut part_params = vec![chan_name.to_string()];
        if !reason.is_empty() {
            part_params.push(reason.clone());
        }
        let part_msg = Message::with_source(&prefix, Command::Part, part_params);
        send_to_channel(ctx, chan_name, &part_msg).await;

        // Remove from channel
        {
            let mut chan = channel.write().await;
            chan.remove_member(&client_id);
        }

        // Remove from client's channel list
        {
            let mut client = ctx.client.write().await;
            client.channels.remove(chan_name);
        }

        // Clean up empty channel
        {
            let chan = channel.read().await;
            if chan.is_empty() {
                ctx.state.channels.remove(&chan_name.to_ascii_lowercase());
            }
        }
    }
}

/// Handle TOPIC command.
pub async fn handle_topic(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["TOPIC".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

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

    let client_id = ctx.client_id().await;

    if msg.params.len() == 1 {
        // Query topic
        send_topic(ctx, chan_name).await;
        return;
    }

    // Set topic
    let new_topic = &msg.params[1];

    {
        let chan = channel.read().await;
        if !chan.is_member(&client_id) {
            ctx.send_numeric(
                ERR_NOTONCHANNEL,
                vec![chan_name.clone(), "You're not on that channel".into()],
            )
            .await;
            return;
        }
        if chan.modes.topic_ops_only && !chan.is_op(&client_id) {
            ctx.send_numeric(
                ERR_CHANOPRIVSNEEDED,
                vec![chan_name.clone(), "You're not channel operator".into()],
            )
            .await;
            return;
        }
    }

    let prefix = ctx.prefix().await;

    {
        let mut chan = channel.write().await;
        if new_topic.is_empty() {
            chan.topic = None;
            chan.topic_setter = None;
            chan.topic_time = None;
        } else {
            chan.topic = Some(new_topic.clone());
            chan.topic_setter = Some(prefix.clone());
            chan.topic_time = Some(chrono::Utc::now());
        }
    }

    // Notify channel
    let topic_msg = Message::with_source(
        &prefix,
        Command::Topic,
        vec![chan_name.clone(), new_topic.clone()],
    );
    send_to_channel(ctx, chan_name, &topic_msg).await;
}

/// Handle KICK command.
pub async fn handle_kick(ctx: &HandlerContext, msg: &Message) {
    if msg.params.len() < 2 {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["KICK".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let chan_name = &msg.params[0];
    let target_nick = &msg.params[1];
    let kicker_nick = ctx.nick().await;
    let reason = msg
        .params
        .get(2)
        .cloned()
        .unwrap_or_else(|| kicker_nick.clone());

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

    let client_id = ctx.client_id().await;

    // Check permissions
    {
        let chan = channel.read().await;
        if !chan.is_member(&client_id) {
            ctx.send_numeric(
                ERR_NOTONCHANNEL,
                vec![chan_name.clone(), "You're not on that channel".into()],
            )
            .await;
            return;
        }
        if !chan.is_op(&client_id) {
            ctx.send_numeric(
                ERR_CHANOPRIVSNEEDED,
                vec![chan_name.clone(), "You're not channel operator".into()],
            )
            .await;
            return;
        }
    }

    // Find target
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

    let target_id = target.read().await.id;

    {
        let chan = channel.read().await;
        if !chan.is_member(&target_id) {
            ctx.send_numeric(
                ERR_USERNOTINCHANNEL,
                vec![
                    target_nick.clone(),
                    chan_name.clone(),
                    "They aren't on that channel".into(),
                ],
            )
            .await;
            return;
        }
    }

    let prefix = ctx.prefix().await;

    // Notify channel
    let kick_msg = Message::with_source(
        &prefix,
        Command::Kick,
        vec![chan_name.clone(), target_nick.clone(), reason],
    );
    send_to_channel(ctx, chan_name, &kick_msg).await;

    // Remove target from channel
    {
        let mut chan = channel.write().await;
        chan.remove_member(&target_id);
    }
    {
        let mut tc = target.write().await;
        tc.channels.remove(chan_name);
    }
}

/// Handle INVITE command.
pub async fn handle_invite(ctx: &HandlerContext, msg: &Message) {
    if msg.params.len() < 2 {
        ctx.send_numeric(
            ERR_NEEDMOREPARAMS,
            vec!["INVITE".into(), "Not enough parameters".into()],
        )
        .await;
        return;
    }

    let target_nick = &msg.params[0];
    let chan_name = &msg.params[1];

    let client_id = ctx.client_id().await;

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

    {
        let chan = channel.read().await;
        if !chan.is_member(&client_id) {
            ctx.send_numeric(
                ERR_NOTONCHANNEL,
                vec![chan_name.clone(), "You're not on that channel".into()],
            )
            .await;
            return;
        }
        if chan.modes.invite_only && !chan.is_op(&client_id) {
            ctx.send_numeric(
                ERR_CHANOPRIVSNEEDED,
                vec![chan_name.clone(), "You're not channel operator".into()],
            )
            .await;
            return;
        }
    }

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

    let target_id = target.read().await.id;

    {
        let chan = channel.read().await;
        if chan.is_member(&target_id) {
            ctx.send_numeric(
                ERR_USERONCHANNEL,
                vec![
                    target_nick.clone(),
                    chan_name.clone(),
                    "is already on channel".into(),
                ],
            )
            .await;
            return;
        }
    }

    // Add to invite list
    {
        let mut chan = channel.write().await;
        chan.invites.insert(target_id);
    }

    let prefix = ctx.prefix().await;

    // Notify inviter
    ctx.send_numeric(
        RPL_INVITING,
        vec![target_nick.clone(), chan_name.clone()],
    )
    .await;

    // Notify target
    {
        let tc = target.read().await;
        tc.send(Message::with_source(
            &prefix,
            Command::Invite,
            vec![target_nick.clone(), chan_name.clone()],
        ));
    }
}

/// Handle NAMES command.
pub async fn handle_names(ctx: &HandlerContext, msg: &Message) {
    if msg.params.is_empty() {
        // No argument — just send end of names
        ctx.send_numeric(
            RPL_ENDOFNAMES,
            vec!["*".into(), "End of /NAMES list".into()],
        )
        .await;
        return;
    }

    let channels: Vec<&str> = msg.params[0].split(',').collect();
    for chan_name in channels {
        send_names(ctx, chan_name).await;
    }
}

/// Handle LIST command.
pub async fn handle_list(ctx: &HandlerContext, _msg: &Message) {
    ctx.send_numeric(RPL_LISTSTART, vec!["Channel".into(), "Users  Name".into()])
        .await;

    for entry in ctx.state.channels.iter() {
        let chan = entry.value().read().await;

        // Skip secret channels unless the user is a member
        let client_id = ctx.client_id().await;
        if chan.modes.secret && !chan.is_member(&client_id) {
            continue;
        }

        let topic = chan.topic.clone().unwrap_or_default();
        ctx.send_numeric(
            RPL_LIST,
            vec![
                chan.name.clone(),
                chan.members.len().to_string(),
                topic,
            ],
        )
        .await;
    }

    ctx.send_numeric(RPL_LISTEND, vec!["End of /LIST".into()])
        .await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a message to all members of a channel.
pub async fn send_to_channel(ctx: &HandlerContext, chan_name: &str, msg: &Message) {
    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => return,
    };

    let chan = channel.read().await;
    for (&member_id, _) in &chan.members {
        if let Some(member) = ctx.state.clients.get(&member_id) {
            let m = member.read().await;
            m.send(msg.clone());
        }
    }
}

/// Send topic information for a channel to the requesting client.
async fn send_topic(ctx: &HandlerContext, chan_name: &str) {
    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => return,
    };

    let chan = channel.read().await;
    match &chan.topic {
        Some(topic) => {
            ctx.send_numeric(
                RPL_TOPIC,
                vec![chan_name.to_string(), topic.clone()],
            )
            .await;
            if let (Some(setter), Some(time)) = (&chan.topic_setter, &chan.topic_time) {
                ctx.send_numeric(
                    RPL_TOPICWHOTIME,
                    vec![
                        chan_name.to_string(),
                        setter.clone(),
                        time.timestamp().to_string(),
                    ],
                )
                .await;
            }
        }
        None => {
            ctx.send_numeric(
                RPL_NOTOPIC,
                vec![chan_name.to_string(), "No topic is set".into()],
            )
            .await;
        }
    }
}

/// Send NAMES list for a channel.
async fn send_names(ctx: &HandlerContext, chan_name: &str) {
    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => {
            ctx.send_numeric(
                RPL_ENDOFNAMES,
                vec![chan_name.to_string(), "End of /NAMES list".into()],
            )
            .await;
            return;
        }
    };

    let chan = channel.read().await;

    // Build names list
    let mut names = Vec::new();
    for (&member_id, flags) in &chan.members {
        if let Some(member) = ctx.state.clients.get(&member_id) {
            let m = member.read().await;
            names.push(format!("{}{}", flags.highest_prefix(), m.nick));
        }
    }

    // Symbol: = (public), * (private), @ (secret)
    let symbol = if chan.modes.secret {
        "@"
    } else if chan.modes.private {
        "*"
    } else {
        "="
    };

    // Send in batches (to avoid line length limits)
    for chunk in names.chunks(20) {
        ctx.send_numeric(
            RPL_NAMREPLY,
            vec![
                symbol.to_string(),
                chan_name.to_string(),
                chunk.join(" "),
            ],
        )
        .await;
    }

    ctx.send_numeric(
        RPL_ENDOFNAMES,
        vec![chan_name.to_string(), "End of /NAMES list".into()],
    )
    .await;
}
