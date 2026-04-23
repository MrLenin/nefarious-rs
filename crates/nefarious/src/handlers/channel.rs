
use irc_proto::{Command, Message, irc_casefold};

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

        let (is_account, is_tls) = {
            let c = ctx.client.read().await;
            (c.account.is_some(), c.tls)
        };

        {
            let mut chan = channel.write().await;

            // Check join eligibility
            match chan.can_join(&client_id, &prefix, key, is_account, is_tls) {
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
                JoinCheck::RegisteredOnly => {
                    // 477 ERR_NEEDREGGEDNICK / ERR_REGONLYCHAN (nefarious2
                    // uses 477 for +r gates). Reuse BANNEDFROMCHAN's
                    // code-gate surface — the numeric code is
                    // channel-specific and our numeric module doesn't
                    // have it defined yet.
                    ctx.send_numeric(
                        477,
                        vec![
                            chan_name.to_string(),
                            "Cannot join channel (+r) — you need to authenticate".into(),
                        ],
                    )
                    .await;
                    continue;
                }
                JoinCheck::SslOnly => {
                    // 489 ERR_SECUREONLYCHAN per nefarious2
                    ctx.send_numeric(
                        489,
                        vec![
                            chan_name.to_string(),
                            "Cannot join channel (+z) — SSL only".into(),
                        ],
                    )
                    .await;
                    continue;
                }
            }

            // A channel is genuinely brand-new only when it has no members
            // at all — local OR remote. If remote_members is populated the
            // channel already exists somewhere on the network (from burst
            // or a prior link) and the joiner must not get ops for free.
            is_new = chan.is_empty();

            // Add the member — first member (of a brand-new channel) gets ops.
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

        // Notify all channel members (including the joiner).
        //
        // IRCv3 extended-join clients receive
        //   `:nick!user@host JOIN <channel> <account> :<realname>`
        // with `*` as the account for logged-out users. Other clients
        // receive the plain RFC form. Per-recipient cap check means
        // we build both variants and pick at send time.
        let (src, account, realname) = {
            let c = ctx.client.read().await;
            (
                crate::tags::SourceInfo::from_local(&c),
                c.account.clone().unwrap_or_else(|| "*".to_string()),
                c.realname.clone(),
            )
        };
        let plain = Message::with_source(&prefix, Command::Join, vec![chan_name.to_string()]);
        let extended = Message::with_source(
            &prefix,
            Command::Join,
            vec![chan_name.to_string(), account, realname],
        );
        send_join_to_channel(ctx, chan_name, &plain, &extended, &src).await;

        // Route to S2S
        {
            let chan = channel.read().await;
            crate::s2s::routing::route_join(
                &ctx.state,
                client_id,
                chan_name,
                chan.created_ts,
                &src,
            )
            .await;
        }

        // Send topic (silent when unset — matches C nefarious m_join.c:290)
        send_topic(ctx, chan_name, false).await;

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

        // Notify channel before removing (local client broadcast)
        let mut part_params = vec![chan_name.to_string()];
        if !reason.is_empty() {
            part_params.push(reason.clone());
        }
        let part_msg = Message::with_source(&prefix, Command::Part, part_params);
        let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);
        send_to_channel(ctx, chan_name, &part_msg, &src).await;

        // Mutate local state BEFORE routing to S2S. The S2S read task
        // runs concurrently; if we routed first, a fast peer echo
        // (e.g. any returning PART/state-sync token) could land in a
        // handler that reads our channel state mid-update. Mirrors
        // the handle_kick race fix: membership write happens first,
        // wire emission second.
        {
            let mut chan = channel.write().await;
            chan.remove_member(&client_id);
        }
        {
            let mut client = ctx.client.write().await;
            client.channels.remove(chan_name);
        }

        // Route to S2S now that local state matches what we're telling
        // peers.
        crate::s2s::routing::route_part(&ctx.state, client_id, chan_name, &reason, &src).await;

        // Clean up empty channel
        {
            let chan = channel.read().await;
            if chan.is_empty() {
                ctx.state.channels.remove(&irc_casefold(chan_name));
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
        // Query topic (emit RPL_NOTOPIC when unset — matches C m_topic.c:295)
        send_topic(ctx, chan_name, true).await;
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

    // Capture one timestamp and use it for both the stored topic_time
    // and the S2S TOPIC emission, so our local state matches exactly
    // what peers see on the wire. Separate `Utc::now()` calls for the
    // store and the route could drift by microseconds and cause a
    // spurious TS mismatch if a peer later echoed a TOPIC back.
    let ts_now = chrono::Utc::now();
    let ts_epoch = ts_now.timestamp() as u64;

    {
        let mut chan = channel.write().await;
        if new_topic.is_empty() {
            chan.topic = None;
            chan.topic_setter = None;
            chan.topic_time = None;
        } else {
            chan.topic = Some(new_topic.clone());
            chan.topic_setter = Some(prefix.clone());
            chan.topic_time = Some(ts_now);
        }
    }

    // Notify channel
    let topic_msg = Message::with_source(
        &prefix,
        Command::Topic,
        vec![chan_name.clone(), new_topic.clone()],
    );
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);
    send_to_channel(ctx, chan_name, &topic_msg, &src).await;

    // Route to S2S using the same timestamp we stored.
    crate::s2s::routing::route_topic(
        &ctx.state,
        client_id,
        chan_name,
        new_topic,
        &prefix,
        ts_epoch,
        &src,
    )
    .await;
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

    // Find target — could be a local Client or a remote user on a
    // linked server.
    let local_target = ctx.state.find_client_by_nick(target_nick);
    let remote_target = if local_target.is_none() {
        ctx.state.find_remote_by_nick(target_nick)
    } else {
        None
    };

    let prefix = ctx.prefix().await;
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);

    if let Some(target) = local_target {
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

        let kick_msg = Message::with_source(
            &prefix,
            Command::Kick,
            vec![chan_name.clone(), target_nick.clone(), reason.clone()],
        );
        send_to_channel(ctx, chan_name, &kick_msg, &src).await;

        let target_numeric = crate::s2s::routing::local_numeric(&ctx.state, target_id);
        crate::s2s::routing::route_kick(
            &ctx.state,
            client_id,
            chan_name,
            &target_numeric,
            &reason,
            &src,
        )
        .await;

        {
            let mut chan = channel.write().await;
            chan.remove_member(&target_id);
        }
        {
            let mut tc = target.write().await;
            tc.channels.remove(chan_name);
        }
    } else if let Some(remote) = remote_target {
        let target_numeric = remote.read().await.numeric;
        {
            let chan = channel.read().await;
            if !chan.remote_members.contains_key(&target_numeric) {
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

        let kick_msg = Message::with_source(
            &prefix,
            Command::Kick,
            vec![chan_name.clone(), target_nick.clone(), reason.clone()],
        );
        send_to_channel(ctx, chan_name, &kick_msg, &src).await;

        // Remove from chan.remote_members and rc.channels BEFORE routing
        // the KICK upstream. nefarious2's make_zombie (channel.c:2259-2263)
        // sends us back an L (PART) acknowledgment for the kicked user,
        // and the S2S read task runs concurrently — if we route first,
        // the PART can land in handle_part while the user is still in
        // chan.remote_members, producing a phantom "has left" right
        // after the KICK. Removing first makes handle_part's "was this
        // user still a member?" check reliably return false.
        {
            let mut chan = channel.write().await;
            chan.remote_members.remove(&target_numeric);
        }
        {
            let mut rc = remote.write().await;
            rc.channels.remove(chan_name);
        }

        // Remote victim — route with their 5-char YYXXX so the
        // upstream peer can find them.
        crate::s2s::routing::route_kick(
            &ctx.state,
            client_id,
            chan_name,
            &target_numeric.to_string(),
            &reason,
            &src,
        )
        .await;

        ctx.state.reap_channel_if_empty(chan_name).await;
    } else {
        ctx.send_numeric(
            ERR_NOSUCHNICK,
            vec![target_nick.clone(), "No such nick/channel".into()],
        )
        .await;
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

    // Resolve the target. A local match takes precedence (standard
    // IRC semantics — local nick lookups win), but if no local client
    // has that nick we fall through to the remote nick table. Neither
    // hit produces ERR_NOSUCHNICK.
    enum InviteTarget {
        Local {
            id: crate::client::ClientId,
            arc: std::sync::Arc<tokio::sync::RwLock<crate::client::Client>>,
            canonical_nick: String,
        },
        Remote {
            numeric: p10_proto::ClientNumeric,
            canonical_nick: String,
        },
    }

    let target = if let Some(arc) = ctx.state.find_client_by_nick(target_nick) {
        let (id, nick) = {
            let c = arc.read().await;
            (c.id, c.nick.clone())
        };
        InviteTarget::Local {
            id,
            arc,
            canonical_nick: nick,
        }
    } else if let Some(remote) = ctx.state.find_remote_by_nick(target_nick) {
        let (numeric, nick) = {
            let r = remote.read().await;
            (r.numeric, r.nick.clone())
        };
        InviteTarget::Remote {
            numeric,
            canonical_nick: nick,
        }
    } else {
        ctx.send_numeric(
            ERR_NOSUCHNICK,
            vec![target_nick.clone(), "No such nick/channel".into()],
        )
        .await;
        return;
    };

    // "Already on channel?" check — consult the matching membership
    // map for the target's locality.
    {
        let chan = channel.read().await;
        let already_on = match &target {
            InviteTarget::Local { id, .. } => chan.is_member(id),
            InviteTarget::Remote { numeric, .. } => {
                chan.remote_members.contains_key(numeric)
            }
        };
        if already_on {
            let canonical_nick = match &target {
                InviteTarget::Local { canonical_nick, .. } => canonical_nick,
                InviteTarget::Remote { canonical_nick, .. } => canonical_nick,
            };
            ctx.send_numeric(
                ERR_USERONCHANNEL,
                vec![
                    canonical_nick.clone(),
                    chan_name.clone(),
                    "is already on channel".into(),
                ],
            )
            .await;
            return;
        }
    }

    // Track the invite in chan.invites so the local JOIN check
    // honours the +i bypass. Only applicable for local targets —
    // remote users are invite-checked by their own server.
    if let InviteTarget::Local { id, .. } = &target {
        let mut chan = channel.write().await;
        chan.invites.insert(*id);
    }

    let prefix = ctx.prefix().await;

    let canonical_nick = match &target {
        InviteTarget::Local { canonical_nick, .. } => canonical_nick.clone(),
        InviteTarget::Remote { canonical_nick, .. } => canonical_nick.clone(),
    };

    // Notify inviter
    ctx.send_numeric(
        RPL_INVITING,
        vec![canonical_nick.clone(), chan_name.clone()],
    )
    .await;

    let invite_msg = Message::with_source(
        &prefix,
        Command::Invite,
        vec![canonical_nick.clone(), chan_name.clone()],
    );
    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);

    // Direct delivery to a local target. Remote targets receive the
    // INVITE via the S2S route below (their own server hands it to them).
    let local_target_id: Option<crate::client::ClientId> = match &target {
        InviteTarget::Local { id, arc, .. } => {
            arc.read().await.send_from(invite_msg.clone(), &src);
            Some(*id)
        }
        InviteTarget::Remote { .. } => None,
    };

    // IRCv3 invite-notify: fan to every channel op with the cap.
    // Skip the inviter (would echo) and the target if they're local
    // (already delivered directly).
    if let Some(channel) = ctx.state.get_channel(chan_name) {
        let chan = channel.read().await;
        for (&member_id, flags) in &chan.members {
            if member_id == client_id || Some(member_id) == local_target_id {
                continue;
            }
            if !flags.op {
                continue;
            }
            if let Some(member) = ctx.state.clients.get(&member_id) {
                let m = member.read().await;
                if m.has_cap(crate::capabilities::Capability::InviteNotify) {
                    m.send_from(invite_msg.clone(), &src);
                }
            }
        }
    }

    // Route to S2S so the target's server (local or remote) delivers
    // the INVITE to its user. For a local target we still route so
    // other peers can drive their own invite-notify fan-outs. The
    // wire uses the target's *nick* (not numeric) plus the channel's
    // creation TS — see route_invite doc comment.
    let chan_ts = {
        let c = channel.read().await;
        c.created_ts
    };
    crate::s2s::routing::route_invite(
        &ctx.state,
        client_id,
        &canonical_nick,
        chan_name,
        chan_ts,
        &src,
    )
    .await;
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

/// Send a JOIN to every channel member, picking the `extended-join`
/// form for clients that negotiated the cap and the plain form for
/// everyone else. Per-recipient IRCv3 tags are applied via
/// `send_from`.
async fn send_join_to_channel(
    ctx: &HandlerContext,
    chan_name: &str,
    plain: &Message,
    extended: &Message,
    src: &crate::tags::SourceInfo,
) {
    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => return,
    };

    let chan = channel.read().await;
    for (&member_id, _) in &chan.members {
        if let Some(member) = ctx.state.clients.get(&member_id) {
            let m = member.read().await;
            let msg = if m.has_cap(crate::capabilities::Capability::ExtendedJoin) {
                extended.clone()
            } else {
                plain.clone()
            };
            m.send_from(msg, src);
        }
    }
}

/// Send a message to all members of a channel with per-recipient
/// IRCv3 tag attachment. `src` is the event metadata (time, source
/// account) used by `send_from`.
pub async fn send_to_channel(
    ctx: &HandlerContext,
    chan_name: &str,
    msg: &Message,
    src: &crate::tags::SourceInfo,
) {
    let channel = match ctx.state.get_channel(chan_name) {
        Some(c) => c,
        None => return,
    };

    let chan = channel.read().await;
    for (&member_id, _) in &chan.members {
        if let Some(member) = ctx.state.clients.get(&member_id) {
            let m = member.read().await;
            m.send_from(msg.clone(), src);
        }
    }
}

/// Send topic information for a channel to the requesting client.
///
/// `on_query` distinguishes the two call sites: a /TOPIC query with no
/// argument expects RPL_NOTOPIC when the topic is unset, whereas a JOIN
/// should stay silent in that case (matches nefarious2/ircd/m_join.c:290
/// which only emits RPL_TOPIC when `chptr->topic[0]` is non-empty).
async fn send_topic(ctx: &HandlerContext, chan_name: &str, on_query: bool) {
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
        None if on_query => {
            ctx.send_numeric(
                RPL_NOTOPIC,
                vec![chan_name.to_string(), "No topic is set".into()],
            )
            .await;
        }
        None => {}
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

    // Format knobs come from the requester's negotiated caps:
    //   multi-prefix      → emit every active prefix (e.g. `@+nick`)
    //                        instead of only the highest.
    //   userhost-in-names → emit `nick!user@host` instead of just `nick`.
    let (multi_prefix, userhost_in_names) = {
        let c = ctx.client.read().await;
        (
            c.has_cap(crate::capabilities::Capability::MultiPrefix),
            c.has_cap(crate::capabilities::Capability::UserhostInNames),
        )
    };

    // Build names list. Include BOTH local members and remote members
    // (from other servers via P10) so a client on our side actually
    // sees everyone in the channel. Without the remote branch, users
    // on the far side of any s2s link are invisible to /NAMES — and
    // the client-side channel roster stays empty, which in turn
    // prevents it from rendering PRIVMSGs arriving from those users.
    let mut names = Vec::new();
    for (&member_id, flags) in &chan.members {
        if let Some(member) = ctx.state.clients.get(&member_id) {
            let m = member.read().await;
            let prefix = if multi_prefix {
                flags.all_prefixes()
            } else {
                flags.highest_prefix().to_string()
            };
            let identity = if userhost_in_names {
                format!("{}!{}@{}", m.nick, m.user, m.host)
            } else {
                m.nick.clone()
            };
            names.push(format!("{prefix}{identity}"));
        }
    }
    for (&numeric, flags) in &chan.remote_members {
        if let Some(remote) = ctx.state.remote_clients.get(&numeric) {
            let r = remote.read().await;
            // Bouncer aliases are network-invisible — they share
            // identity with their primary and would render as a
            // duplicate entry in NAMES. Skip them; the primary is
            // listed via its own membership (or via BjAAA etc.).
            if r.is_alias {
                continue;
            }
            let prefix = if multi_prefix {
                flags.all_prefixes()
            } else {
                flags.highest_prefix().to_string()
            };
            let identity = if userhost_in_names {
                format!("{}!{}@{}", r.nick, r.user, r.host)
            } else {
                r.nick.clone()
            };
            names.push(format!("{prefix}{identity}"));
        }
        // No RemoteClient: silently skip. Either the numeric is an
        // alias we haven't been introduced to via BX C, or upstream
        // state is stale; either way, we can't render an identity.
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
