use std::collections::HashSet;
use std::sync::Arc;

use irc_proto::irc_casefold;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use p10_proto::{ClientNumeric, P10Message, ServerNumeric};

use crate::channel::{BanEntry, Channel, ChannelModes, MembershipFlags};
use crate::s2s::types::{RemoteClient, RemoteServer, ServerFlags, ServerLink};
use crate::state::ServerState;

/// Handle S (SERVER) — remote server introduction during burst.
pub async fn handle_server(state: &ServerState, msg: &P10Message) {
    // SERVER has 8 params: name hop start_ts link_ts protocol numeric_capacity flags :description
    if msg.params.len() < 8 {
        warn!("SERVER message too short: {:?}", msg.params);
        return;
    }

    let name = &msg.params[0];
    let hop_count: u16 = msg.params[1].parse().unwrap_or(1);
    let _zero = &msg.params[2]; // always "0" for burst servers
    let timestamp: u64 = msg.params[3].parse().unwrap_or(0);
    let _protocol = &msg.params[4];
    let numeric_capacity = &msg.params[5];
    let flags_str = msg.params[6].as_str();
    let description = msg.params.last().unwrap();

    let (numeric, _mask) = match p10_proto::numeric::parse_server_numeric_capacity(numeric_capacity)
    {
        Some(v) => v,
        None => return,
    };

    let uplink = msg
        .origin
        .as_ref()
        .and_then(|o| ServerNumeric::from_str(o))
        .unwrap_or(state.numeric);

    info!("remote server: {name} ({numeric}), hop={hop_count}, uplink={uplink}");

    let server = Arc::new(RwLock::new(RemoteServer {
        name: name.to_string(),
        numeric,
        hop_count,
        description: description.to_string(),
        uplink,
        timestamp,
        flags: ServerFlags::from_flag_str(flags_str),
    }));

    state.remote_servers.insert(numeric, server);
}

/// Handle N (NICK) — remote user introduction during burst or nick change.
pub async fn handle_nick(state: &ServerState, msg: &P10Message) {
    // Burst NICK: <origin> N <nick> <hopcount> <nick_ts> <user> <host> <modes> <ip> <numeric> :<realname>
    // Nick change: <user_numeric> N <new_nick> <nick_ts>

    if msg.params.len() <= 2 {
        // Nick change
        handle_nick_change(state, msg).await;
        return;
    }

    if msg.params.len() < 8 {
        warn!("NICK message too short: {:?}", msg.params);
        return;
    }

    let nick = &msg.params[0];
    let _hop: u16 = msg.params[1].parse().unwrap_or(1);
    let nick_ts: u64 = msg.params[2].parse().unwrap_or(0);
    let user = &msg.params[3];
    let host = &msg.params[4];

    // Parse modes and find IP/numeric positions
    // Modes start at params[5], might be "+xyz" or just the IP if no modes
    let (modes, ip_idx) = if msg.params[5].starts_with('+') {
        let modes: HashSet<char> = msg.params[5][1..].chars().collect();
        (modes, 6)
    } else {
        (HashSet::new(), 5)
    };

    if msg.params.len() <= ip_idx + 1 {
        warn!("NICK message missing IP/numeric: {:?}", msg.params);
        return;
    }

    let ip_base64 = &msg.params[ip_idx];

    // P10 NICK burst uses a single combined 5-char YYXXX numeric (2 server + 3 user).
    let numeric = match ClientNumeric::from_str(&msg.params[ip_idx + 1]) {
        Some(n) => n,
        None => {
            warn!("invalid NICK numeric: {:?}", msg.params);
            return;
        }
    };

    let realname = msg.params.last().unwrap().to_string();

    info!("remote user: {nick} ({numeric}) on server {}", numeric.server);

    // Sanity checks. Two different users cannot share a YYXXX, and
    // the server portion must be in our server map — otherwise the
    // burst arrived out of order and we'll end up with ghost state.
    if !state.remote_servers.contains_key(&numeric.server) && numeric.server != state.numeric {
        warn!(
            "accepting NICK for {nick} on unknown server {} (numeric={numeric}) — introduced before SERVER intro?",
            numeric.server
        );
    }
    if let Some(existing) = state.remote_clients.get(&numeric) {
        let existing_nick = existing.read().await.nick.clone();
        warn!(
            "numeric collision: {numeric} already held by {existing_nick}; new burst introduces it as {nick}"
        );
    }

    // P10 nick-TS collision resolution: if another user already owns this
    // casefolded nick, the one with the older nick_ts wins. Equal TS → both
    // lose. Without this, two servers introducing the same nick silently
    // corrupt the nick map.
    //
    // Whenever our decision drops a user, emit a P10 KILL so every server
    // on the network converges on the same state. Otherwise we'd silently
    // remove an entry while the user's own server still believes they're
    // online.
    match find_nick_owner(state, nick).await {
        Some(NickOwner::Local { id, ts: local_ts }) => {
            use std::cmp::Ordering::*;
            match nick_ts.cmp(&local_ts) {
                Less => {
                    warn!(
                        "nick collision on {nick}: remote (ts={nick_ts}) wins over local (ts={local_ts})"
                    );
                    let local_nick = collision_kill_local(state, id, "Nick collision").await;
                    if let Some(n) = local_nick {
                        crate::s2s::routing::route_kill(state, &n, "Nick collision").await;
                    }
                }
                Greater => {
                    warn!(
                        "nick collision on {nick}: local (ts={local_ts}) wins over remote (ts={nick_ts}); dropping remote"
                    );
                    crate::s2s::routing::route_kill(state, nick, "Nick collision").await;
                    return;
                }
                Equal => {
                    warn!("nick collision tie on {nick} at ts={nick_ts}; killing both");
                    let local_nick = collision_kill_local(state, id, "Nick collision").await;
                    if let Some(n) = local_nick {
                        crate::s2s::routing::route_kill(state, &n, "Nick collision").await;
                    }
                    crate::s2s::routing::route_kill(state, nick, "Nick collision").await;
                    return;
                }
            }
        }
        Some(NickOwner::Remote { numeric: existing, ts: existing_ts }) => {
            use std::cmp::Ordering::*;
            match nick_ts.cmp(&existing_ts) {
                Less => {
                    warn!(
                        "nick collision on {nick}: newer remote (ts={nick_ts}) wins over existing remote (ts={existing_ts})"
                    );
                    crate::s2s::routing::route_kill(
                        state,
                        &existing.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(existing).await;
                }
                Greater => {
                    warn!("nick collision on {nick}: existing remote wins; dropping incoming");
                    crate::s2s::routing::route_kill(state, nick, "Nick collision").await;
                    return;
                }
                Equal => {
                    warn!("nick collision tie on {nick}; removing both");
                    crate::s2s::routing::route_kill(
                        state,
                        &existing.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(existing).await;
                    crate::s2s::routing::route_kill(state, nick, "Nick collision").await;
                    return;
                }
            }
        }
        None => {}
    }

    let client = Arc::new(RwLock::new(RemoteClient {
        nick: nick.to_string(),
        numeric,
        server: numeric.server,
        user: user.to_string(),
        host: host.to_string(),
        realname,
        ip_base64: ip_base64.to_string(),
        modes,
        account: None,
        nick_ts,
        channels: HashSet::new(),
    }));

    state.register_remote_client(client, nick, numeric);
}

/// Who currently owns a nick, for TS-based collision resolution.
enum NickOwner {
    Local { id: crate::client::ClientId, ts: u64 },
    Remote { numeric: ClientNumeric, ts: u64 },
}

async fn find_nick_owner(state: &ServerState, nick: &str) -> Option<NickOwner> {
    let casefolded = irc_casefold(nick);

    // Local owner?
    if let Some(entry) = state.nicks.get(&casefolded) {
        let id = *entry;
        drop(entry);
        if let Some(client_arc) = state.clients.get(&id) {
            let ts = client_arc.read().await.nick_ts;
            return Some(NickOwner::Local { id, ts });
        }
    }

    // Remote owner?
    if let Some(entry) = state.remote_nicks.get(&casefolded) {
        let numeric = *entry;
        drop(entry);
        if let Some(remote_arc) = state.remote_clients.get(&numeric) {
            let ts = remote_arc.read().await.nick_ts;
            return Some(NickOwner::Remote { numeric, ts });
        }
    }

    None
}

/// Release the nick immediately and ask the client's message loop to exit.
/// The actual socket close and channel QUIT broadcasts happen when the
/// loop returns through its normal cleanup path. Returns the victim's old
/// nick so the caller can propagate a P10 KILL upstream.
async fn collision_kill_local(
    state: &ServerState,
    id: crate::client::ClientId,
    reason: &str,
) -> Option<String> {
    let client_arc = state.clients.get(&id)?;
    let client = client_arc.read().await;
    let nick = client.nick.clone();
    state.release_nick(&nick, id);
    client.request_disconnect(reason);
    Some(nick)
}

/// Handle nick change from remote user.
async fn handle_nick_change(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    let new_nick = match msg.params.first() {
        Some(n) => n,
        None => return,
    };

    // Remote nick-change format: `<user_numeric> N <new_nick> <nick_ts>`.
    // The nick timestamp is load-bearing for future collision resolution
    // (older TS wins), so capture it alongside the nick itself.
    let new_nick_ts: u64 = msg
        .params
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    // Collision check BEFORE renaming: the new nick may be taken.
    // A remote user is already guaranteed to hold its *current* nick, so
    // ignore that entry if `find_nick_owner` returns it. Same KILL-on-
    // decision rule as handle_nick so the rest of the network converges.
    match find_nick_owner(state, new_nick).await {
        Some(NickOwner::Local { id, ts: local_ts }) => {
            use std::cmp::Ordering::*;
            match new_nick_ts.cmp(&local_ts) {
                Less => {
                    warn!(
                        "rename collision on {new_nick}: remote (ts={new_nick_ts}) wins over local (ts={local_ts})"
                    );
                    let local_nick =
                        collision_kill_local(state, id, "Nick collision").await;
                    if let Some(n) = local_nick {
                        crate::s2s::routing::route_kill(state, &n, "Nick collision").await;
                    }
                }
                Greater => {
                    warn!(
                        "rename collision on {new_nick}: local wins; dropping remote rename"
                    );
                    crate::s2s::routing::route_kill(
                        state,
                        &numeric.to_string(),
                        "Nick collision",
                    )
                    .await;
                    return;
                }
                Equal => {
                    let local_nick =
                        collision_kill_local(state, id, "Nick collision").await;
                    if let Some(n) = local_nick {
                        crate::s2s::routing::route_kill(state, &n, "Nick collision").await;
                    }
                    crate::s2s::routing::route_kill(
                        state,
                        &numeric.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(numeric).await;
                    return;
                }
            }
        }
        Some(NickOwner::Remote { numeric: existing, ts: existing_ts }) if existing != numeric => {
            use std::cmp::Ordering::*;
            match new_nick_ts.cmp(&existing_ts) {
                Less => {
                    crate::s2s::routing::route_kill(
                        state,
                        &existing.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(existing).await;
                }
                Greater => {
                    crate::s2s::routing::route_kill(
                        state,
                        &numeric.to_string(),
                        "Nick collision",
                    )
                    .await;
                    return;
                }
                Equal => {
                    crate::s2s::routing::route_kill(
                        state,
                        &existing.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(existing).await;
                    crate::s2s::routing::route_kill(
                        state,
                        &numeric.to_string(),
                        "Nick collision",
                    )
                    .await;
                    state.remove_remote_client(numeric).await;
                    return;
                }
            }
        }
        _ => {}
    }

    if let Some(remote) = state.remote_clients.get(&numeric) {
        let old_nick = {
            let mut rc = remote.write().await;
            let old = rc.nick.clone();
            rc.nick = new_nick.clone();
            if new_nick_ts > 0 {
                rc.nick_ts = new_nick_ts;
            }
            old
        };

        state.rename_remote_nick(&old_nick, new_nick, numeric);

        // Notify local channel members
        let rc = remote.read().await;
        let nick_msg = irc_proto::Message::with_source(
            &rc.prefix(),
            irc_proto::Command::Nick,
            vec![new_nick.clone()],
        );
        let src = crate::tags::SourceInfo::from_remote(&rc);

        for chan_name in &rc.channels {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        m.send_from(nick_msg.clone(), &src);
                    }
                }
            }
        }
    }
}

/// Handle B (BURST) — channel state during burst.
///
/// Format: `<origin> B <channel> <create_ts> [+<modes> [<mode_params>]] [<members>] [%<bans>]`
pub async fn handle_burst(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 2 {
        return;
    }

    let chan_name = &msg.params[0];
    let create_ts: u64 = msg.params[1].parse().unwrap_or(0);

    let channel_arc = state.get_or_create_channel(chan_name);
    let mut chan = channel_arc.write().await;

    // P10 channel-TS collision resolution. The side with the older
    // `created_ts` is authoritative for modes, bans and op status;
    // the newer side resets its modes/bans and de-ops its members
    // (the classic "TS oper burst" behaviour).
    //
    //   remote_wins: burst_ts < local_ts  (or we had no prior state)
    //   local_wins:  burst_ts > local_ts
    //   tie:         burst_ts == local_ts (both >0) — merge both sides
    let local_ts = chan.created_ts;
    let remote_wins = create_ts > 0 && (local_ts == 0 || create_ts < local_ts);
    let local_wins = local_ts > 0 && create_ts > local_ts;

    if remote_wins {
        chan.created_ts = create_ts;
        chan.modes = ChannelModes::default();
        chan.bans.clear();
        for m in chan.members.values_mut() {
            m.op = false;
        }
        for m in chan.remote_members.values_mut() {
            m.op = false;
        }
    }

    // Parse remaining params: modes, members, bans
    let mut idx = 2;

    // Parse modes if present. Always consume the mode params from the wire
    // so downstream indexing is correct; only apply them to state when the
    // local side is NOT the authoritative one.
    if idx < msg.params.len() && msg.params[idx].starts_with('+') {
        let mode_str = msg.params[idx].clone();
        idx += 1;

        if !local_wins {
            apply_burst_modes(&mut chan, &mode_str);
        }

        // A key parameter follows if the mode string contains 'k'; a limit
        // parameter follows if it contains 'l'. Consume each regardless;
        // only assign to chan.modes when we're taking the remote's state.
        if mode_str.contains('k') {
            if let Some(key) = msg.params.get(idx) {
                if !local_wins {
                    chan.modes.key = Some(key.clone());
                }
                idx += 1;
            }
        }
        if mode_str.contains('l') {
            if let Some(limit_str) = msg.params.get(idx) {
                if !local_wins {
                    if let Ok(limit) = limit_str.parse::<u32>() {
                        chan.modes.limit = Some(limit);
                    }
                }
                idx += 1;
            }
        }
    }

    // Parse members and bans from remaining params. Members are always
    // added to the channel roster, but their op/voice flags are only
    // honoured when we aren't the authoritative side.
    let accept_status = !local_wins;
    while idx < msg.params.len() {
        let param = &msg.params[idx];

        if param.starts_with('%') {
            if accept_status {
                for mask in param[1..].split(' ').filter(|s| !s.is_empty()) {
                    chan.bans.push(BanEntry {
                        mask: mask.to_string(),
                        set_by: "burst".to_string(),
                        set_at: chrono::Utc::now(),
                    });
                }
            }
            idx += 1;
            while idx < msg.params.len() {
                if accept_status {
                    for mask in msg.params[idx].split(' ').filter(|s| !s.is_empty()) {
                        chan.bans.push(BanEntry {
                            mask: mask.to_string(),
                            set_by: "burst".to_string(),
                            set_at: chrono::Utc::now(),
                        });
                    }
                }
                idx += 1;
            }
            break;
        }

        if param.contains(',')
            || ClientNumeric::from_str(param.split(':').next().unwrap_or("")).is_some()
        {
            parse_burst_members(state, &mut chan, param, accept_status).await;
        }

        idx += 1;
    }

    debug!(
        "burst: {} - {} remote members, {} bans, modes={}",
        chan_name,
        chan.remote_members.len(),
        chan.bans.len(),
        chan.modes.to_mode_string()
    );
}

/// Parse burst mode string and apply to channel.
fn apply_burst_modes(chan: &mut Channel, mode_str: &str) {
    for c in mode_str.chars() {
        match c {
            '+' => {}
            'n' => chan.modes.no_external = true,
            't' => chan.modes.topic_ops_only = true,
            'm' => chan.modes.moderated = true,
            'i' => chan.modes.invite_only = true,
            's' => chan.modes.secret = true,
            'p' => chan.modes.private = true,
            'k' => chan.modes.key = Some(String::new()), // placeholder, filled from params
            'l' => chan.modes.limit = Some(0), // placeholder, filled from params
            _ => {}
        }
    }
}

/// Parse a burst member list and fold it into the channel roster.
///
/// When `accept_status` is false (local side won the TS race), the listed
/// op/voice bits are discarded — the member joins as a plain participant.
async fn parse_burst_members(
    state: &ServerState,
    chan: &mut Channel,
    member_str: &str,
    accept_status: bool,
) {
    for entry in member_str.split(',') {
        let (numeric_str, mode_str) = match entry.find(':') {
            Some(pos) => (&entry[..pos], &entry[pos + 1..]),
            None => (entry, ""),
        };

        let numeric = match ClientNumeric::from_str(numeric_str) {
            Some(n) => n,
            None => continue,
        };

        let mut flags = MembershipFlags::default();
        if accept_status {
            for c in mode_str.chars() {
                match c {
                    'o' | '0' => flags.op = true,
                    'v' => flags.voice = true,
                    _ => {} // oplevel numbers, halfop, etc.
                }
            }
        }

        chan.remote_members.insert(numeric, flags);

        // Track channel on the remote client
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let mut rc = remote.write().await;
            rc.channels.insert(chan.name.clone());
        }
    }
}

/// Handle G (PING) from remote server.
pub async fn handle_ping(state: &ServerState, msg: &P10Message, link: &ServerLink) {
    // PING wire: `<pinger> G [<arg>] :<destination>`.
    // PONG wire (matches nefarious2/ircd/m_ping.c:275): `<us> Z <us> :<pinger>`.
    // The PONG's first field is our numeric (routing anchor), and the
    // trailing colon-prefixed param echoes the ping's origin.
    let pinger = msg.origin.as_deref().unwrap_or("");
    let pong = format!("{us} Z {us} :{pinger}", us = state.numeric);
    link.send_line(pong).await;
}

/// Handle P/O (PRIVMSG/NOTICE) from remote — deliver to local users.
pub async fn handle_privmsg_notice(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    if msg.params.len() < 2 {
        return;
    }

    let target = &msg.params[0];
    let text = &msg.params[1];

    // Find the remote sender, capturing the prefix AND the account so
    // cap-gated tags (@account) resolve correctly per recipient.
    let (sender_prefix, src) = if let Some(numeric) = ClientNumeric::from_str(origin) {
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let rc = remote.read().await;
            (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc))
        } else {
            warn!(
                "dropping PRIVMSG/NOTICE to {target}: unknown remote origin numeric {numeric}"
            );
            return;
        }
    } else {
        // Server origin — use server name, no account.
        let prefix = if let Some(sn) = ServerNumeric::from_str(origin) {
            if let Some(server) = state.remote_servers.get(&sn) {
                server.read().await.name.clone()
            } else {
                origin.to_string()
            }
        } else {
            origin.to_string()
        };
        (prefix, crate::tags::SourceInfo::now())
    };

    let command = match msg.token {
        p10_proto::P10Token::Privmsg => irc_proto::Command::Privmsg,
        _ => irc_proto::Command::Notice,
    };

    let irc_msg = irc_proto::Message::with_source(
        &sender_prefix,
        command,
        vec![target.clone(), text.clone()],
    );

    if target.starts_with('#') || target.starts_with('&') {
        // Channel message — deliver to local members
        if let Some(channel) = state.get_channel(target) {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(irc_msg.clone(), &src);
                }
            }
        }
    } else {
        // Private message to a user — could be nick or numeric
        if let Some(client) = state.find_client_by_nick(target) {
            let c = client.read().await;
            c.send_from(irc_msg, &src);
        }
    }
}

/// Handle J (JOIN) from remote.
pub async fn handle_join(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    if msg.params.is_empty() {
        return;
    }

    let chan_name = &msg.params[0];

    // Get remote client info for the JOIN message
    let (prefix, src) = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.insert(chan_name.to_string());
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc))
    } else {
        warn!(
            "dropping JOIN for {chan_name}: unknown remote user numeric {numeric}"
        );
        return;
    };

    info!("remote JOIN: {prefix} → {chan_name}");

    let channel = state.get_or_create_channel(chan_name);
    {
        let mut chan = channel.write().await;
        chan.remote_members
            .insert(numeric, MembershipFlags::default());
    }

    // Notify local channel members
    let join_msg = irc_proto::Message::with_source(
        &prefix,
        irc_proto::Command::Join,
        vec![chan_name.clone()],
    );

    let chan = channel.read().await;
    for (&member_id, _) in &chan.members {
        if let Some(member) = state.clients.get(&member_id) {
            let m = member.read().await;
            m.send_from(join_msg.clone(), &src);
        }
    }
}

/// Handle C (CREATE) from remote — new channel created by remote user.
pub async fn handle_create(state: &ServerState, msg: &P10Message) {
    // CREATE format: <user_numeric> C <channel> <timestamp>
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    if msg.params.is_empty() {
        return;
    }

    let chan_name = &msg.params[0];
    let ts: u64 = msg.params.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let (prefix, src) = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.insert(chan_name.to_string());
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc))
    } else {
        warn!(
            "dropping CREATE for {chan_name}: unknown remote user numeric {numeric}"
        );
        return;
    };

    info!("remote CREATE: {prefix} → {chan_name}");

    let channel = state.get_or_create_channel(chan_name);
    {
        let mut chan = channel.write().await;
        if ts > 0 {
            chan.created_ts = ts;
        }
        // Creator gets ops
        chan.remote_members.insert(
            numeric,
            MembershipFlags {
                op: true,
                ..Default::default()
            },
        );
    }

    // Notify local channel members (if any — usually none for CREATE)
    let join_msg = irc_proto::Message::with_source(
        &prefix,
        irc_proto::Command::Join,
        vec![chan_name.clone()],
    );

    let chan = channel.read().await;
    for (&member_id, _) in &chan.members {
        if let Some(member) = state.clients.get(&member_id) {
            let m = member.read().await;
            m.send_from(join_msg.clone(), &src);
        }
    }
}

/// Handle L (PART) from remote.
pub async fn handle_part(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    if msg.params.is_empty() {
        return;
    }

    let chan_name = &msg.params[0];
    let reason = msg.params.get(1).cloned().unwrap_or_default();

    let (prefix, src) = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.remove(chan_name);
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc))
    } else {
        return;
    };

    // Notify local members before removing
    let mut part_params = vec![chan_name.clone()];
    if !reason.is_empty() {
        part_params.push(reason);
    }
    let part_msg =
        irc_proto::Message::with_source(&prefix, irc_proto::Command::Part, part_params);

    if let Some(channel) = state.get_channel(chan_name) {
        {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(part_msg.clone(), &src);
                }
            }
        }

        // Remove remote member
        let mut chan = channel.write().await;
        chan.remote_members.remove(&numeric);
    }
}

/// Handle D (KILL) from remote.
///
/// KILL wire: `<killer> D <victim> :<killpath> (<reason>)`. Unlike QUIT
/// (where the origin IS the user quitting), the origin of a KILL is the
/// killer and `params[0]` identifies the victim — which is why this is
/// separate from `handle_quit`.
pub async fn handle_kill(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }
    let victim = &msg.params[0];
    let reason = msg
        .params
        .last()
        .cloned()
        .unwrap_or_else(|| "Killed".to_string());

    // Victim might be a numeric or a nick.
    let resolved_numeric = ClientNumeric::from_str(victim).or_else(|| {
        state
            .remote_nicks
            .get(&irc_casefold(victim))
            .map(|e| *e)
    });

    if let Some(numeric) = resolved_numeric {
        // Remote user killed — broadcast QUIT to channels and drop state.
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let rc = remote.read().await;
            let quit_msg = irc_proto::Message::with_source(
                &rc.prefix(),
                irc_proto::Command::Quit,
                vec![format!("Killed ({reason})")],
            );
            let src = crate::tags::SourceInfo::from_remote(&rc);
            for chan_name in &rc.channels {
                if let Some(channel) = state.get_channel(chan_name) {
                    let chan = channel.read().await;
                    for (&member_id, _) in &chan.members {
                        if let Some(member) = state.clients.get(&member_id) {
                            let m = member.read().await;
                            m.send_from(quit_msg.clone(), &src);
                        }
                    }
                }
            }
        }
        state.remove_remote_client(numeric).await;
        return;
    }

    // Fall back to local lookup by nick — remote killed one of our users.
    if let Some(client_arc) = state.find_client_by_nick(victim) {
        let client = client_arc.read().await;
        client.request_disconnect(format!("Killed ({reason})"));
    }
}

/// Handle Q (QUIT) from remote.
pub async fn handle_quit(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    let reason = msg.params.first().cloned().unwrap_or("Quit".to_string());

    if let Some(remote) = state.remote_clients.get(&numeric) {
        let rc = remote.read().await;
        let quit_msg = irc_proto::Message::with_source(
            &rc.prefix(),
            irc_proto::Command::Quit,
            vec![reason],
        );
        let src = crate::tags::SourceInfo::from_remote(&rc);

        // Notify local channel members
        for chan_name in &rc.channels {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        m.send_from(quit_msg.clone(), &src);
                    }
                }
            }
        }
    }

    state.remove_remote_client(numeric).await;
}

/// Handle M (MODE) from remote.
pub async fn handle_mode(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }

    let target = &msg.params[0];
    if !target.starts_with('#') && !target.starts_with('&') {
        // User mode change — ignore for now
        return;
    }

    // Find the source prefix for relaying to local users
    let source_prefix = get_source_prefix(state, msg).await;
    let src = source_info_from_origin(state, msg).await;

    // Apply the mode change to our own channel state BEFORE relaying. Without
    // this, local op/voice/ban/flag state drifts out of sync with peers and
    // every subsequent permission check gives the wrong answer.
    if msg.params.len() >= 2 {
        let mode_str = msg.params[1].clone();
        let mode_params: Vec<String> = msg.params[2..].to_vec();
        apply_remote_channel_mode(state, target, &mode_str, &mode_params).await;
    }

    // Relay the MODE message to local channel members
    if let Some(channel) = state.get_channel(target) {
        let mode_msg = irc_proto::Message::with_source(
            &source_prefix,
            irc_proto::Command::Mode,
            msg.params.clone(),
        );

        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send_from(mode_msg.clone(), &src);
            }
        }
    }
}

/// Apply a MODE message from a remote server to our channel state.
///
/// Op/voice targets in P10 MODE are nicks (not numerics), so resolve them
/// against both local and remote nick tables. Op/voice on a target we don't
/// know is silently dropped — the network will resync on the next burst.
async fn apply_remote_channel_mode(
    state: &ServerState,
    chan_name: &str,
    mode_str: &str,
    params: &[String],
) {
    let channel = match state.get_channel(chan_name) {
        Some(c) => c,
        None => return,
    };

    // Resolve any op/voice nick targets to ids BEFORE taking the channel
    // write lock, so we never block the channel while awaiting a Client
    // read lock elsewhere.
    enum MemberTarget {
        Local(crate::client::ClientId),
        Remote(ClientNumeric),
    }
    let mut resolved: Vec<MemberTarget> = Vec::new();
    let mut pi = 0usize;
    let mut scan_adding = true;
    for c in mode_str.chars() {
        match c {
            '+' => scan_adding = true,
            '-' => scan_adding = false,
            'o' | 'v' => {
                if let Some(nick) = params.get(pi) {
                    if let Some(client) = state.find_client_by_nick(nick) {
                        let id = client.read().await.id;
                        resolved.push(MemberTarget::Local(id));
                    } else if let Some(remote) = state.find_remote_by_nick(nick) {
                        let numeric = remote.read().await.numeric;
                        resolved.push(MemberTarget::Remote(numeric));
                    }
                    pi += 1;
                }
                let _ = scan_adding;
            }
            'k' | 'b' => {
                // consume param on both + and -
                if params.get(pi).is_some() {
                    pi += 1;
                }
            }
            'l' => {
                if scan_adding && params.get(pi).is_some() {
                    pi += 1;
                }
            }
            _ => {}
        }
    }

    let mut chan = channel.write().await;
    let mut adding = true;
    let mut pi = 0usize;
    let mut ri = 0usize; // resolved-target index

    for c in mode_str.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,

            'n' => chan.modes.no_external = adding,
            't' => chan.modes.topic_ops_only = adding,
            'm' => chan.modes.moderated = adding,
            'i' => chan.modes.invite_only = adding,
            's' => chan.modes.secret = adding,
            'p' => chan.modes.private = adding,

            'k' => {
                if adding {
                    if let Some(key) = params.get(pi) {
                        chan.modes.key = Some(key.clone());
                    }
                } else {
                    chan.modes.key = None;
                }
                if params.get(pi).is_some() {
                    pi += 1;
                }
            }
            'l' => {
                if adding {
                    if let Some(limit_str) = params.get(pi) {
                        if let Ok(limit) = limit_str.parse::<u32>() {
                            chan.modes.limit = Some(limit);
                        }
                        pi += 1;
                    }
                } else {
                    chan.modes.limit = None;
                }
            }
            'o' | 'v' => {
                let is_voice = c == 'v';
                if let Some(target) = resolved.get(ri) {
                    match target {
                        MemberTarget::Local(id) => {
                            if let Some(flags) = chan.members.get_mut(id) {
                                if is_voice {
                                    flags.voice = adding;
                                } else {
                                    flags.op = adding;
                                }
                            }
                        }
                        MemberTarget::Remote(numeric) => {
                            if let Some(flags) = chan.remote_members.get_mut(numeric) {
                                if is_voice {
                                    flags.voice = adding;
                                } else {
                                    flags.op = adding;
                                }
                            }
                        }
                    }
                    ri += 1;
                }
                if params.get(pi).is_some() {
                    pi += 1;
                }
            }
            'b' => {
                if let Some(mask) = params.get(pi) {
                    if adding {
                        chan.bans.push(BanEntry {
                            mask: mask.clone(),
                            set_by: "remote".to_string(),
                            set_at: chrono::Utc::now(),
                        });
                    } else {
                        chan.bans.retain(|b| &b.mask != mask);
                    }
                    pi += 1;
                }
            }
            _ => {
                // unknown mode char — ignore
            }
        }
    }
}

/// Handle K (KICK) from remote.
pub async fn handle_kick(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 2 {
        return;
    }

    let chan_name = &msg.params[0];
    let target_str = &msg.params[1];
    let reason = msg.params.get(2).cloned().unwrap_or_default();

    let source_prefix = get_source_prefix(state, msg).await;

    // The target could be a nick or a numeric
    let target_nick;

    if let Some(numeric) = ClientNumeric::from_str(target_str) {
        // Remote user being kicked
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let mut rc = remote.write().await;
            target_nick = rc.nick.clone();
            rc.channels.remove(chan_name);
        } else {
            return;
        }

        if let Some(channel) = state.get_channel(chan_name) {
            let mut chan = channel.write().await;
            chan.remote_members.remove(&numeric);
        }
    } else {
        // Could be a local user being kicked by remote
        target_nick = target_str.to_string();
        if let Some(client) = state.find_client_by_nick(target_str) {
            let mut c = client.write().await;
            c.channels.remove(chan_name);
            let client_id = c.id;
            drop(c);

            if let Some(channel) = state.get_channel(chan_name) {
                let mut chan = channel.write().await;
                chan.remove_member(&client_id);
            }
        }
    }

    // Notify local channel members
    let kick_msg = irc_proto::Message::with_source(
        &source_prefix,
        irc_proto::Command::Kick,
        vec![chan_name.clone(), target_nick, reason],
    );
    let src = source_info_from_origin(state, msg).await;

    if let Some(channel) = state.get_channel(chan_name) {
        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send_from(kick_msg.clone(), &src);
            }
        }
    }
}

/// Handle T (TOPIC) from remote.
pub async fn handle_topic(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }

    let chan_name = &msg.params[0];
    let source_prefix = get_source_prefix(state, msg).await;

    // TOPIC format varies:
    // <origin> T <channel> <setter> <ts> <ts> :<topic>
    // or simpler: <origin> T <channel> :<topic>
    let topic = msg.params.last().cloned().unwrap_or_default();

    if let Some(channel) = state.get_channel(chan_name) {
        {
            let mut chan = channel.write().await;
            chan.topic = if topic.is_empty() {
                None
            } else {
                Some(topic.clone())
            };
            chan.topic_setter = Some(source_prefix.clone());
            chan.topic_time = Some(chrono::Utc::now());
        }

        // Notify local members
        let topic_msg = irc_proto::Message::with_source(
            &source_prefix,
            irc_proto::Command::Topic,
            vec![chan_name.clone(), topic],
        );
        let src = source_info_from_origin(state, msg).await;

        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send_from(topic_msg.clone(), &src);
            }
        }
    }
}

/// Handle AC (ACCOUNT) from remote — track account state.
pub async fn handle_account(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }

    let target_str = &msg.params[0];

    let numeric = match ClientNumeric::from_str(target_str) {
        Some(n) => n,
        None => return,
    };

    if msg.params.len() < 2 {
        return;
    }

    // Extended accounts: AC <numeric> <type> [<account>] [<timestamp>]
    // Non-extended: AC <numeric> <account> [<timestamp>]
    let account = if msg.params.len() >= 3 {
        match msg.params[1].as_str() {
            "R" | "M" => msg.params.get(2).cloned(),
            "U" => None,
            _ => Some(msg.params[1].clone()), // non-extended format
        }
    } else {
        Some(msg.params[1].clone())
    };

    if let Some(remote) = state.remote_clients.get(&numeric) {
        let (prefix, channels, account_str, src) = {
            let mut rc = remote.write().await;
            rc.account = account.clone();
            debug!("account update for {}: {:?}", rc.nick, rc.account);
            (
                rc.prefix(),
                rc.channels.clone(),
                account.clone().unwrap_or_else(|| "*".to_string()),
                crate::tags::SourceInfo::from_remote(&rc),
            )
        };

        // IRCv3 account-notify: every local user sharing a channel
        // with this remote user and with `account-notify` enabled
        // sees `:X ACCOUNT <account-or-*>`.
        let account_msg = irc_proto::Message::with_source(
            &prefix,
            irc_proto::Command::Account,
            vec![account_str],
        );
        let mut seen = std::collections::HashSet::new();
        for chan_name in &channels {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if !seen.insert(member_id) {
                        continue;
                    }
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        if m.has_cap(crate::capabilities::Capability::AccountNotify) {
                            m.send_from(account_msg.clone(), &src);
                        }
                    }
                }
            }
        }
    }
}

/// Handle DE (DESTRUCT) — channel destruction.
pub async fn handle_destruct(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }

    let chan_name = &msg.params[0];
    // Only remove if truly empty
    if let Some(channel) = state.get_channel(chan_name) {
        let chan = channel.read().await;
        if chan.members.is_empty() && chan.remote_members.is_empty() {
            drop(chan);
            state.channels.remove(&irc_casefold(chan_name));
            debug!("channel {} destroyed", chan_name);
        }
    }
}

/// Helper: get source prefix from a P10 message origin.
async fn get_source_prefix(state: &ServerState, msg: &P10Message) -> String {
    let origin = match &msg.origin {
        Some(o) => o.as_str(),
        None => return state.server_name.clone(),
    };

    if let Some(numeric) = ClientNumeric::from_str(origin) {
        if let Some(remote) = state.remote_clients.get(&numeric) {
            return remote.read().await.prefix();
        }
    }

    if let Some(sn) = ServerNumeric::from_str(origin) {
        if let Some(server) = state.remote_servers.get(&sn) {
            return server.read().await.name.clone();
        }
    }

    origin.to_string()
}

/// Helper: build a SourceInfo from a P10 message's origin for IRCv3
/// tag attachment. A remote-user origin contributes an account; a
/// server origin leaves the account None.
async fn source_info_from_origin(state: &ServerState, msg: &P10Message) -> crate::tags::SourceInfo {
    if let Some(origin) = &msg.origin {
        if let Some(numeric) = ClientNumeric::from_str(origin) {
            if let Some(remote) = state.remote_clients.get(&numeric) {
                return crate::tags::SourceInfo::from_remote(&*remote.read().await);
            }
        }
    }
    crate::tags::SourceInfo::now()
}
