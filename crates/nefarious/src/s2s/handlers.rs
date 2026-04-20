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
    if msg.params.len() < 7 {
        return;
    }

    let name = &msg.params[0];
    let hop_count: u16 = msg.params[1].parse().unwrap_or(1);
    let _zero = &msg.params[2]; // always "0" for burst servers
    let timestamp: u64 = msg.params[3].parse().unwrap_or(0);
    let _protocol = &msg.params[4];
    let numeric_capacity = &msg.params[5];
    let flags_str = msg.params.get(6).map(|s| s.as_str()).unwrap_or("+");
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

    // Numeric is the next field — could be 2 chars (server) + 3 chars (user) = 5 total
    // Or split into separate params: "AB" "AAA"
    let numeric = if msg.params.len() > ip_idx + 2 {
        // Split format: server_yy user_xxx
        let server_str = &msg.params[ip_idx + 1];
        let user_str = &msg.params[ip_idx + 2];
        let combined = format!("{server_str}{user_str}");
        ClientNumeric::from_str(&combined)
    } else {
        // Combined format
        ClientNumeric::from_str(&msg.params[ip_idx + 1])
    };

    let numeric = match numeric {
        Some(n) => n,
        None => {
            warn!("invalid NICK numeric: {:?}", msg.params);
            return;
        }
    };

    let realname = msg.params.last().unwrap().to_string();

    debug!("remote user: {nick} ({numeric}) on server {}", numeric.server);

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

    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    if let Some(remote) = state.remote_clients.get(&numeric) {
        let old_nick = {
            let mut rc = remote.write().await;
            let old = rc.nick.clone();
            rc.nick = new_nick.clone();
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

        for chan_name in &rc.channels {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        m.send(nick_msg.clone());
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

    // If the burst timestamp is older, the bursting server's state wins
    if create_ts > 0 && (chan.created_ts == 0 || create_ts <= chan.created_ts) {
        chan.created_ts = create_ts;
    }

    // Parse remaining params: modes, members, bans
    let mut idx = 2;

    // Parse modes if present
    if idx < msg.params.len() && msg.params[idx].starts_with('+') {
        let mode_str = &msg.params[idx];
        apply_burst_modes(&mut chan, mode_str);
        idx += 1;

        // Mode parameters (key, limit)
        if chan.modes.key.is_some() || chan.modes.limit.is_some() {
            // Key and limit params follow the mode string
            if let Some(ref _key) = chan.modes.key {
                if idx < msg.params.len() && !msg.params[idx].contains(',') && !msg.params[idx].starts_with('%') {
                    chan.modes.key = Some(msg.params[idx].clone());
                    idx += 1;
                }
            }
            if chan.modes.limit.is_some() {
                if idx < msg.params.len() {
                    if let Ok(limit) = msg.params[idx].parse::<u32>() {
                        chan.modes.limit = Some(limit);
                        idx += 1;
                    }
                }
            }
        }
    }

    // Parse members and bans from remaining params
    while idx < msg.params.len() {
        let param = &msg.params[idx];

        if param.starts_with('%') {
            // Ban list — everything from % onwards
            let ban_str = &param[1..];
            for mask in ban_str.split(' ') {
                if !mask.is_empty() {
                    chan.bans.push(BanEntry {
                        mask: mask.to_string(),
                        set_by: "burst".to_string(),
                        set_at: chrono::Utc::now(),
                    });
                }
            }
            // Remaining params after % are also bans
            idx += 1;
            while idx < msg.params.len() {
                for mask in msg.params[idx].split(' ') {
                    if !mask.is_empty() {
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

        // Member list: comma-separated "ABAAB,ABAAC:o,ABAAD:v"
        if param.contains(',') || ClientNumeric::from_str(param.split(':').next().unwrap_or("")).is_some() {
            parse_burst_members(state, &mut chan, param).await;
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

/// Parse burst member list and add to channel.
async fn parse_burst_members(state: &ServerState, chan: &mut Channel, member_str: &str) {
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
        for c in mode_str.chars() {
            match c {
                'o' | '0' => flags.op = true,
                'v' => flags.voice = true,
                _ => {} // oplevel numbers, halfop, etc.
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
    // PING format: <origin> G [:<target>]
    // Response: <our_numeric> Z <target> <origin>
    let origin = msg.origin.as_deref().unwrap_or("");
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    let pong = format!("{} Z {} {}", state.numeric, target, origin);
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

    // Find the remote sender
    let sender_prefix = if let Some(numeric) = ClientNumeric::from_str(origin) {
        if let Some(remote) = state.remote_clients.get(&numeric) {
            remote.read().await.prefix()
        } else {
            return;
        }
    } else {
        // Server origin — use server name
        if let Some(sn) = ServerNumeric::from_str(origin) {
            if let Some(server) = state.remote_servers.get(&sn) {
                server.read().await.name.clone()
            } else {
                origin.to_string()
            }
        } else {
            origin.to_string()
        }
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
                    m.send(irc_msg.clone());
                }
            }
        }
    } else {
        // Private message to a user — could be nick or numeric
        if let Some(client) = state.find_client_by_nick(target) {
            let c = client.read().await;
            c.send(irc_msg);
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
    let prefix = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.insert(chan_name.to_string());
        rc.prefix()
    } else {
        return;
    };

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
            m.send(join_msg.clone());
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

    let prefix = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.insert(chan_name.to_string());
        rc.prefix()
    } else {
        return;
    };

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
            m.send(join_msg.clone());
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

    let prefix = if let Some(remote) = state.remote_clients.get(&numeric) {
        let mut rc = remote.write().await;
        rc.channels.remove(chan_name);
        rc.prefix()
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
                    m.send(part_msg.clone());
                }
            }
        }

        // Remove remote member
        let mut chan = channel.write().await;
        chan.remote_members.remove(&numeric);
    }
}

/// Handle Q (QUIT) or D (KILL) from remote.
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

        // Notify local channel members
        for chan_name in &rc.channels {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        m.send(quit_msg.clone());
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
                m.send(mode_msg.clone());
            }
        }
    }

    // TODO: apply mode changes to channel state (op/voice changes, mode flags)
    // For now we just relay — this means local state might drift, but it's
    // good enough for Phase 1 basic routing.
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

    if let Some(channel) = state.get_channel(chan_name) {
        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send(kick_msg.clone());
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

        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send(topic_msg.clone());
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
        let mut rc = remote.write().await;
        rc.account = account;
        debug!("account update for {}: {:?}", rc.nick, rc.account);
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
