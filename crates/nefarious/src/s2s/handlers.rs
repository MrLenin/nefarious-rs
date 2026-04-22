use std::collections::HashSet;
use std::sync::Arc;

use irc_proto::irc_casefold;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use p10_proto::{ClientNumeric, P10Message, ServerNumeric};

use crate::channel::{BanEntry, Channel, ChannelModes, MembershipFlags};
use crate::s2s::types::{BouncerSession, RemoteClient, RemoteServer, ServerFlags, ServerLink};
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
    let description = msg.params.last().map(|s| s.as_str()).unwrap_or("");

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

    // Modes are the 6th param when present (prefixed with '+'). They're
    // optional — a minimal NICK line has no modes column.
    let modes = if msg.params[5].starts_with('+') {
        msg.params[5][1..].chars().collect::<HashSet<char>>()
    } else {
        HashSet::new()
    };

    // If `+r` (registered / authenticated) is set, the next extension
    // field carries the account name, optionally with a
    // `:<register_ts>[:<flags>]` suffix that we drop. Position is
    // fixed at params[6] when modes are present; matches the field
    // order emitted by nefarious2 m_nick.c when SetAccount is true.
    let account = if modes.contains(&'r') {
        msg.params.get(6).and_then(|s| {
            let core = s.split(':').next().unwrap_or("");
            if core.is_empty() {
                None
            } else {
                Some(core.to_string())
            }
        })
    } else {
        None
    };

    // Resolve the visible host. When `+x` is set nefarious2's display
    // layer (s_user.c hide_hostmask) replaces the real host with one
    // of:
    //   - `<account>.<FEAT_HIDDEN_HOST>`        (style 1, or 3 + account)
    //   - the wire cloakhost                    (style 2 or 3 w/o account)
    //   - the real host                         (style 0)
    // We emulate the most common path: if +x + account + a configured
    // hidden_host_suffix, compute the account form; else if +x + a wire
    // cloakhost, use it; else keep the real host. The cloakhost on the
    // wire sits right after the account field at params[6+1].
    let real_host = host.to_string();
    let visible_host = if modes.contains(&'x') {
        let wire_cloak = msg.params.get(7).cloned();
        if let (Some(acct), Some(suffix)) = (&account, &state.config.general.hidden_host_suffix) {
            format!("{acct}.{suffix}")
        } else if let Some(c) = wire_cloak.filter(|s| !s.is_empty() && s != "_") {
            c
        } else {
            real_host.clone()
        }
    } else {
        real_host.clone()
    };

    // In nefarious2's P10 NICK burst the tail is always:
    //   … <ip_base64> <YYXXX numeric> :<realname>
    // i.e. `parv[parc-2]` is the numeric and `parv[parc-3]` is the
    // IPv4/IPv6 base64 — regardless of how many extension fields (the
    // `account:ts`, spoofhost, second spoofhost, etc.) appear between
    // `host` and the IP. Indexing forward from `host` would have us
    // treat an extension field as the numeric and end up registering
    // every remote user under the first 5 characters of whatever their
    // extension string starts with (a cloaked-host prefix in the common
    // case). Parse from the end instead.
    //
    // See `nefarious2/ircd/m_nick.c:304`:
    //   parv[parc-3] = IP#
    //   parv[parc-2] = YXX, numeric nick
    //   parv[parc-1] = info
    let parc = msg.params.len();
    if parc < 3 {
        warn!("NICK message missing IP/numeric: {:?}", msg.params);
        return;
    }
    let ip_base64 = &msg.params[parc - 3];
    let numeric = match ClientNumeric::from_str(&msg.params[parc - 2]) {
        Some(n) => n,
        None => {
            warn!("invalid NICK numeric: {:?}", msg.params);
            return;
        }
    };
    let realname = msg.params[parc - 1].to_string();

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
        host: visible_host,
        realname,
        ip_base64: ip_base64.to_string(),
        modes,
        account,
        nick_ts,
        channels: HashSet::new(),
        away_message: None,
        privs: HashSet::new(),
        is_alias: false,
        primary: None,
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
                    state.remove_remote_client(numeric).await;
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
                    state.remove_remote_client(numeric).await;
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
        let src = crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg);

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
    let create_ts_raw: u64 = msg.params[1].parse().unwrap_or(0);

    let channel_arc = state.get_or_create_channel(chan_name);
    let mut chan = channel_arc.write().await;

    // Zannel (empty-channel) TS fuzz — mirrors nefarious2/ircd/m_burst.c:252-298.
    //
    // A zannel BURST has only `B <chan> <ts>` with no mode or member
    // params. If the two sides' TSes differ by at most 4s and exactly
    // one side has users, nudge the losing side's TS toward the winner
    // so cycling an empty channel during a netsplit doesn't deop people
    // on reunion. Without this, one `/cycle` during a split is enough
    // to unexpectedly deop everyone.
    let local_ts = chan.created_ts;
    let local_empty = chan.members.is_empty() && chan.remote_members.is_empty();
    let is_zannel_burst = msg.params.len() == 2;

    let create_ts = if local_ts > 0 && is_zannel_burst {
        if create_ts_raw < local_ts && local_ts <= create_ts_raw + 4 && !local_empty {
            // Remote's TS is older (would normally deop our side) but
            // they're zannel and we have users — pretend remote matches
            // us so we don't de-op anyone.
            local_ts
        } else if local_ts < create_ts_raw && create_ts_raw <= local_ts + 4 && local_empty {
            // We're empty and our TS is older — adopt remote's TS so
            // both sides agree on the channel age.
            chan.created_ts = create_ts_raw;
            create_ts_raw
        } else {
            create_ts_raw
        }
    } else {
        create_ts_raw
    };

    // P10 channel-TS collision resolution. The side with the older
    // `created_ts` is authoritative for modes, bans and op status;
    // the newer side resets its modes/bans and de-ops its members
    // (the classic "TS oper burst" behaviour).
    //
    //   remote_wins: burst_ts < local_ts  (or we had no prior state)
    //   local_wins:  burst_ts > local_ts
    //   tie:         burst_ts == local_ts (both >0) — merge both sides
    let remote_wins = create_ts > 0 && (local_ts == 0 || create_ts < local_ts);
    let local_wins = local_ts > 0 && create_ts > local_ts;

    debug!(
        "burst TS: chan={} local_ts={} burst_ts={} remote_wins={} local_wins={} accept_status={}",
        chan_name, local_ts, create_ts, remote_wins, local_wins, !local_wins
    );

    if remote_wins {
        chan.created_ts = create_ts;
        chan.modes = ChannelModes::default();
        chan.bans.clear();
        chan.excepts.clear();

        // Collect which local members had op/halfop/voice before we
        // wipe them — we need their nicks to broadcast MODE -ohv after
        // the state change so clients drop the @ / % / + prefix.
        let mut deop_nicks: Vec<(crate::client::ClientId, bool, bool, bool)> = Vec::new();
        for (&id, m) in &chan.members {
            if m.op || m.halfop || m.voice {
                deop_nicks.push((id, m.op, m.halfop, m.voice));
            }
        }

        for m in chan.members.values_mut() {
            m.op = false;
            m.halfop = false;
            m.voice = false;
            m.oplevel = None;
        }
        for m in chan.remote_members.values_mut() {
            m.op = false;
            m.halfop = false;
            m.voice = false;
            m.oplevel = None;
        }

        // Broadcast MODE -o/-h/-v for every local member we just
        // de-privileged, so IRC clients drop their `@`/`%`/`+`
        // prefixes. Without this the server state and the client's
        // rendered roster diverge — the user appears as op on their
        // client but the server no longer grants them that access.
        // (Mirrors MODEBUF_DEST_CHANNEL | MODE_DEL in m_burst.c:363.)
        if !deop_nicks.is_empty() {
            let src = crate::tags::SourceInfo::now();
            for (id, had_op, had_halfop, had_voice) in &deop_nicks {
                let nick = if let Some(client) = state.clients.get(id) {
                    client.read().await.nick.clone()
                } else {
                    continue;
                };
                let mut flags = String::from("-");
                let mut count = 0;
                if *had_op    { flags.push('o'); count += 1; }
                if *had_halfop { flags.push('h'); count += 1; }
                if *had_voice  { flags.push('v'); count += 1; }
                let mut params = vec![chan_name.clone(), flags];
                for _ in 0..count { params.push(nick.clone()); }
                let mode_msg = irc_proto::Message::with_source(
                    &state.server_name,
                    irc_proto::Command::Mode,
                    params,
                );
                for (&mid, _) in &chan.members {
                    if let Some(member) = state.clients.get(&mid) {
                        let m = member.read().await;
                        m.send_from(mode_msg.clone(), &src);
                    }
                }
            }
        }

        // Topic wipeout — the topic was set under our (now-losing) TS
        // regime, so drop it. Broadcast the empty topic to local
        // members so clients update their UI. (m_burst.c:380-386.)
        if chan.topic.is_some() {
            chan.topic = None;
            chan.topic_setter = None;
            chan.topic_time = None;
            let topic_msg = irc_proto::Message::with_source(
                &state.server_name,
                irc_proto::Command::Topic,
                vec![chan_name.clone(), String::new()],
            );
            let src = crate::tags::SourceInfo::now();
            for (&member_id, _) in &chan.members {
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(topic_msg.clone(), &src);
                }
            }
        }
    }

    // Snapshot which remote members were already present BEFORE the
    // burst touched the roster, so we can distinguish "burst-joined"
    // from "already-joined via a prior CREATE/JOIN". The post-burst
    // MODE emit uses this to avoid re-announcing op/voice for members
    // we already knew about — matches the CHFL_BURST_JOINED /
    // CHFL_BURST_ALREADY_OPPED gating in m_burst.c:700-709.
    let pre_existing: HashSet<ClientNumeric> = chan.remote_members.keys().copied().collect();

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
            // Ban and ban-exception list. The '~' token switches from
            // bans to excepts (nefarious2 FEAT_EXCEPTS); earlier tokens
            // are bans, everything after the '~' is a ban exception.
            let mut in_excepts = false;
            let first_chunk = &param[1..];
            if accept_status {
                absorb_ban_list(&mut chan, first_chunk, &mut in_excepts);
            }
            idx += 1;
            while idx < msg.params.len() {
                if accept_status {
                    absorb_ban_list(&mut chan, &msg.params[idx], &mut in_excepts);
                }
                idx += 1;
            }
            break;
        }

        if param.contains(',')
            || ClientNumeric::from_str(param.split(':').next().unwrap_or("")).is_some()
        {
            parse_burst_members(state, &mut chan, param, accept_status, &pre_existing).await;
        }

        idx += 1;
    }

    debug!(
        "burst: {} - {} remote members, {} bans, {} excepts, modes={}",
        chan_name,
        chan.remote_members.len(),
        chan.bans.len(),
        chan.excepts.len(),
        chan.modes.to_mode_string()
    );
}

/// Absorb a whitespace-delimited chunk of ban/except tokens from a
/// burst `%`-param into the channel. A bare `~` toggles the stream
/// into ban-exception mode for the remainder of the burst (matches
/// nefarious2/ircd/m_burst.c:408-413).
fn absorb_ban_list(chan: &mut Channel, chunk: &str, in_excepts: &mut bool) {
    for token in chunk.split(' ').filter(|s| !s.is_empty()) {
        if token == "~" {
            *in_excepts = true;
            continue;
        }
        let entry = BanEntry {
            mask: token.to_string(),
            set_by: "burst".to_string(),
            set_at: chrono::Utc::now(),
        };
        if *in_excepts {
            chan.excepts.push(entry);
        } else {
            chan.bans.push(entry);
        }
    }
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
/// The P10 wire format for a burst member token is
/// `<numeric>[:<mode-chunk>]`, where the mode chunk is optional and is
/// re-used by every subsequent member in the list until the next
/// chunk appears (per m_burst.c). Supported chunk flags:
///
/// - `o` — chanop (legacy, pre-oplevel; equivalent to `MAXOPLEVEL`)
/// - `h` — halfop
/// - `v` — voice
/// - digits — oplevel (either absolute after a reset, or cumulative
///   delta when only digits follow a prior chanop chunk)
///
/// When `accept_status` is false (local side won the TS race) we
/// discard the status bits and the member joins as a plain
/// participant, but we still track the membership.
///
/// We also emit a synthetic JOIN (CAP-gated into extended-join and
/// plain variants) to every local member so their IRC clients see the
/// remote user appear, plus a synthetic MODE for op/halfop/voice so
/// the prefix renders. For away users, emit a CAP-gated AWAY line so
/// clients with `away-notify` learn the state without a /WHO.
///
/// `pre_existing` is the set of remote-member numerics that were in
/// the channel *before* this burst param — we use it to suppress the
/// post-burst MODE emission for members who were already in the
/// channel as ops/voices via a prior CREATE/JOIN (matches CHFL_BURST_
/// ALREADY_OPPED tracking in m_burst.c:700-709).
async fn parse_burst_members(
    state: &ServerState,
    chan: &mut Channel,
    member_str: &str,
    accept_status: bool,
    pre_existing: &HashSet<ClientNumeric>,
) {
    // Sticky status, updated whenever a member token carries a `:chunk`.
    let mut sticky_op = false;
    let mut sticky_halfop = false;
    let mut sticky_voice = false;
    let mut sticky_oplevel: Option<u16> = None;

    for entry in member_str.split(',') {
        let (numeric_str, mode_str) = match entry.find(':') {
            Some(pos) => (&entry[..pos], &entry[pos + 1..]),
            None => (entry, ""),
        };

        let numeric = match ClientNumeric::from_str(numeric_str) {
            Some(n) => n,
            None => continue,
        };

        // Update sticky status from the chunk, if any.
        if !mode_str.is_empty() && accept_status {
            let mut op = false;
            let mut halfop = false;
            let mut voice = false;
            let mut absolute_oplevel: Option<u16> = None;
            let mut cumulative_delta: u16 = 0;
            let mut saw_digits = false;
            let mut digits_are_absolute = true;

            let mut chars = mode_str.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    'o' => {
                        op = true;
                        // Pre-oplevel 'o' behaves like MAXOPLEVEL.
                        absolute_oplevel = Some(MAX_OPLEVEL);
                    }
                    'h' => {
                        halfop = true;
                        digits_are_absolute = true;
                    }
                    'v' => {
                        voice = true;
                        digits_are_absolute = true;
                    }
                    d if d.is_ascii_digit() => {
                        // Multi-digit number; consume subsequent digits.
                        let mut n: u32 = (d as u32) - ('0' as u32);
                        while let Some(&next) = chars.peek() {
                            if let Some(val) = next.to_digit(10) {
                                n = n.saturating_mul(10).saturating_add(val);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        let n = n.min(MAX_OPLEVEL as u32) as u16;
                        op = true;
                        saw_digits = true;
                        if digits_are_absolute {
                            absolute_oplevel = Some(n);
                            digits_are_absolute = false;
                        } else {
                            cumulative_delta = cumulative_delta.saturating_add(n);
                        }
                    }
                    _ => {
                        // Unknown flag — tolerate & ignore.
                    }
                }
            }

            // Resolve the level: absolute if we saw one (fresh 'o' or
            // first digit-run), otherwise previous sticky level plus
            // cumulative delta.
            let resolved_level = if let Some(abs) = absolute_oplevel {
                Some(abs.saturating_add(cumulative_delta).min(MAX_OPLEVEL))
            } else if saw_digits {
                sticky_oplevel
                    .map(|prev| prev.saturating_add(cumulative_delta).min(MAX_OPLEVEL))
                    .or(Some(cumulative_delta.min(MAX_OPLEVEL)))
            } else {
                None
            };

            sticky_op = op;
            sticky_halfop = halfop;
            sticky_voice = voice;
            if let Some(lvl) = resolved_level {
                sticky_oplevel = Some(lvl);
            } else if !op {
                sticky_oplevel = None;
            }
        }

        let flags = if accept_status {
            MembershipFlags {
                op: sticky_op,
                halfop: sticky_halfop,
                voice: sticky_voice,
                oplevel: if sticky_op { sticky_oplevel } else { None },
            }
        } else {
            MembershipFlags::default()
        };

        let was_pre_existing = pre_existing.contains(&numeric);
        let prior_had_op = was_pre_existing
            && chan
                .remote_members
                .get(&numeric)
                .is_some_and(|f| f.op);
        let prior_had_halfop = was_pre_existing
            && chan
                .remote_members
                .get(&numeric)
                .is_some_and(|f| f.halfop);
        let prior_had_voice = was_pre_existing
            && chan
                .remote_members
                .get(&numeric)
                .is_some_and(|f| f.voice);

        let is_op = flags.op;
        let is_halfop = flags.halfop;
        let is_voice = flags.voice;

        let mode_label = if mode_str.is_empty() { "(sticky)".to_string() } else { mode_str.to_string() };
        debug!(
            "burst member {numeric}: sticky_op={sticky_op} sticky_halfop={sticky_halfop} sticky_voice={sticky_voice} \
             accept_status={accept_status} is_op={is_op} was_pre_existing={was_pre_existing} \
             prior_had_op={prior_had_op} mode_chunk={mode_label}"
        );

        chan.remote_members.insert(numeric, flags);

        // Track channel on the remote client and capture what we need
        // to broadcast the synthetic JOIN/AWAY without holding the
        // remote's write lock while awaiting on per-recipient sends.
        let Some(remote_arc) = state.remote_clients.get(&numeric) else {
            // Expected state for bouncer aliases that we haven't been
            // introduced to via BX C yet (or for the stale-alias path
            // where nefarious2's bounce_burst omits the BX C on relink).
            // Keep the membership in chan.remote_members — MODE/KICK/PART
            // for that numeric remain addressable — but skip the
            // synthetic JOIN/MODE emit since we have no visible identity
            // to attach.
            debug!(
                "burst member {numeric}: no RemoteClient — assuming alias; skipping JOIN/MODE emit"
            );
            continue;
        };
        // Burst-synth JOIN uses a fresh SourceInfo — no single inbound
        // message maps to it (we synthesize one JOIN per member of the
        // bursted channel list).
        let (prefix, src, account, realname, away_message) = {
            let mut rc = remote_arc.write().await;
            rc.channels.insert(chan.name.clone());
            (
                rc.prefix(),
                crate::tags::SourceInfo::from_remote(&rc),
                rc.account.clone(),
                rc.realname.clone(),
                rc.away_message.clone(),
            )
        };
        drop(remote_arc);

        // Only emit the synthetic JOIN for members who weren't already
        // in the channel via a prior CREATE/JOIN. Re-announcing JOIN
        // for a known member would confuse clients into tracking a
        // second entry.
        if !was_pre_existing {
            let plain_join = irc_proto::Message::with_source(
                &prefix,
                irc_proto::Command::Join,
                vec![chan.name.clone()],
            );
            let ext_account = account.as_deref().unwrap_or("*").to_string();
            let extended_join = irc_proto::Message::with_source(
                &prefix,
                irc_proto::Command::Join,
                vec![chan.name.clone(), ext_account, realname.clone()],
            );
            for (&member_id, _) in &chan.members {
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    let msg =
                        if m.has_cap(crate::capabilities::Capability::ExtendedJoin) {
                            extended_join.clone()
                        } else {
                            plain_join.clone()
                        };
                    m.send_from(msg, &src);
                }
            }

            // AWAY-notify emission for clients with the `away-notify`
            // cap. `away_message` is None for users who aren't away;
            // the emit becomes live once a future P10 AWAY token
            // handler starts populating this field.
            if let Some(away) = &away_message {
                let away_msg = irc_proto::Message::with_source(
                    &prefix,
                    irc_proto::Command::Away,
                    vec![away.clone()],
                );
                for (&member_id, _) in &chan.members {
                    if let Some(member) = state.clients.get(&member_id) {
                        let m = member.read().await;
                        if m.has_cap(crate::capabilities::Capability::AwayNotify) {
                            m.send_from(away_msg.clone(), &src);
                        }
                    }
                }
            }
        }

        // Post-burst synthetic MODE: announce op/halfop/voice that
        // we didn't already know about. For pre-existing members we
        // only emit deltas (new bits we didn't have before) — for
        // fresh burst-joined members we emit whatever bits they have.
        let gained_op = is_op && !prior_had_op;
        let gained_halfop = is_halfop && !prior_had_halfop;
        let gained_voice = is_voice && !prior_had_voice;

        if gained_op || gained_halfop || gained_voice {
            let remote_nick = {
                if let Some(remote) = state.remote_clients.get(&numeric) {
                    remote.read().await.nick.clone()
                } else {
                    continue;
                }
            };
            let mut mode_flags = String::from("+");
            let mut applied = 0;
            if gained_op {
                mode_flags.push('o');
                applied += 1;
            }
            if gained_halfop {
                mode_flags.push('h');
                applied += 1;
            }
            if gained_voice {
                mode_flags.push('v');
                applied += 1;
            }
            let mut mode_params = vec![chan.name.clone(), mode_flags];
            for _ in 0..applied {
                mode_params.push(remote_nick.clone());
            }
            let mode_msg = irc_proto::Message::with_source(
                &state.server_name,
                irc_proto::Command::Mode,
                mode_params,
            );
            let mode_src = crate::tags::SourceInfo::now();
            for (&member_id, _) in &chan.members {
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(mode_msg.clone(), &mode_src);
                }
            }
        }
    }
}

/// P10 MAXOPLEVEL — the ceiling for cumulative oplevels during burst.
/// Matches `MAXOPLEVEL` in nefarious2/include/channel.h (999 for the
/// current tree; the cap is "everyone can deop me" semantics).
const MAX_OPLEVEL: u16 = 999;

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
    // Reuse the inbound msgid/time tags if the peer attached them,
    // so our local clients see the *same* @msgid the originating
    // server put on the wire — preserves network-wide id consistency.
    let (sender_prefix, src) = if let Some(numeric) = ClientNumeric::from_str(origin) {
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let rc = remote.read().await;
            (
                rc.prefix(),
                crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg).with_inbound_tags(msg),
            )
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

    if target.starts_with('#') || target.starts_with('&') {
        // Channel message — target is a channel name, safe to use verbatim.
        let irc_msg = irc_proto::Message::with_source(
            &sender_prefix,
            command,
            vec![target.clone(), text.clone()],
        );
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
        // Private message. P10 allows numeric targets; resolve to the
        // recipient's actual nick so clients don't see a raw numeric.
        // Only consult our slot table when the numeric's server field
        // is our own — otherwise we'd happily resolve a remote user's
        // numeric to an unrelated local client sharing the client slot.
        let (recipient_nick, client_arc) =
            if let Some(id) = ClientNumeric::from_str(target)
                .filter(|num| num.server == state.numeric)
                .and_then(|num| state.client_by_numeric_slot(num.client))
            {
                if let Some(arc) = state.clients.get(&id) {
                    let nick = arc.read().await.nick.clone();
                    (nick, Some(arc.clone()))
                } else {
                    return;
                }
            } else if let Some(arc) = state.find_client_by_nick(target) {
                let nick = arc.read().await.nick.clone();
                (nick, Some(arc))
            } else {
                return;
            };

        if let Some(arc) = client_arc {
            let irc_msg = irc_proto::Message::with_source(
                &sender_prefix,
                command,
                vec![recipient_nick, text.clone()],
            );
            arc.read().await.send_from(irc_msg, &src);
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
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg))
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
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg))
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
        (rc.prefix(), crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg))
    } else {
        return;
    };

    // When a remote user is kicked (whether by a local or remote op),
    // nefarious2's make_zombie path can echo an L (PART) back to every
    // server that saw the KICK (channel.c:2244-). Re-broadcasting that
    // PART to local clients produces a phantom "has left" right after
    // the KICK event. Suppress the broadcast when the user has already
    // been removed from chan.remote_members — either our handle_kick or
    // the local kick handler got there first. Use the result of remove()
    // as the authoritative "were they still a member?" check.
    let part_msg = {
        let Some(channel) = state.get_channel(chan_name) else {
            warn!("handle_part: channel {chan_name} not found for PART from {numeric}");
            return;
        };
        let was_member = {
            let mut chan = channel.write().await;
            chan.remote_members.remove(&numeric).is_some()
        };
        if !was_member {
            debug!(
                "handle_part: suppressing phantom PART for {numeric} on {chan_name} \
                 (already removed — probably a KICK acknowledgment)"
            );
            state.reap_channel_if_empty(chan_name).await;
            return;
        }

        debug!("handle_part: relaying PART for {numeric} on {chan_name}");
        let mut part_params = vec![chan_name.clone()];
        if !reason.is_empty() {
            part_params.push(reason);
        }
        irc_proto::Message::with_source(&prefix, irc_proto::Command::Part, part_params)
    };

    if let Some(channel) = state.get_channel(chan_name) {
        let chan = channel.read().await;
        for (&member_id, _) in &chan.members {
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                m.send_from(part_msg.clone(), &src);
            }
        }
    }
    state.reap_channel_if_empty(chan_name).await;
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
            let src = crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg);
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
        let src = crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg);

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
        // User-mode change — apply to the remote user's flag set so
        // WHOIS, USERHOST and friends reflect the right state. No
        // broadcast to local clients: per RFC, user modes are visible
        // to the user themselves (and to opers via WHOIS), not fanned
        // out to channel peers.
        handle_remote_user_mode(state, msg).await;
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

    // Build a client-facing params list: P10 MODE targets are numerics on
    // the wire; IRC clients expect nicks. Resolve each numeric param that
    // corresponds to an o/v/h/b/k/l flag, leaving non-target params as-is.
    let client_params = if msg.params.len() >= 2 {
        let mode_str = &msg.params[1];
        let mut out = vec![target.clone(), mode_str.clone()];
        let mut pi = 2usize;
        let mut adding = true;
        for c in mode_str.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                'o' | 'v' | 'h' => {
                    if let Some(param) = msg.params.get(pi) {
                        // Resolve numeric → nick; pass through if already a nick.
                        // Only fall through to the local slot table when the
                        // numeric's server field matches ours — otherwise a
                        // remote numeric would collide with an unrelated local
                        // slot and we'd render a wrong nick.
                        let resolved = if let Some(num) = ClientNumeric::from_str(param) {
                            if let Some(remote) = state.remote_clients.get(&num) {
                                remote.read().await.nick.clone()
                            } else if num.server == state.numeric {
                                if let Some(id) = state.client_by_numeric_slot(num.client) {
                                    if let Some(local) = state.clients.get(&id) {
                                        local.read().await.nick.clone()
                                    } else {
                                        param.clone()
                                    }
                                } else {
                                    param.clone()
                                }
                            } else {
                                param.clone()
                            }
                        } else {
                            param.clone()
                        };
                        out.push(resolved);
                        pi += 1;
                    }
                }
                'k' => {
                    if let Some(p) = msg.params.get(pi) { out.push(p.clone()); pi += 1; }
                }
                'b' => {
                    if let Some(p) = msg.params.get(pi) { out.push(p.clone()); pi += 1; }
                }
                'l' => {
                    if adding {
                        if let Some(p) = msg.params.get(pi) { out.push(p.clone()); pi += 1; }
                    }
                }
                _ => {}
            }
        }
        out
    } else {
        msg.params.clone()
    };

    // Relay the MODE message to local channel members
    if let Some(channel) = state.get_channel(target) {
        let mode_msg = irc_proto::Message::with_source(
            &source_prefix,
            irc_proto::Command::Mode,
            client_params,
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
/// Per P10, op/voice/halfop targets arrive on the wire as 5-char YYXXX
/// numerics (not nicks). Resolve the numeric against remote_clients
/// first, then — if `num.server` is ours — against our client-slot map.
/// The nick fallback is only there to tolerate a malformed peer; the
/// normal path is numeric. Unknown targets are silently dropped (the
/// network will resync on the next burst).
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

    // Resolve op/voice/halfop targets to (Local(id) | Remote(numeric))
    // BEFORE taking the channel write lock, so we never block the
    // channel while awaiting a Client read lock elsewhere.
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
            'o' | 'v' | 'h' => {
                if let Some(tok) = params.get(pi) {
                    let mut target: Option<MemberTarget> = None;
                    if let Some(num) = ClientNumeric::from_str(tok) {
                        if state.remote_clients.contains_key(&num) {
                            target = Some(MemberTarget::Remote(num));
                        } else if num.server == state.numeric {
                            if let Some(id) = state.client_by_numeric_slot(num.client) {
                                target = Some(MemberTarget::Local(id));
                            }
                        }
                    }
                    if target.is_none() {
                        if let Some(client) = state.find_client_by_nick(tok) {
                            let id = client.read().await.id;
                            target = Some(MemberTarget::Local(id));
                        } else if let Some(remote) = state.find_remote_by_nick(tok) {
                            let numeric = remote.read().await.numeric;
                            target = Some(MemberTarget::Remote(numeric));
                        }
                    }
                    if let Some(t) = target {
                        resolved.push(t);
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
            'o' | 'v' | 'h' => {
                if let Some(target) = resolved.get(ri) {
                    let apply = |flags: &mut MembershipFlags| match c {
                        'o' => flags.op = adding,
                        'v' => flags.voice = adding,
                        'h' => flags.halfop = adding,
                        _ => {}
                    };
                    match target {
                        MemberTarget::Local(id) => {
                            if let Some(flags) = chan.members.get_mut(id) {
                                apply(flags);
                            }
                        }
                        MemberTarget::Remote(numeric) => {
                            if let Some(flags) = chan.remote_members.get_mut(numeric) {
                                apply(flags);
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

    // The target can arrive on the wire as either a 5-char P10 numeric
    // or a nick. `ClientNumeric::from_str` happily accepts any nick
    // ≥5 chars whose first two bytes are in the base64 alphabet, so
    // don't rely on the parse alone. Dispatch in order:
    //   1. parsed numeric belongs to a remote user we know   (common)
    //   2. parsed numeric belongs to us (server == our own
    //      numeric, slot resolves in `client_numerics`)       (our user)
    //   3. raw string resolves as a local nick                (legacy)
    //   4. no match — warn and pass through the raw string
    // Cases 2 and 3 both cover "remote op kicked one of our users",
    // which is why the target needs to render as *our user's nick*
    // on the wire broadcast — otherwise channel members see the kick
    // directed at a raw numeric like "BiAAB" instead of "ibutsu__".
    // Resolve the target's display nick AND classify the removal we need
    // to perform after the wire broadcast. The broadcast must happen
    // *before* the removal so the kicked local user still receives
    // their own KICK line (the local handler in handlers/channel.rs
    // applies the same ordering).
    let parsed_numeric = ClientNumeric::from_str(target_str);
    let target_nick;
    enum KickTarget {
        RemoteNumeric(ClientNumeric),
        LocalClient(crate::client::ClientId),
        Unknown,
    }
    let removal: KickTarget;

    if let Some(numeric) = parsed_numeric.filter(|n| state.remote_clients.contains_key(n)) {
        // Case 1: remote user being kicked. Their channels set is
        // maintained here — safe to clear now, since remote clients
        // aren't in chan.members (the broadcast target iter).
        if let Some(remote) = state.remote_clients.get(&numeric) {
            let mut rc = remote.write().await;
            target_nick = rc.nick.clone();
            rc.channels.remove(chan_name);
        } else {
            target_nick = target_str.to_string();
        }
        removal = KickTarget::RemoteNumeric(numeric);
    } else if let Some(client_id) = parsed_numeric
        .filter(|n| n.server == state.numeric)
        .and_then(|n| state.client_by_numeric_slot(n.client))
    {
        // Case 2: remote operator kicking one of our users by numeric.
        let nick = if let Some(client) = state.clients.get(&client_id) {
            client.read().await.nick.clone()
        } else {
            target_str.to_string()
        };
        target_nick = nick;
        removal = KickTarget::LocalClient(client_id);
    } else if let Some(client) = state.find_client_by_nick(target_str) {
        // Case 3: target came through as a nick (legacy) for a local
        // user.
        target_nick = target_str.to_string();
        let client_id = client.read().await.id;
        removal = KickTarget::LocalClient(client_id);
    } else {
        // Case 4: unknown target. Still broadcast so members see the
        // wire event; upstream is presumably authoritative.
        target_nick = target_str.to_string();
        removal = KickTarget::Unknown;
        warn!(
            "K from {source_prefix} for {chan_name}: target {target_str} is neither a known remote numeric nor a local user"
        );
    }

    // Broadcast the KICK to every current channel member (including
    // the kicked local user, who is still in chan.members at this
    // point) so every client sees the kick event.
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

    // Now apply the state removal.
    match removal {
        KickTarget::RemoteNumeric(numeric) => {
            if let Some(channel) = state.get_channel(chan_name) {
                let mut chan = channel.write().await;
                chan.remote_members.remove(&numeric);
            }
            state.reap_channel_if_empty(chan_name).await;
        }
        KickTarget::LocalClient(client_id) => {
            if let Some(channel) = state.get_channel(chan_name) {
                let mut chan = channel.write().await;
                chan.remove_member(&client_id);
            }
            if let Some(client) = state.clients.get(&client_id) {
                let mut c = client.write().await;
                c.channels.remove(chan_name);
            }
        }
        KickTarget::Unknown => {}
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
                crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg),
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

/// Apply a remote user-mode change (`<user> M <nick> <modestring>`)
/// to the relevant RemoteClient. Purely internal state — we don't fan
/// out to local clients because user modes aren't broadcastable.
async fn handle_remote_user_mode(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 2 {
        return;
    }
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };
    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };
    let mode_str = &msg.params[1];

    let Some(remote) = state.remote_clients.get(&numeric) else {
        return;
    };
    let mut rc = remote.write().await;
    let mut adding = true;
    for c in mode_str.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            // Recognised umode flags — matches what the C side propagates.
            // The full set is broader (x, n, g, h, k, R, I, etc.); we
            // track what we actually store on RemoteClient.
            flag if flag.is_alphabetic() => {
                if adding {
                    rc.modes.insert(flag);
                } else {
                    rc.modes.remove(&flag);
                }
            }
            _ => {}
        }
    }
    debug!("remote user mode: {numeric} now {:?}", rc.modes);
}

/// Handle PRIVS from a remote server — record oper privileges on
/// the named user. Nefarious2 can split large priv sets across
/// multiple PRIVS lines, each for the same user; we merge into the
/// user's `privs` set rather than replacing it so the full set is
/// captured regardless of how it's split. An empty PRIVS line
/// (target only, no privs) is tolerated and just no-ops.
///
/// Wire: `<server> PRIVS <user_numeric> <priv1> <priv2> ...`.
pub async fn handle_privs(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }
    let Some(numeric) = ClientNumeric::from_str(&msg.params[0]) else {
        return;
    };
    if msg.params.len() < 2 {
        return;
    }

    let Some(remote) = state.remote_clients.get(&numeric) else {
        return;
    };
    let mut rc = remote.write().await;
    for tok in &msg.params[1..] {
        // A single param can carry multiple whitespace-separated privs
        // (nefarious2 packs them into one trailing arg when they fit).
        for p in tok.split_whitespace() {
            if !p.is_empty() {
                rc.privs.insert(p.to_uppercase());
            }
        }
    }
    debug!("PRIVS: {numeric} now has {} privs", rc.privs.len());
}

/// Handle SR (SETNAME) from a remote user.
///
/// Wire: `<user> SR :<realname>`. Update the remote_client realname
/// and fan `:prefix SETNAME :<realname>` out to every local user
/// sharing a channel with them who has the `setname` cap.
pub async fn handle_setname(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };
    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };
    let new_realname = msg.params[0].clone();

    let Some(remote) = state.remote_clients.get(&numeric) else {
        return;
    };
    let (prefix, channels, src) = {
        let mut rc = remote.write().await;
        rc.realname = new_realname.clone();
        (
            rc.prefix(),
            rc.channels.clone(),
            crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg),
        )
    };
    drop(remote);

    let setname_msg = irc_proto::Message::with_source(
        &prefix,
        irc_proto::Command::Setname,
        vec![new_realname],
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
                    if m.has_cap(crate::capabilities::Capability::Setname) {
                        m.send_from(setname_msg.clone(), &src);
                    }
                }
            }
        }
    }
}

/// Handle A (AWAY) from a remote user.
///
/// Wire: `<user> A [:<msg>]`. Trailing param present means "set away
/// with this message"; absent means "clear away". Updates the remote
/// client's `away_message` and fans an AWAY line out to every local
/// user sharing a channel with them who has `away-notify` enabled.
pub async fn handle_away(state: &ServerState, msg: &P10Message) {
    let origin = match &msg.origin {
        Some(o) => o,
        None => return,
    };
    let numeric = match ClientNumeric::from_str(origin) {
        Some(n) => n,
        None => return,
    };

    let new_state = msg.params.first().cloned().filter(|s| !s.is_empty());

    let Some(remote) = state.remote_clients.get(&numeric) else {
        return;
    };
    let (prefix, channels, src) = {
        let mut rc = remote.write().await;
        rc.away_message = new_state.clone();
        (
            rc.prefix(),
            rc.channels.clone(),
            crate::tags::SourceInfo::from_remote(&rc).with_inbound_tags(msg),
        )
    };
    drop(remote);

    let away_params = match &new_state {
        Some(m) => vec![m.clone()],
        None => Vec::new(),
    };
    let away_msg =
        irc_proto::Message::with_source(&prefix, irc_proto::Command::Away, away_params);

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
                    if m.has_cap(crate::capabilities::Capability::AwayNotify) {
                        m.send_from(away_msg.clone(), &src);
                    }
                }
            }
        }
    }
}

/// Handle I (INVITE) from a remote user.
///
/// Wire: `<inviter_numeric> I <target_numeric_or_nick> <channel> [<ts>]`.
/// Per nefarious2 m_invite.c: deliver the INVITE directly to the target
/// if we host them, and fan invite-notify out to every channel op on
/// our side with the cap enabled. Both fan-outs are independent — a
/// remote-target INVITE still wants the local ops notified so their
/// clients render the event.
pub async fn handle_invite(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 2 {
        return;
    }
    let target_str = &msg.params[0];
    let chan_name = &msg.params[1];

    // Optional trailing channel-creation TS. Per nefarious2 m_invite.c
    // 309-312, silently discard the invite if invite_ts > our
    // chan.created_ts — that means the sender's view of the channel
    // is newer than ours (e.g. they recreated it) and their invite
    // targets a channel that effectively no longer exists on this side.
    if let Some(ts_str) = msg.params.get(2) {
        if let Ok(invite_ts) = ts_str.parse::<u64>() {
            if let Some(channel) = state.get_channel(chan_name) {
                let chan = channel.read().await;
                if invite_ts > chan.created_ts {
                    debug!(
                        "handle_invite: dropping stale invite to {chan_name} \
                         (invite_ts={invite_ts} > chan.created_ts={})",
                        chan.created_ts
                    );
                    return;
                }
            }
        }
    }

    let source_prefix = get_source_prefix(state, msg).await;
    let src = source_info_from_origin(state, msg).await;

    // Resolve the target to (display_nick, Option<ClientId>). A local
    // client is represented by its ClientId; a remote target (or a
    // target we can't resolve) leaves that slot None. The display nick
    // is what we render on the wire: we prefer the resolved nick from
    // the client/remote record so numeric-form targets don't leak into
    // local clients' view.
    let (target_nick, local_target_id): (String, Option<crate::client::ClientId>) = {
        // Local numeric path first.
        let parsed = ClientNumeric::from_str(target_str);
        if let Some(id) = parsed
            .filter(|n| n.server == state.numeric)
            .and_then(|n| state.client_by_numeric_slot(n.client))
        {
            let nick = state
                .clients
                .get(&id)
                .map(|c| c.value().clone());
            if let Some(arc) = nick {
                let n = arc.read().await.nick.clone();
                (n, Some(id))
            } else {
                (target_str.to_string(), None)
            }
        } else if let Some(num) = parsed {
            // Remote numeric — resolve to nick for display only.
            if let Some(remote) = state.remote_clients.get(&num) {
                (remote.read().await.nick.clone(), None)
            } else {
                (target_str.to_string(), None)
            }
        } else if let Some(arc) = state.find_client_by_nick(target_str) {
            let (n, id) = {
                let c = arc.read().await;
                (c.nick.clone(), c.id)
            };
            (n, Some(id))
        } else {
            (target_str.to_string(), None)
        }
    };

    let invite_msg = irc_proto::Message::with_source(
        &source_prefix,
        irc_proto::Command::Invite,
        vec![target_nick.clone(), chan_name.clone()],
    );

    // Direct delivery + invite-bypass tracking, but only when the
    // target is one of ours. Without the chan.invites insert, a remote
    // op's invite would be cosmetic only — JOIN still rejects on +i.
    if let Some(target_id) = local_target_id {
        if let Some(target_arc) = state.clients.get(&target_id) {
            target_arc.read().await.send_from(invite_msg.clone(), &src);
        }
        if let Some(channel) = state.get_channel(chan_name) {
            let mut chan = channel.write().await;
            chan.invites.insert(target_id);
        }
    }

    // IRCv3 invite-notify: fan to every op on the channel with the
    // cap, regardless of whether the target is local. Skip the target
    // on the local path (they received it directly above); the inviter
    // is remote so there's nothing local to skip for them.
    if let Some(channel) = state.get_channel(chan_name) {
        let chan = channel.read().await;
        for (&member_id, flags) in &chan.members {
            if !flags.op {
                continue;
            }
            if Some(member_id) == local_target_id {
                continue;
            }
            if let Some(member) = state.clients.get(&member_id) {
                let m = member.read().await;
                if m.has_cap(crate::capabilities::Capability::InviteNotify) {
                    m.send_from(invite_msg.clone(), &src);
                }
            }
        }
    }
}

/// Handle W (WHOIS) from a remote user targeting one of our users.
///
/// Wire per nefarious2 m_whois.c:550 — `<requester> W [<target_server>]
/// :<nick_masklist>`. When the target server is specified (parc > 2
/// after origin), it's the server we're being asked to answer on
/// behalf of — we only respond if it resolves to us or a user on
/// us. The nick list is comma-separated; we handle it generically
/// even though clients usually ask about one nick.
///
/// Responses are server-originated numerics routed back to the
/// requester via their P10 numeric. Wire form:
///   `<our_server> <NNN> <requester_numeric> <params> :<trailing>`
///
/// Emits the same numerics the local /WHOIS handler does — 311
/// (user), 301 (away), 312 (server), 313 (oper), 319 (channels),
/// 330 (account), 318 (end).
pub async fn handle_whois(state: &ServerState, msg: &P10Message) {
    let Some(ref origin) = msg.origin else { return };
    let Some(requester) = ClientNumeric::from_str(origin) else {
        return;
    };
    if msg.params.is_empty() {
        return;
    }

    // With >1 param the first is a target server/nick mask we're
    // being routed to answer for; the last is always the nick list.
    // We accept any target and just answer the last param — hop
    // routing in a multi-server network would need hunt_server_cmd
    // logic, but a single-uplink deployment can treat "we got it"
    // as "it's for us".
    let nick_list = msg.params.last().unwrap().clone();
    let our = state.numeric.to_string();
    let req_str = requester.to_string();

    // Is the remote requester an oper? Skip HIS_* hiding in that
    // case. Self-WHOIS over S2S can't happen (requester must be on
    // another server), so the "target == requester" branch doesn't
    // apply here.
    let requester_is_oper = if let Some(rc) = state.remote_clients.get(&requester) {
        rc.read().await.modes.contains(&'o')
    } else {
        false
    };

    let mut responded_any = false;

    for nick in nick_list.split(',').filter(|n| !n.is_empty()) {
        if let Some(target) = state.find_client_by_nick(nick) {
            let t = target.read().await;
            responded_any = true;

            let host = if requester_is_oper {
                t.host.clone()
            } else {
                t.visible_host(&state.config)
            };

            // 311 RPL_WHOISUSER — <nick> <user> <host> * :<realname>
            send_whois_numeric(
                state,
                &our,
                &req_str,
                311,
                &[&t.nick, &t.user, &host, "*", &t.realname],
            )
            .await;

            // 301 RPL_AWAY if away
            if let Some(ref away) = t.away_message {
                send_whois_numeric(state, &our, &req_str, 301, &[&t.nick, away]).await;
            }

            // 312 RPL_WHOISSERVER — <nick> <server> :<server_info>
            let (srv_name, srv_desc) = if requester_is_oper {
                (state.server_name.as_str(), state.server_description.as_str())
            } else {
                (
                    state.config.his_servername().unwrap_or(&state.server_name),
                    state.config.his_serverinfo().unwrap_or(&state.server_description),
                )
            };
            send_whois_numeric(
                state,
                &our,
                &req_str,
                312,
                &[&t.nick, srv_name, srv_desc],
            )
            .await;

            // 313 RPL_WHOISOPERATOR if +o
            if t.modes.contains(&'o') {
                send_whois_numeric(
                    state,
                    &our,
                    &req_str,
                    313,
                    &[&t.nick, "is an IRC operator"],
                )
                .await;
            }

            // 330 RPL_WHOISACCOUNT if logged in
            if let Some(ref account) = t.account {
                send_whois_numeric(
                    state,
                    &our,
                    &req_str,
                    330,
                    &[&t.nick, account, "is logged in as"],
                )
                .await;
            }

            // 319 RPL_WHOISCHANNELS (prefixes + list)
            if !t.channels.is_empty() {
                let mut chan_list = Vec::new();
                for chan_name in &t.channels {
                    if let Some(channel) = state.get_channel(chan_name) {
                        let chan = channel.read().await;
                        // Secret/private channels are only visible
                        // to members. The requester here is remote —
                        // consult chan.remote_members.
                        let hidden = chan.modes.secret || chan.modes.private;
                        let requester_on = chan.remote_members.contains_key(&requester);
                        if hidden && !requester_on {
                            continue;
                        }
                        if let Some(flags) = chan.members.get(&t.id) {
                            chan_list.push(format!(
                                "{}{}",
                                flags.highest_prefix(),
                                chan_name
                            ));
                        }
                    }
                }
                if !chan_list.is_empty() {
                    send_whois_numeric(
                        state,
                        &our,
                        &req_str,
                        319,
                        &[&t.nick, &chan_list.join(" ")],
                    )
                    .await;
                }
            }

            // 317 RPL_WHOISIDLE — idle seconds, signon time
            let idle_secs = (chrono::Utc::now() - t.last_active).num_seconds().max(0);
            send_whois_numeric(
                state,
                &our,
                &req_str,
                317,
                &[
                    &t.nick,
                    &idle_secs.to_string(),
                    &t.connected_at.timestamp().to_string(),
                    "seconds idle, signon time",
                ],
            )
            .await;
        } else {
            // 401 ERR_NOSUCHNICK
            send_whois_numeric(state, &our, &req_str, 401, &[nick, "No such nick"]).await;
        }
    }

    // 318 RPL_ENDOFWHOIS
    let _ = responded_any;
    send_whois_numeric(
        state,
        &our,
        &req_str,
        318,
        &[&nick_list, "End of /WHOIS list"],
    )
    .await;
}

/// Emit a server-originated numeric over S2S targeting a remote
/// client. Wire form: `<our_server> <NNN> <target> <params...>`.
/// The last param is trailing-colon-prefixed if it contains spaces.
async fn send_whois_numeric(
    state: &ServerState,
    our_server: &str,
    target_numeric: &str,
    code: u16,
    params: &[&str],
) {
    let Some(link) = state.get_link() else { return };
    let mut line = format!("{our_server} {code:03} {target_numeric}");
    for (i, p) in params.iter().enumerate() {
        let last = i == params.len() - 1;
        if last && (p.contains(' ') || p.is_empty() || p.starts_with(':')) {
            line.push(' ');
            line.push(':');
            line.push_str(p);
        } else {
            line.push(' ');
            line.push_str(p);
        }
    }
    link.send_line(line).await;
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

/// Handle BS (BOUNCER_SESSION) from a remote server.
///
/// Wire: `<origin> BS <subcmd> <account> <sessid> [params…]`. Baseline
/// scope tracks only enough to interpret BX P (numeric-swap promote):
///
/// - `C` — Create. Records the (account, sessid) entry; primary is
///   left None until a subsequent BS A attaches a numeric.
/// - `A` — Attach. The 5th param is a 3-char `XXX` client numeric,
///   meant to be combined with the session's origin server (2-char
///   `YY`) to form a full `YYXXX`. We use the message origin's server
///   portion as that YY.
/// - `D` — Detach. Clears the primary pointer (session enters holding
///   state on the authoritative side; we only need to forget the
///   numeric).
/// - `X` — Destroy. Removes the session entry entirely.
/// - Other subcommands (`U`, `T`, …) are accepted silently; baseline
///   behaviour doesn't depend on them.
pub async fn handle_bouncer_session(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 3 {
        return;
    }
    let subcmd = match msg.params[0].chars().next() {
        Some(c) => c,
        None => return,
    };
    let account = msg.params[1].clone();
    let sessid = msg.params[2].clone();
    let key = (account.clone(), sessid.clone());

    match subcmd {
        'C' => {
            state
                .bouncer_sessions
                .entry(key)
                .or_insert(BouncerSession {
                    account,
                    sessid,
                    primary: None,
                });
            debug!("BS C: registered bouncer session");
        }
        'A' => {
            let Some(xxx) = msg.params.get(3) else {
                return;
            };
            // The XXX attaches to the session's server-of-origin YY. The
            // P10 line's origin is that server's numeric; combine and
            // parse as a full ClientNumeric.
            let origin = msg.origin.as_deref().unwrap_or("");
            let full = format!("{origin}{xxx}");
            let Some(numeric) = ClientNumeric::from_str(&full) else {
                warn!("BS A: cannot parse {full} as client numeric");
                return;
            };
            state
                .bouncer_sessions
                .entry(key)
                .and_modify(|s| s.primary = Some(numeric))
                .or_insert(BouncerSession {
                    account,
                    sessid,
                    primary: Some(numeric),
                });
            debug!("BS A: session primary → {numeric}");
        }
        'D' => {
            state
                .bouncer_sessions
                .entry(key)
                .and_modify(|s| s.primary = None);
            debug!("BS D: session detached");
        }
        'X' => {
            state.bouncer_sessions.remove(&key);
            debug!("BS X: session destroyed");
        }
        _ => {
            debug!("BS {subcmd}: unhandled subcommand (baseline)");
        }
    }
}

/// Handle BX (BOUNCER_TRANSFER) from a remote server.
///
/// Wire formats (per nefarious2 bouncer_session.c):
///
/// - `BX C <primary> <alias> <account> <sessid> [<modes>] :<channels>`
///   Register a new alias numeric that shadows `<primary>`. Alias is
///   network-invisible: shares identity with the primary and is
///   addressable only by its numeric.
/// - `BX X <alias>` — Destroy alias.
/// - `BX P <old> <new> <sessid> <nick>` — Promote: the numeric-swap
///   path. Transfer every channel membership from `<old>` to `<new>`,
///   transfer `rc.channels` from old to new, silently remove `<old>`
///   from client state, and (if `<new>` was an alias) clear its
///   alias marker so it becomes visible. No QUIT is emitted — the C
///   side uses FLAG_KILLED to suppress S2S QUIT for this reason.
///
/// Other subcommands (`N`, `U`, `E`, `K`) are accepted silently; they
/// don't affect the desync-avoidance baseline.
pub async fn handle_bouncer_transfer(state: &ServerState, msg: &P10Message) {
    if msg.params.is_empty() {
        return;
    }
    let subcmd = match msg.params[0].chars().next() {
        Some(c) => c,
        None => return,
    };

    match subcmd {
        'C' => handle_bx_create(state, msg).await,
        'X' => handle_bx_destroy(state, msg).await,
        'P' => handle_bx_promote(state, msg).await,
        _ => debug!("BX {subcmd}: unhandled subcommand (baseline)"),
    }
}

async fn handle_bx_create(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 5 {
        return;
    }
    let Some(primary) = ClientNumeric::from_str(&msg.params[1]) else {
        return;
    };
    let Some(alias) = ClientNumeric::from_str(&msg.params[2]) else {
        return;
    };
    let account = msg.params[3].clone();

    // The trailing parameter carries a space-separated list of channels
    // the alias shadows. Per nefarious2 bounce_alias_create, the alias
    // must be added to each of these channels so MODE/KICK targeting
    // the alias numeric stay addressable. Parse before doing anything
    // else so we can attach the alias to channels inside the single
    // register pass below.
    let channels_param: Vec<String> = msg
        .params
        .last()
        .map(|s| {
            s.split_whitespace()
                .filter(|c| !c.is_empty())
                .map(|c| c.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Pull identity from primary. If primary isn't known locally we
    // can't render the alias, but we still record the alias entry so
    // that later MODE/KICK for that numeric land — the alias is
    // network-invisible anyway.
    let (nick, user, host, realname, modes, acct) =
        if let Some(p) = state.remote_clients.get(&primary) {
            let pr = p.read().await;
            (
                pr.nick.clone(),
                pr.user.clone(),
                pr.host.clone(),
                pr.realname.clone(),
                pr.modes.clone(),
                pr.account.clone(),
            )
        } else {
            (
                account.clone(),
                account.clone(),
                "bouncer".to_string(),
                account.clone(),
                HashSet::new(),
                Some(account.clone()),
            )
        };

    // If there's already a client at this numeric (e.g. it was
    // introduced via NICK and is being re-stated as an alias), convert
    // in place so any channel memberships already attached to it
    // survive. Otherwise build a fresh RemoteClient.
    if let Some(existing) = state.remote_clients.get(&alias) {
        let mut rc = existing.write().await;
        let old_nick = rc.nick.clone();
        rc.is_alias = true;
        rc.primary = Some(primary);
        rc.nick = nick;
        rc.user = user;
        rc.host = host;
        rc.realname = realname;
        rc.account = acct;
        for ch in &channels_param {
            rc.channels.insert(ch.clone());
        }
        drop(rc);
        // Ensure the alias appears in chan.remote_members for each
        // listed channel. Plain member (no ops) — the primary carries
        // any channel privileges; alias-specific mode changes would
        // update its entry separately.
        for ch in &channels_param {
            let channel = state.get_or_create_channel(ch);
            let mut c = channel.write().await;
            c.remote_members
                .entry(alias)
                .or_insert_with(MembershipFlags::default);
        }
        // An alias isn't in the nick hash — remove the stale mapping
        // if we put one there during its NICK introduction.
        state.remote_nicks.remove(&irc_casefold(&old_nick));
        debug!(
            "BX C: converted {alias} to alias of {primary}, attached to {} channels",
            channels_param.len()
        );
        return;
    }

    let mut alias_channels: HashSet<String> = HashSet::new();
    for ch in &channels_param {
        alias_channels.insert(ch.clone());
    }
    let new_alias = Arc::new(RwLock::new(RemoteClient {
        nick,
        numeric: alias,
        server: alias.server,
        user,
        host,
        realname,
        ip_base64: String::new(),
        modes,
        account: acct,
        nick_ts: 0,
        channels: alias_channels,
        away_message: None,
        privs: HashSet::new(),
        is_alias: true,
        primary: Some(primary),
    }));
    state.register_remote_alias(new_alias, alias);

    // Attach alias to each channel it shadows so MODE/KICK targeting
    // the alias numeric resolve against a real roster entry. The
    // membership carries no mode flags — the visible primary's entry
    // carries any channel privileges (see bounce_alias_create in
    // nefarious2/ircd/bouncer_session.c).
    for ch in &channels_param {
        let channel = state.get_or_create_channel(ch);
        let mut c = channel.write().await;
        c.remote_members
            .entry(alias)
            .or_insert_with(MembershipFlags::default);
    }

    debug!(
        "BX C: registered alias {alias} → primary {primary}, attached to {} channels",
        channels_param.len()
    );
}

async fn handle_bx_destroy(state: &ServerState, msg: &P10Message) {
    if msg.params.len() < 2 {
        return;
    }
    let Some(alias) = ClientNumeric::from_str(&msg.params[1]) else {
        return;
    };
    // Strip the alias from every channel it shadowed, then drop the
    // client record itself. No nick-map removal needed — aliases
    // never had a nick entry.
    for entry in state.channels.iter() {
        let mut chan = entry.value().write().await;
        chan.remote_members.remove(&alias);
    }
    state.remote_clients.remove(&alias);
    debug!("BX X: destroyed alias {alias}");
}

async fn handle_bx_promote(state: &ServerState, msg: &P10Message) {
    // BX P <old> <new> <sessid> <nick>
    if msg.params.len() < 5 {
        return;
    }
    let Some(old) = ClientNumeric::from_str(&msg.params[1]) else {
        return;
    };
    let Some(new) = ClientNumeric::from_str(&msg.params[2]) else {
        return;
    };
    let sessid = msg.params[3].clone();
    let nick = msg.params[4].clone();

    if old == new {
        // Idempotent — sometimes the originating server sends old==new
        // when it can't determine the prior primary at SQUIT time.
        debug!("BX P: old==new ({old}); ignoring");
        return;
    }

    // Determine whether `new` is currently an alias. That changes the
    // semantics: an alias promotion just clears the alias flag and
    // copies mode bits; a non-alias swap transfers memberships bodily.
    let new_was_alias = if let Some(nr) = state.remote_clients.get(&new) {
        nr.read().await.is_alias
    } else {
        false
    };

    // Walk every channel where `old` has a membership and transfer
    // the flags to `new`. On the alias path, `new` already has a
    // CHFL_ALIAS-style ghost membership that we promote; on the swap
    // path, `new` has no membership so we insert one.
    let mut transferred_channels: Vec<String> = Vec::new();
    for entry in state.channels.iter() {
        let chan_name = entry.key().clone();
        let mut chan = entry.value().write().await;
        let old_flags = chan.remote_members.remove(&old);
        if let Some(flags) = old_flags {
            // If `new` already has a (ghost) membership entry, merge —
            // take the max of old flags OR'd with whatever `new` had.
            let entry_flags = chan.remote_members.entry(new).or_insert(MembershipFlags::default());
            entry_flags.op |= flags.op;
            entry_flags.halfop |= flags.halfop;
            entry_flags.voice |= flags.voice;
            entry_flags.oplevel = entry_flags.oplevel.max(flags.oplevel);
            transferred_channels.push(chan_name);
        }
    }

    // Move rc.channels bookkeeping. Old's set goes to new's.
    if let Some(old_arc) = state.remote_clients.get(&old) {
        let old_channels = {
            let rc = old_arc.read().await;
            rc.channels.clone()
        };
        drop(old_arc);
        if let Some(new_arc) = state.remote_clients.get(&new) {
            let mut nr = new_arc.write().await;
            nr.channels.extend(old_channels.iter().cloned());
            // Promote: clear alias marker so /NAMES starts rendering.
            if new_was_alias {
                nr.is_alias = false;
                nr.primary = None;
            }
            if !nick.is_empty() && nr.nick != nick {
                nr.nick = nick.clone();
            }
            // Insert into the nick hash if we weren't there (alias
            // promotion path) or if the nick changed.
            state
                .remote_nicks
                .insert(irc_casefold(&nr.nick), nr.numeric);
        }
    }

    // Drop `old` silently: no QUIT emitted to local clients (matches
    // C's FLAG_KILLED suppression). The nick map mapping for `old`
    // was either absent (alias) or stale; clear it defensively.
    if let Some(old_arc) = state.remote_clients.get(&old) {
        let old_nick = old_arc.read().await.nick.clone();
        drop(old_arc);
        state
            .remote_nicks
            .remove_if(&irc_casefold(&old_nick), |_, v| *v == old);
    }
    state.remote_clients.remove(&old);

    // Update the session's primary pointer so subsequent BS lookups
    // find the new numeric.
    if let Some(account) = state
        .bouncer_sessions
        .iter()
        .find(|e| e.key().1 == sessid)
        .map(|e| e.key().0.clone())
    {
        state
            .bouncer_sessions
            .entry((account, sessid))
            .and_modify(|s| s.primary = Some(new));
    }

    debug!(
        "BX P: promoted {old} → {new} (alias_path={new_was_alias}, {} channels transferred)",
        transferred_channels.len()
    );
}

/// Propagate a forwarded `EB` (End of Burst) from a remote server to
/// every outbound link except the one it arrived on (`skip`).
///
/// Mirrors `sendcmdto_serv_butone(sptr, CMD_END_OF_BURST, cptr, "")` in
/// m_endburst.c:124. Currently nefarious-rs only supports a single
/// uplink, so this is a no-op — the plumbing is here for when we grow
/// multi-server fan-out.
pub async fn propagate_end_of_burst(
    state: &ServerState,
    msg: &P10Message,
    skip: ServerNumeric,
) {
    let origin = match &msg.origin {
        Some(o) => o.clone(),
        None => return,
    };
    let wire = format!("{origin} EB");
    for entry in state.links.iter() {
        if *entry.key() != skip {
            entry.value().send_line(wire.clone()).await;
        }
    }
}

/// Propagate a forwarded `EA` (End of Burst Ack) to every outbound
/// link except the one it arrived on (`skip`).
///
/// Mirrors `sendcmdto_serv_butone(sptr, CMD_END_OF_BURST_ACK, cptr, "")` in
/// m_endburst.c:224.
pub async fn propagate_end_of_burst_ack(
    state: &ServerState,
    msg: &P10Message,
    skip: ServerNumeric,
) {
    let origin = match &msg.origin {
        Some(o) => o.clone(),
        None => return,
    };
    let wire = format!("{origin} EA");
    for entry in state.links.iter() {
        if *entry.key() != skip {
            entry.value().send_line(wire.clone()).await;
        }
    }
}
