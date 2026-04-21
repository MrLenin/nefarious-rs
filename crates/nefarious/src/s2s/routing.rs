use crate::client::ClientId;
use crate::state::ServerState;

/// Get the P10 numeric string for a local client.
///
/// Panics in debug if the client is not registered (has no allocated
/// numeric) — that would be a caller bug. In release we fall back to slot
/// 0 which is reserved and will never be accepted by a peer, making the
/// failure visible but non-fatal.
pub fn local_numeric(state: &ServerState, client_id: ClientId) -> String {
    let slot = state.numeric_for(client_id).unwrap_or_else(|| {
        debug_assert!(
            false,
            "local_numeric called for client {client_id:?} with no allocated numeric"
        );
        0
    });
    p10_proto::ClientNumeric {
        server: state.numeric,
        client: slot,
    }
    .to_string()
}

/// Route a local PRIVMSG/NOTICE to the S2S link.
pub async fn route_privmsg(
    state: &ServerState,
    client_id: ClientId,
    target: &str,
    text: &str,
    is_notice: bool,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let token = if is_notice { "O" } else { "P" };
    let numeric = local_numeric(state, client_id);
    let line = format!("{numeric} {token} {target} :{text}");
    link.send_line(line).await;
}

/// Route a local JOIN to the S2S link.
pub async fn route_join(state: &ServerState, client_id: ClientId, channel: &str, ts: u64) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    // Use CREATE (C) for new channels, JOIN (J) for existing
    let numeric = local_numeric(state, client_id);

    // Check if channel has remote members — if not, it's a CREATE
    let has_remote = if let Some(chan) = state.get_channel(channel) {
        let c = chan.read().await;
        !c.remote_members.is_empty()
    } else {
        false
    };

    if has_remote {
        let line = format!("{numeric} J {channel} {ts}");
        link.send_line(line).await;
    } else {
        let line = format!("{numeric} C {channel} {ts}");
        link.send_line(line).await;
    }
}

/// Route a local PART to the S2S link.
pub async fn route_part(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    reason: &str,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    if reason.is_empty() {
        link.send_line(format!("{numeric} L {channel}")).await;
    } else {
        link.send_line(format!("{numeric} L {channel} :{reason}")).await;
    }
}

/// Route a local QUIT to the S2S link.
pub async fn route_quit(state: &ServerState, client_id: ClientId, reason: &str) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} Q :{reason}")).await;
}

/// Route a local NICK change to the S2S link.
pub async fn route_nick_change(
    state: &ServerState,
    client_id: ClientId,
    new_nick: &str,
    ts: u64,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} N {new_nick} {ts}")).await;
}

/// Route a local TOPIC change to the S2S link.
pub async fn route_topic(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    topic: &str,
    setter: &str,
    ts: u64,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} T {channel} {setter} {ts} {ts} :{topic}"))
        .await;
}

/// Route a local KICK to the S2S link.
pub async fn route_kick(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    target_numeric: &str,
    reason: &str,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} K {channel} {target_numeric} :{reason}"))
        .await;
}

/// Route a local MODE change to the S2S link.
pub async fn route_mode(
    state: &ServerState,
    client_id: ClientId,
    target: &str,
    mode_str: &str,
    params: &[String],
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let mut line = format!("{numeric} M {target} {mode_str}");
    for p in params {
        line.push(' ');
        line.push_str(p);
    }
    link.send_line(line).await;
}

/// Route a local INVITE to the S2S link. The target numeric identifies the
/// remote or local user being invited.
pub async fn route_invite(
    state: &ServerState,
    client_id: ClientId,
    target_numeric: &str,
    channel: &str,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} I {target_numeric} {channel}"))
        .await;
}

/// Route the introduction of a newly-registered local client to every
/// S2S link.
///
/// Must be called once, right after `ServerState::register_client`,
/// whenever a client completes registration after the link is already
/// active — otherwise peers never learn the client exists. The burst
/// path in `send_burst` covers clients registered *before* the link
/// came up; this path covers the steady-state case.
///
/// Wire format matches `send_burst`'s NICK emission exactly:
///   `<our_numeric> N <nick> 1 <nick_ts> <user> <host> [+<modes>] <ip> <YYXXX> :<realname>`
///
/// If the client is logged into an account, emits the follow-up
/// `AC <numeric> R <account> <ts>` token so peers record the login.
/// Silently skips when no S2S link exists or the client has no
/// allocated P10 numeric.
pub async fn route_nick_intro(
    state: &ServerState,
    client: &std::sync::Arc<tokio::sync::RwLock<crate::client::Client>>,
) {
    if state.links.is_empty() {
        return;
    }
    let c = client.read().await;
    let Some(slot) = state.numeric_for(c.id) else {
        return;
    };
    let client_numeric = p10_proto::ClientNumeric {
        server: state.numeric,
        client: slot,
    };
    let our = state.numeric.to_string();

    let modes: String = c.modes.iter().collect();
    let mode_tok = if modes.is_empty() {
        String::new()
    } else {
        format!(" +{modes}")
    };
    let ip_encoded = p10_proto::numeric::ip_to_base64(c.addr.ip());

    let line = format!(
        "{our} N {nick} 1 {nick_ts} {user} {host}{mode_tok} {ip_encoded} {client_numeric} :{realname}",
        nick = c.nick,
        nick_ts = c.nick_ts,
        user = c.user,
        host = c.host,
        realname = c.realname,
    );

    let account_line = c.account.as_ref().map(|a| {
        format!(
            "{our} AC {client_numeric} R {a} {ts}",
            ts = c.nick_ts,
        )
    });
    drop(c);

    for entry in state.links.iter() {
        entry.value().send_line(line.clone()).await;
        if let Some(ref ac) = account_line {
            entry.value().send_line(ac.clone()).await;
        }
    }
}

/// Route a local AWAY state change to the S2S link.
///
/// Wire format per nefarious2/ircd/m_away.c: `<user> A :<msg>` when
/// setting, `<user> A` (no trailing) when clearing. Sent on every
/// AWAY change so peers can relay away-notify to their own clients.
pub async fn route_away(
    state: &ServerState,
    client_id: ClientId,
    away_message: Option<&str>,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    let line = match away_message {
        Some(msg) => format!("{numeric} A :{msg}"),
        None => format!("{numeric} A"),
    };
    link.send_line(line).await;
}

/// Route a local SETNAME (realname change) to the S2S link.
///
/// Wire: `<user> SR :<realname>`. Peers update their remote_client
/// realname and fan out `:prefix SETNAME :<realname>` to local channel
/// peers with the `setname` cap.
pub async fn route_setname(state: &ServerState, client_id: ClientId, realname: &str) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} SR :{realname}")).await;
}

/// Route a local user-mode change (e.g. +i, +w, -o) to the S2S link.
///
/// Wire: `<user> M <nick> <modestring>`. Shares the `M` token with
/// channel MODE; the target being a nick rather than `#channel`
/// distinguishes the two on the receiving side. Matches nefarious2
/// send_umode_out in ircd/s_user.c.
pub async fn route_user_mode(
    state: &ServerState,
    client_id: ClientId,
    nick: &str,
    mode_str: &str,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    link.send_line(format!("{numeric} M {nick} {mode_str}")).await;
}

/// Announce a P10 KILL originated by this server — used when we settle a
/// nick-TS collision and need every other server to drop their entry for
/// the losing user. `victim` is the user's nick or numeric; the killer is
/// always this server.
pub async fn route_kill(state: &ServerState, victim: &str, reason: &str) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    // Format: `<killer> D <victim> :<killpath> (<reason>)`. We use our own
    // server numeric as the killpath since the kill originates here.
    link.send_line(format!(
        "{us} D {victim} :{us} ({reason})",
        us = state.numeric
    ))
    .await;
}
