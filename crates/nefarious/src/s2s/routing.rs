use crate::client::ClientId;
use crate::state::ServerState;
use crate::tags::{SourceInfo, compact_s2s_tag_prefix};

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

/// Route a local PRIVMSG/NOTICE to the S2S link with compact
/// nefarious2-native time+msgid tags.
///
/// Wire: `@A<time_b64_7><msgid_14> <numeric> P|O <target> :<text>`.
/// See nefarious2 ircd/send.c `format_s2s_tags` and ircd/parse.c:1708
/// for the wire contract.
///
/// The msgid on the wire is taken from `src` so every recipient
/// across the network sees the same id on the broadcast (per IRCv3
/// msgid: one id per *event*, not per delivery).
pub async fn route_privmsg(
    state: &ServerState,
    client_id: ClientId,
    target: &str,
    text: &str,
    is_notice: bool,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let token = if is_notice { "O" } else { "P" };
    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    let line = format!("{tag_prefix} {numeric} {token} {target} :{text}");
    link.send_line(line).await;
}

/// Route a local JOIN to the S2S link.
pub async fn route_join(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    ts: u64,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    // Use CREATE (C) for new channels, JOIN (J) for existing
    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);

    // Check if channel has remote members — if not, it's a CREATE
    let has_remote = if let Some(chan) = state.get_channel(channel) {
        let c = chan.read().await;
        !c.remote_members.is_empty()
    } else {
        false
    };

    let token = if has_remote { "J" } else { "C" };
    let line = format!("{tag_prefix} {numeric} {token} {channel} {ts}");
    link.send_line(line).await;
}

/// Route a local PART to the S2S link.
pub async fn route_part(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    reason: &str,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    let line = if reason.is_empty() {
        format!("{tag_prefix} {numeric} L {channel}")
    } else {
        format!("{tag_prefix} {numeric} L {channel} :{reason}")
    };
    link.send_line(line).await;
}

/// Route a local QUIT to the S2S link.
pub async fn route_quit(
    state: &ServerState,
    client_id: ClientId,
    reason: &str,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!("{tag_prefix} {numeric} Q :{reason}"))
        .await;
}

/// Route a local NICK change to the S2S link.
pub async fn route_nick_change(
    state: &ServerState,
    client_id: ClientId,
    new_nick: &str,
    ts: u64,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!("{tag_prefix} {numeric} N {new_nick} {ts}"))
        .await;
}

/// Route a local TOPIC change to the S2S link.
pub async fn route_topic(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    topic: &str,
    setter: &str,
    ts: u64,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!(
        "{tag_prefix} {numeric} T {channel} {setter} {ts} {ts} :{topic}"
    ))
    .await;
}

/// Route a local KICK to the S2S link.
pub async fn route_kick(
    state: &ServerState,
    client_id: ClientId,
    channel: &str,
    target_numeric: &str,
    reason: &str,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!(
        "{tag_prefix} {numeric} K {channel} {target_numeric} :{reason}"
    ))
    .await;
}

/// Route a local MODE change to the S2S link.
pub async fn route_mode(
    state: &ServerState,
    client_id: ClientId,
    target: &str,
    mode_str: &str,
    params: &[String],
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    let mut line = format!("{tag_prefix} {numeric} M {target} {mode_str}");
    for p in params {
        line.push(' ');
        line.push_str(p);
    }
    link.send_line(line).await;
}

/// Route a local INVITE to the S2S link.
///
/// Wire format per nefarious2 m_invite.c:237 — `<inviter> I <nick>
/// <channel> <chan_ts>`. The target is carried as a *nick*, not a
/// numeric (`FindUser(parv[1])` in the server handler looks it up
/// by name), and the channel's creation timestamp is required so
/// peers can silently discard invites that arrive after a channel
/// has been recreated (m_invite.c:309-312).
///
/// We previously sent the target as a numeric and omitted the TS;
/// the peer failed the FindUser and returned `401 :No such nick`.
pub async fn route_invite(
    state: &ServerState,
    client_id: ClientId,
    target_nick: &str,
    channel: &str,
    chan_ts: u64,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };

    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!(
        "{tag_prefix} {numeric} I {target_nick} {channel} {chan_ts}"
    ))
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
///   `@A<time_7><msgid_14> <our_numeric> N <nick> 1 <nick_ts> <user> <host> [+<modes>] <ip> <YYXXX> :<realname>`
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

    // Use a fresh SourceInfo tied to this nick-intro event. The msgid
    // lets peers dedupe if they somehow receive us twice during
    // netjoin races; the @time anchors chathistory's "first seen".
    let src = SourceInfo::from_local(&c);
    let tag_prefix = compact_s2s_tag_prefix(&src);

    let line = format!(
        "{tag_prefix} {our} N {nick} 1 {nick_ts} {user} {host}{mode_tok} {ip_encoded} {client_numeric} :{realname}",
        nick = c.nick,
        nick_ts = c.nick_ts,
        user = c.user,
        host = c.host,
        realname = c.realname,
    );

    // AC follow-up gets its own fresh tag prefix: it's a separate
    // event (account login) that the receiver should treat with its
    // own msgid.
    let account_line = c.account.as_ref().map(|a| {
        let ac_src = SourceInfo::from_local(&c);
        let ac_tag = compact_s2s_tag_prefix(&ac_src);
        format!(
            "{ac_tag} {our} AC {client_numeric} R {a} {ts}",
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

/// Route a local oper's privilege set to S2S peers.
///
/// Wire: `@A<time_7><msgid_14> <our_server> PRIVS <user_numeric> <priv1> <priv2> ...`.
/// Called once after a successful /OPER, right after the `+o` user
/// mode is propagated. Mirrors `client_sendtoserv_privs` in
/// nefarious2/ircd/client.c — splits into multiple PRIVS lines if
/// the priv list would blow the 512-byte wire limit. Each split gets
/// its own tag prefix (fresh msgid per line).
pub async fn route_privs(state: &ServerState, client_id: ClientId, privs: &[&str]) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    if privs.is_empty() {
        return;
    }
    let numeric = local_numeric(state, client_id);
    let our = state.numeric.to_string();

    // Pack privs until we'd cross ~400 bytes, then flush. The 512-byte
    // line limit minus prefix/token/numeric+tag overhead leaves room
    // for roughly 14-20 priv names per line.
    let flush = async |line: &mut String, our: &str, numeric: &str| {
        let src = SourceInfo::now();
        let tag_prefix = compact_s2s_tag_prefix(&src);
        link.send_line(format!("{tag_prefix} {our} PRIVS {numeric}{line}"))
            .await;
        line.clear();
    };

    let mut body = String::new();
    for p in privs {
        if body.len() + 1 + p.len() > 400 {
            flush(&mut body, &our, &numeric).await;
        }
        body.push(' ');
        body.push_str(p);
    }
    if !body.is_empty() {
        flush(&mut body, &our, &numeric).await;
    }
}

/// Route a local AWAY state change to the S2S link.
///
/// Wire format per nefarious2/ircd/m_away.c:
/// `@A<time_7><msgid_14> <user> A :<msg>` when setting,
/// `@A<time_7><msgid_14> <user> A` (no trailing) when clearing.
pub async fn route_away(
    state: &ServerState,
    client_id: ClientId,
    away_message: Option<&str>,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    let line = match away_message {
        Some(msg) => format!("{tag_prefix} {numeric} A :{msg}"),
        None => format!("{tag_prefix} {numeric} A"),
    };
    link.send_line(line).await;
}

/// Route a local SETNAME (realname change) to the S2S link.
///
/// Wire: `@A<time_7><msgid_14> <user> SR :<realname>`.
pub async fn route_setname(
    state: &ServerState,
    client_id: ClientId,
    realname: &str,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!("{tag_prefix} {numeric} SR :{realname}"))
        .await;
}

/// Route a local user-mode change (e.g. +i, +w, -o) to the S2S link.
///
/// Wire: `@A<time_7><msgid_14> <user> M <nick> <modestring>`. Shares
/// the `M` token with channel MODE; the target being a nick rather
/// than `#channel` distinguishes the two on the receiving side.
pub async fn route_user_mode(
    state: &ServerState,
    client_id: ClientId,
    nick: &str,
    mode_str: &str,
    src: &SourceInfo,
) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    let numeric = local_numeric(state, client_id);
    let tag_prefix = compact_s2s_tag_prefix(src);
    link.send_line(format!("{tag_prefix} {numeric} M {nick} {mode_str}"))
        .await;
}

/// Announce a P10 KILL originated by this server — used when we settle a
/// nick-TS collision and need every other server to drop their entry for
/// the losing user. `victim` is the user's nick or numeric; the killer is
/// always this server.
///
/// Wire: `@A<time_7><msgid_14> <killer> D <victim> :<killpath> (<reason>)`.
pub async fn route_kill(state: &ServerState, victim: &str, reason: &str) {
    let link = match state.get_link() {
        Some(l) => l,
        None => return,
    };
    // KILL originates here with no specific source-user context, so
    // generate a fresh server-event SourceInfo.
    let src = SourceInfo::now();
    let tag_prefix = compact_s2s_tag_prefix(&src);
    link.send_line(format!(
        "{tag_prefix} {us} D {victim} :{us} ({reason})",
        us = state.numeric
    ))
    .await;
}
