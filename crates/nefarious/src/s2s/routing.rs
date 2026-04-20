use crate::client::ClientId;
use crate::state::ServerState;

use p10_proto::inttobase64;

/// Get the P10 numeric string for a local client.
fn local_numeric(state: &ServerState, client_id: ClientId) -> String {
    let cn = p10_proto::ClientNumeric {
        server: state.numeric,
        client: client_id.0 as u32,
    };
    cn.to_string()
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
