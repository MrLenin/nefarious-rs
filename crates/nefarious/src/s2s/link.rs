use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LinesCodec};
use tracing::{debug, error, info, warn};

use p10_proto::{P10Message, P10Token, ServerNumeric};

use crate::s2s::types::{LinkState, RemoteServer, ServerFlags, ServerLink};
use crate::state::ServerState;

/// Handle an inbound server-to-server connection.
///
/// Called when we detect that an incoming connection sends PASS+SERVER
/// instead of NICK+USER.
pub async fn handle_server_link<S>(
    stream: S,
    state: Arc<ServerState>,
    password_received: String,
    server_msg_params: Vec<String>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_server_link_inner(stream, state, password_received, server_msg_params, false)
        .await;
}

/// Same as `handle_server_link` but for the outbound side of a link,
/// where we've already sent PASS + SERVER before reading the remote
/// greeting. Setting `suppress_greeting = true` skips the second
/// PASS/SERVER emission that the inbound path uses as its reply.
pub async fn handle_server_link_outbound<S>(
    stream: S,
    state: Arc<ServerState>,
    password_received: String,
    server_msg_params: Vec<String>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_server_link_inner(stream, state, password_received, server_msg_params, true)
        .await;
}

async fn handle_server_link_inner<S>(
    stream: S,
    state: Arc<ServerState>,
    password_received: String,
    server_msg_params: Vec<String>,
    suppress_greeting: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Parse the SERVER message we already received during detection
    // SERVER <name> <hopcount> <start_ts> <link_ts> <protocol> <numeric_capacity> <flags> :<info>
    if server_msg_params.len() < 8 {
        error!("SERVER message has too few parameters: {:?}", server_msg_params);
        return;
    }

    let remote_name = &server_msg_params[0];
    let _hop_count: u16 = server_msg_params[1].parse().unwrap_or(1);
    let start_ts: u64 = server_msg_params[2].parse().unwrap_or(0);
    let _link_ts: u64 = server_msg_params[3].parse().unwrap_or(0);
    let protocol_str = &server_msg_params[4];
    let numeric_capacity = &server_msg_params[5];
    let flags_str = server_msg_params.get(6).map(|s| s.as_str()).unwrap_or("+");
    let description = server_msg_params.last().map(|s| s.as_str()).unwrap_or("");

    // Parse protocol version
    let protocol_version: u16 = protocol_str
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .unwrap_or(10);

    if protocol_version < 10 {
        error!("unsupported protocol version: {protocol_str}");
        return;
    }

    // Parse remote server numeric from capacity string
    let (remote_numeric, _capacity_mask) =
        match p10_proto::numeric::parse_server_numeric_capacity(numeric_capacity) {
            Some(v) => v,
            None => {
                error!("invalid numeric capacity: {numeric_capacity}");
                return;
            }
        };

    info!(
        "server link: {} (numeric={}, protocol={}, flags={})",
        remote_name, remote_numeric, protocol_str, flags_str
    );

    // Validate password against Connect blocks
    let connect = state
        .config
        .connects
        .iter()
        .find(|c| c.name == *remote_name);

    let connect = match connect {
        Some(c) => c,
        None => {
            error!("no Connect block for server {remote_name}");
            return;
        }
    };

    if connect.password != password_received {
        error!("password mismatch for server {remote_name}");
        return;
    }

    // Frame the stream with a simple line codec (P10 is line-based)
    let framed = Framed::new(stream, LinesCodec::new_with_max_length(8192));
    let (mut sink, mut reader) = framed.split();

    // Create the outbound channel
    let (tx, mut rx) = mpsc::channel::<String>(512);

    // Spawn the writer task
    let writer_handle = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if sink.send(line).await.is_err() {
                break;
            }
        }
    });

    // Send our PASS + SERVER response
    let our_numeric = state.numeric;
    let our_name = &state.server_name;
    let our_start_ts = state.start_timestamp;
    let link_ts_now = chrono::Utc::now().timestamp() as u64;

    // Capacity: our max clients encoded. Use 3-char capacity for up to 262143.
    let our_capacity = format!(
        "{}{}",
        our_numeric,
        p10_proto::numeric::capacity_to_base64(4096)
    );

    if !suppress_greeting {
        let pass_line = format!("PASS :{}", connect.password);
        let server_line = format!(
            "SERVER {} 1 {} {} J10 {} +6 :{}",
            our_name, our_start_ts, link_ts_now, our_capacity, state.server_description
        );
        let _ = tx.send(pass_line).await;
        let _ = tx.send(server_line).await;
    } else {
        // Outbound: we already sent PASS+SERVER before the handoff,
        // so the greeting step is a no-op. The rest of this
        // function (register remote_server, drive burst, run the
        // read loop) runs identically.
        let _ = our_start_ts; // keep the symbol live
        let _ = our_capacity;
        let _ = link_ts_now;
    }

    // Register the remote server
    let remote_server = Arc::new(tokio::sync::RwLock::new(RemoteServer {
        name: remote_name.to_string(),
        numeric: remote_numeric,
        hop_count: 1,
        description: description.to_string(),
        uplink: our_numeric,
        timestamp: start_ts,
        flags: ServerFlags::from_flag_str(flags_str),
    }));
    state
        .remote_servers
        .insert(remote_numeric, remote_server);

    // Create and register the link
    let link = Arc::new(ServerLink::new(
        remote_numeric,
        remote_name.to_string(),
        tx.clone(),
    ));
    link.set_state(LinkState::Bursting);
    state.links.insert(remote_numeric, Arc::clone(&link));

    info!("server link established with {remote_name} ({remote_numeric})");

    // P10 burst is bidirectional and concurrent: both sides begin bursting
    // immediately after the handshake completes, so neither side blocks on
    // the other's state. Send ours now and keep reading theirs below.
    super::burst::send_burst(&state, &link).await;

    // Spawn a keepalive task that PINGs the peer every 60s. The task exits
    // on its own once the outbound channel is closed (link drop), so we
    // don't need to explicitly abort it.
    let keepalive_tx = tx.clone();
    let keepalive_us = our_numeric;
    let keepalive_peer = remote_numeric;
    let keepalive_handle = tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // discard the immediate first tick
        loop {
            tick.tick().await;
            let ping = format!("{keepalive_us} G :{keepalive_peer}");
            if keepalive_tx.send(ping).await.is_err() {
                break;
            }
        }
    });

    while let Some(result) = reader.next().await {
        let line = match result {
            Ok(l) => l,
            Err(e) => {
                error!("read error from {remote_name}: {e}");
                break;
            }
        };

        if line.is_empty() {
            continue;
        }

        // Every inbound wire line — deployments should run with
        // RUST_LOG=debug (or similar) so this shows up in `docker logs`.
        debug!("S2S recv: {line}");

        let msg = match P10Message::parse(&line) {
            Some(m) => m,
            None => {
                warn!("unparseable S2S message: {line}");
                continue;
            }
        };

        // If the peer carried a compact tag block (`@A<time><msgid>`)
        // the parser decoded the physical_ms and msgid. The `LLL`
        // logical field is the 3 base64 chars at offset 2 of the
        // msgid. Feed that into the HLC so our next local event ids
        // are strictly ordered after this remote event.
        if let (Some(ms), Some(mid)) = (msg.tag_time_ms, msg.tag_msgid.as_deref()) {
            if mid.len() >= 5 {
                let logical = p10_proto::base64toint(&mid[2..5]) as u16;
                crate::tags::hlc_receive(ms, logical);
            }
        }

        match &msg.token {
            P10Token::Server => {
                super::handlers::handle_server(&state, &msg).await;
            }
            P10Token::Nick => {
                super::handlers::handle_nick(&state, &msg).await;
            }
            P10Token::Burst => {
                super::handlers::handle_burst(&state, &msg).await;
            }
            P10Token::EndOfBurst => {
                // The EB origin may be our direct peer (the server that
                // just finished sending us its burst), or it may be a
                // remote server whose EB our peer is forwarding on its
                // behalf. Per m_endburst.c:131 we only send EA when the
                // originator is directly connected (`MyConnect(sptr)`).
                //
                // In P10, the origin of a forwarded EB is the *remote*
                // server's numeric, not our direct peer's numeric. So
                // `msg.origin == Some(remote_numeric)` iff it's direct.
                let origin_is_direct_peer = msg
                    .origin
                    .as_deref()
                    .and_then(|o| ServerNumeric::from_str(o))
                    .map(|n| n == remote_numeric)
                    .unwrap_or(false);

                if origin_is_direct_peer {
                    info!("END_OF_BURST from direct peer {remote_name} — sending EA");
                    let ea = format!("{our_numeric} EA");
                    link.send_line(ea).await;
                } else {
                    let origin = msg.origin.as_deref().unwrap_or("?");
                    info!("END_OF_BURST from remote {origin} (via {remote_name}) — no EA");
                    // Propagate EB to our other links so they can
                    // respond. The forwarded form keeps the original
                    // server's numeric as the origin.
                    super::handlers::propagate_end_of_burst(
                        &state,
                        &msg,
                        remote_numeric,
                    )
                    .await;
                }
            }
            P10Token::EndOfBurstAck => {
                // EA also travels with the *acknowledging* server's
                // numeric as its origin and is forwarded to all other
                // links (m_endburst.c:224). Only the direct-peer EA
                // marks our link Active.
                let origin_is_direct_peer = msg
                    .origin
                    .as_deref()
                    .and_then(|o| ServerNumeric::from_str(o))
                    .map(|n| n == remote_numeric)
                    .unwrap_or(false);

                let origin = msg.origin.as_deref().unwrap_or("?");
                info!("END_OF_BURST_ACK from {origin} (via {remote_name})");

                if origin_is_direct_peer {
                    link.set_state(LinkState::Active);
                    info!("server link with {remote_name} is now ACTIVE");
                }

                // Propagate EA to other links regardless.
                super::handlers::propagate_end_of_burst_ack(
                    &state,
                    &msg,
                    remote_numeric,
                )
                .await;
            }
            P10Token::Ping => {
                super::handlers::handle_ping(&state, &msg, &link).await;
            }
            P10Token::Pong => {
                // Remote acknowledged our ping — nothing to do
            }
            P10Token::Privmsg | P10Token::Notice => {
                super::handlers::handle_privmsg_notice(&state, &msg).await;
            }
            P10Token::Join => {
                super::handlers::handle_join(&state, &msg).await;
            }
            P10Token::Create => {
                super::handlers::handle_create(&state, &msg).await;
            }
            P10Token::Part => {
                super::handlers::handle_part(&state, &msg).await;
            }
            P10Token::Quit => {
                super::handlers::handle_quit(&state, &msg).await;
            }
            P10Token::Kill => {
                super::handlers::handle_kill(&state, &msg).await;
            }
            P10Token::Mode => {
                super::handlers::handle_mode(&state, &msg).await;
            }
            P10Token::Kick => {
                super::handlers::handle_kick(&state, &msg).await;
            }
            P10Token::Topic => {
                super::handlers::handle_topic(&state, &msg).await;
            }
            P10Token::Account => {
                super::handlers::handle_account(&state, &msg, remote_numeric).await;
            }
            P10Token::Away => {
                super::handlers::handle_away(&state, &msg).await;
            }
            P10Token::Invite => {
                super::handlers::handle_invite(&state, &msg).await;
            }
            P10Token::BouncerSession => {
                super::handlers::handle_bouncer_session(&state, &msg).await;
            }
            P10Token::BouncerTransfer => {
                super::handlers::handle_bouncer_transfer(&state, &msg).await;
            }
            P10Token::Setname => {
                super::handlers::handle_setname(&state, &msg).await;
            }
            P10Token::Privs => {
                super::handlers::handle_privs(&state, &msg).await;
            }
            P10Token::Whois => {
                super::handlers::handle_whois(&state, &msg).await;
            }
            P10Token::Wallops => {
                super::handlers::handle_wallops(&state, &msg).await;
            }
            P10Token::Opmode => {
                // OPMODE is MODE without ops/TS checks (matches
                // nefarious2 m_opmode.c:125 delegating to the
                // modebuf/mode_parse path). Our remote MODE handler
                // is already server-authoritative — no TS gate, no
                // op check — so routing OPMODE through it is
                // correct. The broadcast to local clients still goes
                // out as a regular MODE event.
                super::handlers::handle_mode(&state, &msg).await;
            }
            P10Token::Clearmode => {
                super::handlers::handle_clearmode(&state, &msg).await;
            }
            P10Token::Silence => {
                super::handlers::handle_silence(&state, &msg, remote_numeric).await;
            }
            P10Token::Gline => {
                super::handlers::handle_gline(&state, &msg, remote_numeric).await;
            }
            P10Token::Shun => {
                super::handlers::handle_shun(&state, &msg, remote_numeric).await;
            }
            P10Token::Zline => {
                super::handlers::handle_zline(&state, &msg, remote_numeric).await;
            }
            P10Token::Jupe => {
                super::handlers::handle_jupe(&state, &msg, remote_numeric).await;
            }
            P10Token::Squit => {
                info!("received SQUIT from {remote_name}");
                break;
            }
            P10Token::Destruct => {
                super::handlers::handle_destruct(&state, &msg).await;
            }
            _ => {
                debug!(
                    "unhandled S2S token {:?} from {remote_name}: {line}",
                    msg.token
                );
            }
        }
    }

    // Clean up — server link is dead
    info!("server link with {remote_name} disconnected");

    // A dropped link only affects servers reachable *through* this link.
    // Walk the server tree rooted at `remote_numeric` via the `uplink`
    // field so other links (if any) keep their servers and users.
    let servers_to_remove = collect_downstream_servers(&state, remote_numeric).await;

    for sn in servers_to_remove {
        // Notify local users about QUIT for each remote user on this server
        let clients_to_remove: Vec<p10_proto::ClientNumeric> = state
            .remote_clients
            .iter()
            .filter(|entry| entry.key().server == sn)
            .map(|entry| *entry.key())
            .collect();

        for cn in &clients_to_remove {
            if let Some(remote) = state.remote_clients.get(cn) {
                let rc = remote.read().await;
                let quit_msg = irc_proto::Message::with_source(
                    &rc.prefix(),
                    irc_proto::Command::Quit,
                    vec![format!("{} {}", state.server_name, remote_name)],
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
        }

        state.remove_remote_server(sn).await;
    }

    state.links.remove(&remote_numeric);
    writer_handle.abort();
    keepalive_handle.abort();
}

/// Collect `root` plus every server that reaches us *through* root — i.e.
/// the set of servers we lose when the link to `root` drops.
///
/// Snapshots the uplink tree first so we don't hold a DashMap iterator
/// across an `.await` on the inner per-server RwLock.
async fn collect_downstream_servers(
    state: &Arc<ServerState>,
    root: ServerNumeric,
) -> Vec<ServerNumeric> {
    let keys: Vec<ServerNumeric> = state
        .remote_servers
        .iter()
        .map(|e| *e.key())
        .collect();

    let mut tree: Vec<(ServerNumeric, ServerNumeric)> = Vec::with_capacity(keys.len());
    for k in keys {
        if let Some(server) = state.remote_servers.get(&k) {
            let uplink = server.read().await.uplink;
            tree.push((k, uplink));
        }
    }

    let mut descendants = vec![root];
    let mut i = 0;
    while i < descendants.len() {
        let parent = descendants[i];
        for &(child, uplink) in &tree {
            if uplink == parent && !descendants.contains(&child) {
                descendants.push(child);
            }
        }
        i += 1;
    }
    descendants
}
