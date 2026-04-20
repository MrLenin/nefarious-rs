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
    // Parse the SERVER message we already received during detection
    // SERVER <name> <hopcount> <start_ts> <link_ts> <protocol> <numeric_capacity> <flags> :<info>
    if server_msg_params.len() < 8 {
        error!("SERVER message has too few parameters: {:?}", server_msg_params);
        return;
    }

    let remote_name = &server_msg_params[0];
    let _hop_count: u16 = server_msg_params[1].parse().unwrap_or(1);
    let start_ts: u64 = server_msg_params[2].parse().unwrap_or(0);
    let link_ts: u64 = server_msg_params[3].parse().unwrap_or(0);
    let protocol_str = &server_msg_params[4];
    let numeric_capacity = &server_msg_params[5];
    let flags_str = server_msg_params.get(6).map(|s| s.as_str()).unwrap_or("+");
    let description = server_msg_params.last().unwrap();

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
    let (remote_numeric, capacity_mask) =
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

    let pass_line = format!("PASS :{}", connect.password);
    let server_line = format!(
        "SERVER {} 1 {} {} J10 {} +6 :{}",
        our_name, our_start_ts, link_ts_now, our_capacity, state.server_description
    );

    let _ = tx.send(pass_line).await;
    let _ = tx.send(server_line).await;

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

    // Process incoming burst and steady-state messages
    let mut burst_complete = false;
    let mut our_burst_sent = false;

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

        debug!("S2S recv: {line}");

        let msg = match P10Message::parse(&line) {
            Some(m) => m,
            None => {
                warn!("unparseable S2S message: {line}");
                continue;
            }
        };

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
                info!("received END_OF_BURST from {remote_name}");
                burst_complete = true;

                if !our_burst_sent {
                    // Send our burst
                    super::burst::send_burst(&state, &link).await;
                    our_burst_sent = true;
                }

                // Send EA (end of burst ack)
                let ea = format!("{} EA", our_numeric);
                link.send_line(ea).await;
            }
            P10Token::EndOfBurstAck => {
                info!("received END_OF_BURST_ACK from {remote_name}");
                link.set_state(LinkState::Active);
                info!("server link with {remote_name} is now ACTIVE");
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
                super::handlers::handle_quit(&state, &msg).await;
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
                super::handlers::handle_account(&state, &msg).await;
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

    // Remove all remote state from this server and its downlinks
    // Collect all server numerics to remove (the direct link + any servers introduced through it)
    let servers_to_remove: Vec<ServerNumeric> = state
        .remote_servers
        .iter()
        .map(|entry| *entry.key())
        .collect();

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
        }

        state.remove_remote_server(sn).await;
    }

    state.links.remove(&remote_numeric);
    writer_handle.abort();
}
