use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{RwLock, mpsc};
use tokio_util::codec::Framed;
use tracing::{debug, info};

use irc_proto::{Command, IrcCodec, Message};

use crate::client::Client;
use crate::handlers::HandlerContext;
use crate::handlers::registration::{handle_cap, is_valid_nick};
use crate::numeric::*;
use crate::state::ServerState;

/// Handle a client connection over any async stream (plain TCP or TLS).
pub async fn handle_connection<S>(
    stream: S,
    addr: SocketAddr,
    state: Arc<ServerState>,
    tls: bool,
    listener_port: u16,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("new connection from {addr} on port {listener_port} (tls={tls})");

    // Create the message channel for outbound messages
    let (tx, mut rx) = mpsc::channel::<Message>(256);

    let client = Arc::new(RwLock::new(Client::new(addr, tls, listener_port, tx)));

    // Frame the stream with IRC codec
    let framed = Framed::new(stream, IrcCodec::new());
    let (mut sink, mut reader) = framed.split();

    // Spawn the writer task
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Registration phase
    let registered = registration_phase(&mut reader, &client, &state).await;

    if !registered {
        // Release any nick reserved during the aborted registration.
        let (id, nick) = {
            let c = client.read().await;
            (c.id, c.nick.clone())
        };
        if !nick.is_empty() {
            state.release_nick(&nick, id);
        }
        debug!("client {addr} disconnected during registration");
        writer_handle.abort();
        return;
    }

    let client_id = client.read().await.id;
    let nick = client.read().await.nick.clone();
    info!("client {nick} ({addr}) registered");

    // Register in global state
    state.register_client(Arc::clone(&client), &nick).await;

    // Send welcome burst
    send_welcome(&client, &state).await;

    // Main message loop
    let ctx = HandlerContext {
        state: Arc::clone(&state),
        client: Arc::clone(&client),
    };

    let quit_reason = message_loop(&mut reader, &ctx).await;

    // Client disconnected — clean up
    info!("client {nick} ({addr}) disconnected: {quit_reason}");

    // Notify channels
    let channels: Vec<String> = {
        let c = client.read().await;
        c.channels.iter().cloned().collect()
    };

    let prefix = client.read().await.prefix();
    let quit_msg = Message::with_source(&prefix, Command::Quit, vec![quit_reason.clone()]);

    // Route QUIT to S2S
    crate::s2s::routing::route_quit(&state, client_id, &quit_reason).await;

    for chan_name in &channels {
        if let Some(channel) = state.get_channel(chan_name) {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if member_id == client_id {
                    continue;
                }
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send(quit_msg.clone());
                }
            }
        }
    }

    // Remove from state
    state.remove_client(client_id).await;
    writer_handle.abort();
}

/// Registration phase: wait for NICK + USER, handle PING, CAP.
async fn registration_phase(
    stream: &mut (impl StreamExt<Item = Result<Message, irc_proto::codec::CodecError>> + Unpin),
    client: &Arc<RwLock<Client>>,
    state: &Arc<ServerState>,
) -> bool {
    let mut got_nick = false;
    let mut got_user = false;

    let ctx = HandlerContext {
        state: Arc::clone(state),
        client: Arc::clone(client),
    };

    while let Some(result) = stream.next().await {
        let msg = match result {
            Ok(m) => m,
            Err(e) => {
                debug!("codec error during registration: {e}");
                return false;
            }
        };

        match &msg.command {
            Command::Cap => {
                handle_cap(&ctx, &msg).await;
            }

            Command::Nick => {
                if let Some(nick) = msg.params.first() {
                    if !is_valid_nick(nick) {
                        let c = client.read().await;
                        c.send_numeric(
                            &state.server_name,
                            ERR_ERRONEUSNICKNAME,
                            vec![nick.clone(), "Erroneous nickname".into()],
                        );
                        continue;
                    }
                    // Atomic reserve — no TOCTOU window between the usage
                    // check and taking the nick.
                    let (id, old_nick) = {
                        let c = client.read().await;
                        (c.id, c.nick.clone())
                    };
                    if !state.try_reserve_nick(nick, id) {
                        let c = client.read().await;
                        c.send_numeric(
                            &state.server_name,
                            ERR_NICKNAMEINUSE,
                            vec![nick.clone(), "Nickname is already in use".into()],
                        );
                        continue;
                    }
                    // Release any prior reservation from an earlier NICK
                    // during this same registration, unless it was a
                    // case-only change.
                    if !old_nick.is_empty() && !irc_proto::irc_eq(&old_nick, nick) {
                        state.release_nick(&old_nick, id);
                    }
                    {
                        let mut c = client.write().await;
                        c.nick = nick.clone();
                        c.nick_ts = chrono::Utc::now().timestamp() as u64;
                    }
                    got_nick = true;
                }
            }

            Command::User => {
                if got_user {
                    let c = client.read().await;
                    c.send_numeric(
                        &state.server_name,
                        ERR_ALREADYREGISTERED,
                        vec!["You may not reregister".into()],
                    );
                    continue;
                }
                if msg.params.len() >= 4 {
                    let mut c = client.write().await;
                    c.user = msg.params[0].clone();
                    c.realname = msg.params[3].clone();
                    got_user = true;
                }
            }

            Command::Pass => {
                // Accept and ignore for now (no password auth in Phase 0)
            }

            Command::Ping => {
                let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let c = client.read().await;
                c.send(Message::with_source(
                    &state.server_name,
                    Command::Pong,
                    vec![state.server_name.clone(), token.to_string()],
                ));
            }

            Command::Quit => {
                return false;
            }

            _ => {
                let c = client.read().await;
                c.send_numeric(
                    &state.server_name,
                    ERR_NOTREGISTERED,
                    vec!["You have not registered".into()],
                );
            }
        }

        if got_nick && got_user {
            return true;
        }
    }

    false
}

/// Send the welcome burst after registration.
async fn send_welcome(client: &Arc<RwLock<Client>>, state: &ServerState) {
    let c = client.read().await;
    let server = &state.server_name;

    c.send_numeric(
        server,
        RPL_WELCOME,
        vec![format!(
            "Welcome to the {} Internet Relay Chat Network {}",
            server,
            c.prefix()
        )],
    );

    c.send_numeric(
        server,
        RPL_YOURHOST,
        vec![format!(
            "Your host is {}, running version {}",
            server, state.version
        )],
    );

    c.send_numeric(
        server,
        RPL_CREATED,
        vec![format!(
            "This server was created {}",
            state.created_at.format("%a %b %d %Y at %H:%M:%S UTC")
        )],
    );

    c.send_numeric(
        server,
        RPL_MYINFO,
        vec![
            server.clone(),
            state.version.clone(),
            "iow".to_string(),
            "biklmnopstv".to_string(),
        ],
    );

    let tokens = state.isupport_tokens();
    for chunk in tokens.chunks(13) {
        let mut params: Vec<String> = chunk.to_vec();
        params.push("are supported by this server".to_string());
        c.send_numeric(server, RPL_ISUPPORT, params);
    }

    let clients = state.client_count();
    let channels = state.channel_count();

    c.send_numeric(
        server,
        RPL_LUSERCLIENT,
        vec![format!(
            "There are {clients} users and 0 invisible on 1 servers"
        )],
    );
    c.send_numeric(
        server,
        RPL_LUSEROP,
        vec!["0".into(), "operator(s) online".into()],
    );
    c.send_numeric(
        server,
        RPL_LUSERCHANNELS,
        vec![channels.to_string(), "channels formed".into()],
    );
    c.send_numeric(
        server,
        RPL_LUSERME,
        vec![format!("I have {clients} clients and 0 servers")],
    );

    if state.motd.is_empty() {
        c.send_numeric(server, ERR_NOMOTD, vec!["MOTD File is missing".into()]);
    } else {
        c.send_numeric(
            server,
            RPL_MOTDSTART,
            vec![format!("- {server} Message of the Day -")],
        );
        for line in &state.motd {
            c.send_numeric(server, RPL_MOTD, vec![format!("- {line}")]);
        }
        c.send_numeric(server, RPL_ENDOFMOTD, vec!["End of /MOTD command".into()]);
    }
}

/// Main message loop after registration.
async fn message_loop(
    stream: &mut (impl StreamExt<Item = Result<Message, irc_proto::codec::CodecError>> + Unpin),
    ctx: &HandlerContext,
) -> String {
    // Snapshot the disconnect_signal so we can select on it without
    // holding the client's RwLock across .await points.
    let disconnect_signal = ctx.client.read().await.disconnect_signal.clone();

    loop {
        tokio::select! {
            biased;
            _ = disconnect_signal.notified() => {
                let reason = ctx
                    .client
                    .read()
                    .await
                    .disconnect_reason
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take())
                    .unwrap_or_else(|| "Killed".to_string());
                return reason;
            }
            maybe = stream.next() => {
                let result = match maybe {
                    Some(r) => r,
                    None => return "Connection closed".to_string(),
                };

                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        debug!("codec error: {e}");
                        return format!("Read error: {e}");
                    }
                };

                if let Command::Quit = &msg.command {
                    return msg
                        .params
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Client quit".to_string());
                }

                {
                    let mut client = ctx.client.write().await;
                    client.last_active = chrono::Utc::now();
                }

                ctx.dispatch(&msg).await;
            }
        }
    }
}
