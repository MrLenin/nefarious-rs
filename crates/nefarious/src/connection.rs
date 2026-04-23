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

/// Pick the first Client config block matching this peer's
/// ip/host and, if it has a password, compare against the stashed
/// PASS. Returns `Some(reason)` when the match is refused, `None`
/// when authentication passes (either a password-protected block
/// accepted or no password was required).
fn check_client_block_password(
    clients: &[irc_config::ClientConfig],
    ip: &str,
    host: &str,
    presented: Option<&str>,
) -> Option<String> {
    for block in clients {
        let ip_match = block.ip == "*"
            || crate::channel::wildcard_match(&block.ip, ip);
        let host_match = match &block.host {
            Some(pat) => crate::channel::wildcard_match(pat, host),
            None => true,
        };
        if !(ip_match && host_match) {
            continue;
        }
        match &block.password {
            None => return None, // match, no password required
            Some(required) => {
                return match presented {
                    Some(p) if crate::password::verify(p, required) => None,
                    Some(_) => Some("Invalid password".into()),
                    None => Some("Password required".into()),
                };
            }
        }
    }
    // No Client block matched — allow through for now. A future
    // FEAT_DENY_UNKNOWN_CLIENT can flip this to a refusal.
    None
}

/// Search config Kill blocks for one matching `user_host` or `ip`.
/// Either field being empty counts as a wildcard — a block with only
/// `host` matches by user@host, only `ip` matches by IP, both
/// require both to match. Returns the first matching KillConfig so
/// the caller can log which rule fired. Both `host` and `ip` fields
/// accept the shared GLINE-style mask syntax: glob, numeric IP, or
/// CIDR on the host side and glob/IP/CIDR on the ip side.
fn match_kill_config<'a>(
    kills: &'a [irc_config::KillConfig],
    user: &str,
    host: &str,
    ip: std::net::IpAddr,
) -> Option<&'a irc_config::KillConfig> {
    for kill in kills {
        let host_match = kill.host == "*"
            || crate::gline::user_host_mask_matches(&kill.host, user, host, ip);
        let ip_match = match &kill.ip {
            Some(pattern) => crate::gline::ip_mask_matches(pattern, ip),
            None => true,
        };
        if host_match && ip_match {
            return Some(kill);
        }
    }
    None
}

/// Handle a client connection over any async stream (plain TCP or TLS).
pub async fn handle_connection<S>(
    stream: S,
    addr: SocketAddr,
    state: Arc<ServerState>,
    tls: bool,
    listener_port: u16,
    tls_cert_cn: Option<String>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        "new connection from {addr} on port {listener_port} (tls={tls}, cert_cn={})",
        tls_cert_cn.as_deref().unwrap_or("-")
    );

    // Rate limit: refuse the connection up front if this IP has
    // burned through FEAT_IPCHECK_CLONE_LIMIT connects within the
    // configured window. The socket closes before any state is
    // allocated so a determined attacker gets as little resource
    // consumption as we can manage. Loopback is always allowed so
    // local tooling and health checks don't hit the cap.
    let limit = state.config.load().ipcheck_clone_limit();
    let period = std::time::Duration::from_secs(state.config.load().ipcheck_clone_period());
    if let Err(count) = state.ipcheck.record(addr.ip(), limit, period) {
        tracing::warn!(
            "refusing connection from {addr}: IPcheck clone limit ({limit}) exceeded \
             (count={count}, period={}s)",
            period.as_secs()
        );
        return;
    }

    // Create the message channel for outbound messages
    let (tx, mut rx) = mpsc::channel::<Message>(256);

    let client = Arc::new(RwLock::new(Client::new(addr, tls, listener_port, tx)));
    {
        let mut c = client.write().await;
        c.tls_cert_cn = tls_cert_cn;
    }
    let client_id = client.read().await.id;

    // Reserve a P10 client numeric up front so every registered user has
    // a valid wire id. If the 18-bit slot space is full, refuse the
    // connection — matches the C server's behaviour.
    if state.try_allocate_numeric(client_id).is_none() {
        tracing::error!(
            "refusing connection from {addr}: P10 numeric allocator exhausted"
        );
        return;
    }

    // Kick off a reverse-DNS lookup in the background. The task updates
    // Client.host on success before the user finishes registering, or
    // sends a "Couldn't look up" notice on failure. Matches
    // nefarious2/ircd/ircd_res.c but uses hickory-resolver.
    if let Some(ref resolver) = state.dns_resolver {
        crate::dns::spawn_reverse_lookup(
            Arc::clone(resolver),
            state.server_name.clone(),
            Arc::clone(&client),
            addr.ip(),
        );
    }

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
        // Release any nick reserved during the aborted registration and
        // return the P10 numeric to the pool.
        let (id, nick) = {
            let c = client.read().await;
            (c.id, c.nick.clone())
        };
        if !nick.is_empty() {
            state.release_nick(&nick, id);
        }
        state.release_numeric(id);
        state.ipcheck.release(addr.ip());
        debug!("client {addr} disconnected during registration");
        writer_handle.abort();
        return;
    }

    let client_id = client.read().await.id;
    let nick = client.read().await.nick.clone();

    // Client-block password gate. If any Client {} config block
    // matches this peer (by ip or host glob) and has a password
    // set, the client must have sent a matching PASS during
    // registration. A matching block without a password allows
    // through; no matching block at all also allows through (the
    // strict "deny without I-line" mode is a separate feature
    // flag we haven't wired yet).
    let pass_fail = {
        let c = client.read().await;
        let ip = c.addr.ip().to_string();
        let host = c.host.clone();
        let pass = c.pass.clone();
        drop(c);
        check_client_block_password(&state.config.load().clients, &ip, &host, pass.as_deref())
    };
    if let Some(reason) = pass_fail {
        info!("refusing registration of {nick} ({addr}): {reason}");
        let (id, nick_for_release) = {
            let c = client.read().await;
            (c.id, c.nick.clone())
        };
        let c = client.read().await;
        c.send_raw(irc_proto::Message::with_source(
            &state.server_name,
            irc_proto::Command::Error,
            vec![format!("Closing Link: {nick} [{reason}]")],
        ));
        drop(c);
        if !nick_for_release.is_empty() {
            state.release_nick(&nick_for_release, id);
        }
        state.release_numeric(id);
        state.ipcheck.release(addr.ip());
        writer_handle.abort();
        return;
    }

    // Wipe the stashed password now that authentication is done.
    // Keeping it in memory longer than necessary is a needless
    // exposure if anything later spills client state (debug dumps,
    // stats, etc).
    client.write().await.pass = None;

    // Network-ban gates. Happen *after* nick/USER are parsed so we
    // have `user` + a resolved hostname, but *before* we tell the
    // network about the client — a banned user never gets a numeric
    // announced on the wire and never touches the channel graph,
    // matching register_user() in nefarious2 s_user.c.
    //
    // Three checks run in sequence: ZLINE (IP match), then local
    // K-lines from the config file, then GLINE (user@host). K-lines
    // fall between ZLINE and GLINE because they're local-authored
    // but can still match on user@host patterns the operator baked
    // into the config.
    let ban_match = {
        let c = client.read().await;
        let ip = c.addr.ip();
        let user = c.user.clone();
        let host = c.host.clone();
        drop(c);
        if let Some((mask, reason)) = state.find_matching_zline(ip).await {
            Some(("Z-lined", mask, reason))
        } else if let Some(kill) = match_kill_config(&state.config.load().kills, &user, &host, ip) {
            Some(("K-lined", kill.host.clone(), kill.reason.clone()))
        } else if let Some((mask, reason)) =
            state.find_matching_gline(&user, &host, ip).await
        {
            Some(("G-lined", mask, reason))
        } else {
            None
        }
    };
    if let Some((kind, mask, reason)) = ban_match {
        info!("refusing registration of {nick} ({addr}): {kind} by {mask}");
        let (id, nick_for_release) = {
            let c = client.read().await;
            (c.id, c.nick.clone())
        };
        let c = client.read().await;
        c.send_raw(irc_proto::Message::with_source(
            &state.server_name,
            irc_proto::Command::Error,
            vec![format!("Closing Link: {nick} [{kind} ({reason})]")],
        ));
        drop(c);
        if !nick_for_release.is_empty() {
            state.release_nick(&nick_for_release, id);
        }
        state.release_numeric(id);
        state.ipcheck.release(addr.ip());
        writer_handle.abort();
        return;
    }

    // DNSBL check. Happens after all the ban gates so we don't burn
    // DNS queries on clients we'd refuse anyway. Fails open: if
    // every zone times out or resolves nothing, the client goes
    // through unmarked. A Block / BlockAnon hit refuses the
    // connection; Mark hits tag the Client for oper visibility.
    let dnsbl_blocks = state.config.load().dnsbl.clone();
    if !dnsbl_blocks.is_empty() {
        if let Some(resolver) = state.dns_resolver.as_ref() {
            let ip = client.read().await.addr.ip();
            let is_account = client.read().await.account.is_some();
            let outcome = crate::dnsbl::check_all(
                Arc::clone(resolver),
                ip,
                dnsbl_blocks,
                is_account,
            )
            .await;
            if let Some(crate::dnsbl::DnsBlOutcome::Hit { action, reason, zone }) = outcome {
                use irc_config::DnsBlAction;
                match action {
                    DnsBlAction::Block | DnsBlAction::BlockAnon => {
                        info!(
                            "refusing registration of {nick} ({addr}): DNSBL {zone} ({reason})"
                        );
                        let (id, nick_for_release) = {
                            let c = client.read().await;
                            (c.id, c.nick.clone())
                        };
                        let c = client.read().await;
                        c.send_raw(irc_proto::Message::with_source(
                            &state.server_name,
                            irc_proto::Command::Error,
                            vec![format!("Closing Link: {nick} [DNSBL: {reason}]")],
                        ));
                        drop(c);
                        if !nick_for_release.is_empty() {
                            state.release_nick(&nick_for_release, id);
                        }
                        state.release_numeric(id);
                        state.ipcheck.release(addr.ip());
                        writer_handle.abort();
                        return;
                    }
                    DnsBlAction::Mark => {
                        client.write().await.dnsbl_mark = Some(format!("{zone}: {reason}"));
                    }
                    DnsBlAction::Whitelist => {
                        // Unreachable: check_all collapses
                        // whitelists into a no-op return.
                    }
                }
            }
        }
    }

    info!("client {nick} ({addr}) registered");

    // Server notice to +s opers if the feature flag is on.
    if state.config.load().connexit_notices() {
        let (user, host, realname) = {
            let c = client.read().await;
            (c.user.clone(), c.host.clone(), c.realname.clone())
        };
        state
            .snotice(&format!(
                "Client connecting: {nick} ({user}@{host}) [{addr}] {{{realname}}}"
            ))
            .await;
    }

    // Register in global state
    state.register_client(Arc::clone(&client), &nick).await;

    // Introduce the client to every active S2S link. Without this,
    // registrations that happen after the link is up are invisible
    // to peers until the next burst — a hard desync since the peer
    // never learns the user exists, can't route to them, and will
    // emit nick-collision KILLs if the same nick appears elsewhere.
    crate::s2s::routing::route_nick_intro(&state, &client).await;

    // IRCv3 MONITOR: notify watchers that this nick just came
    // online. Prefix is built from the just-registered client.
    {
        let c = client.read().await;
        let prefix = c.prefix();
        drop(c);
        state.notify_monitor_online(&nick, &prefix).await;
    }

    // Send welcome burst
    send_welcome(&client, &state).await;

    // Main message loop
    let ctx = HandlerContext::new(Arc::clone(&state), Arc::clone(&client));

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
    let src = crate::tags::SourceInfo::from_local(&*client.read().await);

    // Route QUIT to S2S
    crate::s2s::routing::route_quit(&state, client_id, &quit_reason, &src).await;

    for chan_name in &channels {
        if let Some(channel) = state.get_channel(chan_name) {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if member_id == client_id {
                    continue;
                }
                if let Some(member) = state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(quit_msg.clone(), &src);
                }
            }
        }
    }

    // Server notice to +s opers if feature flag is on.
    if state.config.load().connexit_notices() {
        state
            .snotice(&format!(
                "Client exiting: {nick} [{addr}] ({quit_reason})"
            ))
            .await;
    }

    // Remove from state
    state.remove_client(client_id).await;
    state.ipcheck.release(addr.ip());
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

    let ctx = HandlerContext::new(Arc::clone(state), Arc::clone(client));

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
                // Stash the password — enforcement happens at the
                // end of registration against the matching Client
                // config block. Accept multiple PASS commands; the
                // most recent wins (matches ircu's semantics).
                if let Some(pass) = msg.params.first() {
                    let mut c = client.write().await;
                    c.pass = Some(pass.clone());
                }
            }

            Command::Webirc => {
                // WEBIRC <password> <gateway_name> <real_host> <real_ip> [<options>]
                // Only accepted during registration, before USER completes —
                // matches nefarious2 m_webirc.c's mr_webirc. A successful
                // WEBIRC rewrites the client's IP and host so the rest of
                // the register path (ban checks, reverse DNS) sees the
                // actual user rather than the gateway.
                if msg.params.len() < 4 {
                    let c = client.read().await;
                    c.send_numeric(
                        &state.server_name,
                        ERR_NEEDMOREPARAMS,
                        vec!["WEBIRC".into(), "Not enough parameters".into()],
                    );
                    continue;
                }
                let presented_pass = &msg.params[0];
                let _gateway = &msg.params[1];
                let real_host = &msg.params[2];
                let real_ip = &msg.params[3];
                let peer_ip = client.read().await.addr.ip().to_string();

                // Match against configured WebIRC blocks. First entry
                // whose host ACL matches the peer AND whose password
                // matches wins.
                let cfg = state.config.load();
                let matched = cfg.webirc.iter().find(|w| {
                    let host_ok = match &w.host {
                        Some(pat) => {
                            crate::channel::wildcard_match(pat, &peer_ip)
                        }
                        None => true,
                    };
                    host_ok && crate::password::verify(presented_pass, &w.password)
                });
                if matched.is_none() {
                    let c = client.read().await;
                    c.send_raw(Message::with_source(
                        &state.server_name,
                        Command::Error,
                        vec![format!(
                            "Closing Link: [{peer_ip}] (WEBIRC authentication failed)"
                        )],
                    ));
                    return false;
                }

                // Rewrite: parse the real IP, overwrite addr and host.
                match real_ip.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        let mut c = client.write().await;
                        // Port is preserved — only the IP changes. The
                        // host gets replaced with whatever the gateway
                        // passed; we don't kick off a fresh reverse DNS
                        // because the gateway is authoritative.
                        c.addr =
                            std::net::SocketAddr::new(ip, c.addr.port());
                        c.host = real_host.clone();
                        c.real_host = real_host.clone();
                        info!(
                            "WEBIRC: {peer_ip} → {ip} (host {real_host})"
                        );
                    }
                    Err(_) => {
                        let c = client.read().await;
                        c.send_raw(Message::with_source(
                            &state.server_name,
                            Command::Error,
                            vec![format!(
                                "Closing Link: [{peer_ip}] (WEBIRC malformed IP)"
                            )],
                        ));
                        return false;
                    }
                }
            }

            Command::Authenticate => {
                // SASL exchange happens during CAP negotiation, before
                // NICK+USER are allowed to complete registration. Route
                // to the same handler used post-registration.
                crate::handlers::registration::handle_authenticate(&ctx, &msg).await;
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
            // Hold registration open while IRCv3 CAP negotiation is in
            // progress — the client must send CAP END before we can
            // send the welcome burst. Without this gate, CAP LS / REQ
            // would race the welcome and capabilities that gate
            // registration (notably SASL) wouldn't work at all.
            if !client.read().await.cap_negotiating {
                return true;
            }
        }
    }

    false
}

/// Send the welcome burst after registration.
async fn send_welcome(client: &Arc<RwLock<Client>>, state: &ServerState) {
    let c = client.read().await;
    let server = &state.server_name;

    // RPL_WELCOME greets with just the nick, not the full
    // nick!user@host prefix. Matches nefarious2 s_err.c format:
    //   ":Welcome to the %s IRC Network, %s"
    c.send_numeric(
        server,
        RPL_WELCOME,
        vec![format!(
            "Welcome to the {} IRC Network, {}",
            state.config.load().network(),
            c.nick,
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

    // RPL_MYINFO shape matches nefarious2 s_err.c: five params —
    // server, version, user modes, channel modes, channel modes
    // that take params. Clients (older ones especially) read this
    // to figure out what MODE chars need arguments when parsing
    // mode strings; missing or short fields here cascade into
    // parse bugs client-side.
    //
    // Sources: client.h infousermodes / channel.h infochanmodes /
    // channel.h infochanmodeswithparams.
    c.send_numeric(
        server,
        RPL_MYINFO,
        vec![
            server.clone(),
            state.version.clone(),
            "abdgiknoqswxyzBDHLMNORWXY".to_string(),
            "abCcDdhHikLlMmNnOopPQRrSsTtvZz".to_string(),
            "bhkLlov".to_string(),
        ],
    );

    let tokens = state.isupport_tokens();
    for chunk in tokens.chunks(13) {
        let mut params: Vec<String> = chunk.to_vec();
        params.push("are supported by this server".to_string());
        c.send_numeric(server, RPL_ISUPPORT, params);
    }

    // Drop the read lock before delegating to send_lusers — it wants its
    // own lock and we'd deadlock holding one.
    drop(c);
    crate::handlers::query::send_lusers(Arc::clone(client), state).await;
    let c = client.read().await;

    let motd = state.motd.read().expect("motd lock poisoned").clone();
    if motd.is_empty() {
        c.send_numeric(server, ERR_NOMOTD, vec!["MOTD File is missing".into()]);
    } else {
        c.send_numeric(
            server,
            RPL_MOTDSTART,
            vec![format!("- {server} Message of the Day -")],
        );
        for line in &motd {
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

    // Ping-timer tick period. A tick every 15s gives us sub-30s
    // resolution on the idle check without burning many wakeups.
    // The actual PINGFREQ / CONNECTTIMEOUT thresholds come from
    // config and are re-read every tick so a /REHASH picks them up.
    let mut ping_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Whether we've sent a PING waiting for PONG. Cleared whenever
    // the client produces any inbound message (last_active bumped).
    let mut ping_pending_since: Option<chrono::DateTime<chrono::Utc>> = None;

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
            _ = ping_tick.tick() => {
                let cfg = ctx.state.config.load();
                let ping_freq = cfg.ping_freq();
                let timeout = cfg.connect_timeout();
                drop(cfg);
                let (last_active, nick) = {
                    let c = ctx.client.read().await;
                    (c.last_active, c.nick.clone())
                };
                let now = chrono::Utc::now();
                let idle = (now - last_active).num_seconds().max(0) as u64;

                if let Some(sent_at) = ping_pending_since {
                    // Already pinged — if they haven't answered in
                    // CONNECTTIMEOUT seconds, drop them.
                    let waited = (now - sent_at).num_seconds().max(0) as u64;
                    if waited >= timeout {
                        debug!("ping timeout for {nick} after {waited}s");
                        return format!("Ping timeout: {waited} seconds");
                    }
                } else if idle >= ping_freq {
                    // Idle long enough to warrant a probe. Send PING
                    // and record the moment so the next tick can
                    // measure waited-for-PONG against timeout.
                    let server = ctx.state.server_name.clone();
                    let c = ctx.client.read().await;
                    c.send_raw(Message::with_source(
                        &server,
                        Command::Ping,
                        vec![server.clone()],
                    ));
                    drop(c);
                    ping_pending_since = Some(now);
                }
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
                // Any inbound message — PONG included — counts as
                // liveness. Clear the pending-ping marker so the
                // timeout clock resets.
                ping_pending_since = None;

                ctx.dispatch(&msg).await;
            }
        }
    }
}
