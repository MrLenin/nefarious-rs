use irc_proto::{Command, Message, irc_eq};

use crate::numeric::*;

use super::HandlerContext;

/// Handle NICK change for already-registered clients.
pub async fn handle_nick_change(ctx: &HandlerContext, msg: &Message) {
    let new_nick = match msg.params.first() {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            ctx.send_numeric(ERR_NONICKNAMEGIVEN, vec!["No nickname given".into()])
                .await;
            return;
        }
    };

    if !is_valid_nick(&new_nick) {
        ctx.send_numeric(
            ERR_ERRONEUSNICKNAME,
            vec![new_nick, "Erroneous nickname".into()],
        )
        .await;
        return;
    }

    let client_id = ctx.client_id().await;
    let old_prefix = ctx.prefix().await;
    let old_nick = ctx.nick().await;

    // Atomic reserve — closes the TOCTOU between "nick free?" and "take it".
    // try_reserve_nick is idempotent for the same id, so a case-only change
    // (e.g. Alice → alice) still succeeds.
    if !ctx.state.try_reserve_nick(&new_nick, client_id) {
        ctx.send_numeric(
            ERR_NICKNAMEINUSE,
            vec![new_nick, "Nickname is already in use".into()],
        )
        .await;
        return;
    }

    // Release the old reservation unless this is a case-only rename (same
    // casefolded key — the reservation we just made is the only entry).
    if !old_nick.is_empty() && !irc_eq(&old_nick, &new_nick) {
        ctx.state.release_nick(&old_nick, client_id);
    }

    // Update the nick on the Client struct. Capture the new nick_ts so
    // the S2S routing and any downstream burst use the same timestamp.
    let nick_ts = chrono::Utc::now().timestamp() as u64;
    {
        let mut client = ctx.client.write().await;
        client.nick = new_nick.clone();
        client.nick_ts = nick_ts;
    }

    // Propagate the nick change to the linked server.
    crate::s2s::routing::route_nick_change(&ctx.state, client_id, &new_nick, nick_ts).await;

    // Notify the client
    let nick_msg = Message::with_source(&old_prefix, Command::Nick, vec![new_nick.clone()]);

    // Notify all channels the client is in
    let channels: Vec<String> = {
        let client = ctx.client.read().await;
        client.channels.iter().cloned().collect()
    };

    let src = crate::tags::SourceInfo::from_local(&*ctx.client.read().await);

    // Send to the client themselves
    {
        let client = ctx.client.read().await;
        client.send_from(nick_msg.clone(), &src);
    }

    // Send to all channel members
    for chan_name in &channels {
        if let Some(channel) = ctx.state.get_channel(chan_name) {
            let chan = channel.read().await;
            for (&member_id, _) in &chan.members {
                if member_id == client_id {
                    continue;
                }
                if let Some(member) = ctx.state.clients.get(&member_id) {
                    let m = member.read().await;
                    m.send_from(nick_msg.clone(), &src);
                }
            }
        }
    }
}

/// Handle the AUTHENTICATE command — SASL negotiation surface.
///
/// Phase 2.8 ships the framework only: the mechanism negotiation is
/// accepted on the wire, but every authentication attempt is
/// rejected with ERR_SASLFAIL. Phase 3 will replace this with real
/// PLAIN / EXTERNAL / SCRAM implementations.
pub async fn handle_authenticate(ctx: &HandlerContext, msg: &Message) {
    // `AUTHENTICATE *` is the abort form. Acknowledge it cleanly.
    if msg.params.first().map(|s| s.as_str()) == Some("*") {
        ctx.send_numeric(
            crate::numeric::ERR_SASLABORTED,
            vec!["SASL authentication aborted".into()],
        )
        .await;
        return;
    }

    // Everything else is answered with SASL failure until Phase 3
    // wires the actual mechanism handlers.
    ctx.send_numeric(
        crate::numeric::ERR_SASLFAIL,
        vec!["SASL authentication failed".into()],
    )
    .await;
}

/// Handle the CAP command. Implements IRCv3 CAP negotiation (LS/REQ/
/// ACK/LIST/END) as specified by `nefarious2/ircd/m_cap.c` so a mixed
/// network can't observe any difference. Pre-registration CAP LS /
/// CAP REQ also flips `Client.cap_negotiating` so the main
/// `registration_phase` loop blocks from completing USER/NICK until
/// the client sends CAP END.
pub async fn handle_cap(ctx: &HandlerContext, msg: &Message) {
    use crate::capabilities::Capability;

    let subcmd = match msg.params.first() {
        Some(s) => s.to_ascii_uppercase(),
        None => return,
    };
    let server = ctx.server_name().to_string();

    // Client identifier used in the CAP reply: nick once registration
    // has set one, `*` before then. Matches nefarious2's
    // `BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr)` idiom.
    let target = {
        let c = ctx.client.read().await;
        if c.nick.is_empty() {
            "*".to_string()
        } else {
            c.nick.clone()
        }
    };

    match subcmd.as_str() {
        "LS" => {
            // CAP LS [<version>] — the client declares IRCv3 support
            // and asks for the advertised capabilities.
            let version: u16 = msg
                .params
                .get(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            {
                let mut c = ctx.client.write().await;
                c.cap_negotiating = true;
                c.cap_version = version;
            }
            send_cap_list(ctx, &server, &target, "LS", &advertised_list(ctx).await).await;
        }

        "LIST" => {
            // CAP LIST — mid-session introspection of enabled caps.
            let enabled: Vec<String> = {
                let c = ctx.client.read().await;
                c.enabled_caps.iter().map(|cap| cap.name().to_string()).collect()
            };
            send_cap_list(ctx, &server, &target, "LIST", &enabled).await;
        }

        "REQ" => {
            // CAP REQ :<cap1> [<cap2> ...] — atomic: either all caps
            // are advertised (ACK) or none are applied (NAK).
            let raw = msg.params.get(1).cloned().unwrap_or_default();
            let tokens: Vec<&str> = raw.split_whitespace().collect();

            // Mark negotiation as in-progress if we're pre-registration;
            // a client that jumps straight to REQ without LS is also
            // mid-CAP-handshake and must send END before we register them.
            {
                let mut c = ctx.client.write().await;
                if !c.is_registered() {
                    c.cap_negotiating = true;
                }
            }

            let mut to_enable: Vec<Capability> = Vec::with_capacity(tokens.len());
            let mut to_disable: Vec<Capability> = Vec::new();
            let mut rejected = false;
            for tok in &tokens {
                let (neg, name) = if let Some(stripped) = tok.strip_prefix('-') {
                    (true, stripped)
                } else {
                    (false, *tok)
                };
                let cap = match Capability::from_name(name) {
                    Some(c) => c,
                    None => {
                        rejected = true;
                        break;
                    }
                };
                if !neg && !ctx.state.advertised_caps.contains(&cap) {
                    rejected = true;
                    break;
                }
                if neg {
                    to_disable.push(cap);
                } else {
                    to_enable.push(cap);
                }
            }

            if rejected {
                ctx.client.read().await.send(Message::with_source(
                    &server,
                    Command::Cap,
                    vec![target.clone(), "NAK".into(), raw],
                ));
                return;
            }

            // Apply the full set atomically.
            {
                let mut c = ctx.client.write().await;
                for cap in &to_enable {
                    c.enabled_caps.insert(*cap);
                }
                for cap in &to_disable {
                    c.enabled_caps.remove(cap);
                }
            }

            // ACK echoes the original request verbatim so the client
            // knows which tokens (and in what order) were applied.
            ctx.client.read().await.send(Message::with_source(
                &server,
                Command::Cap,
                vec![target.clone(), "ACK".into(), raw],
            ));
        }

        "END" => {
            // CAP END closes negotiation. If the client has USER+NICK
            // already queued, the registration loop's check against
            // cap_negotiating will unblock and complete registration.
            let mut c = ctx.client.write().await;
            c.cap_negotiating = false;
        }

        "ACK" => {
            // Client-to-server ACK only applies to sticky caps that need
            // the client to confirm. We don't use sticky yet — no-op.
        }

        _ => {
            // Unknown subcommand — per IRCv3 we silently ignore. Some
            // servers reply with a standard error; nefarious2 stays quiet.
        }
    }
}

/// Build the list of currently-advertised capability tokens, with
/// `=<value>` metadata when the cap has any (e.g. `sasl=PLAIN,EXTERNAL`).
async fn advertised_list(ctx: &HandlerContext) -> Vec<String> {
    ctx.state
        .advertised_caps
        .iter()
        .map(|cap| match cap.ls_value() {
            Some(v) => format!("{}={v}", cap.name()),
            None => cap.name().to_string(),
        })
        .collect()
}

/// Send a CAP list reply (LS / LIST / ACK / NAK). For CAP 302+ long
/// outputs are split across multiple messages with a `*` marker
/// between parts; otherwise everything fits in a single line. 400 is a
/// conservative slice well under the 512-byte RFC limit.
const CAP_CHUNK_BYTES: usize = 400;

async fn send_cap_list(
    ctx: &HandlerContext,
    server: &str,
    target: &str,
    subcmd: &str,
    tokens: &[String],
) {
    let version = ctx.client.read().await.cap_version;
    let use_continuation = version >= 302 && tokens.len() > 1;

    if tokens.is_empty() {
        ctx.client.read().await.send(Message::with_source(
            server,
            Command::Cap,
            vec![target.to_string(), subcmd.to_string(), String::new()],
        ));
        return;
    }

    let mut buf = String::new();
    let mut pending: Vec<String> = Vec::new();
    for token in tokens {
        let added = if buf.is_empty() { token.len() } else { buf.len() + 1 + token.len() };
        if added > CAP_CHUNK_BYTES && !buf.is_empty() {
            pending.push(std::mem::take(&mut buf));
        }
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(token);
    }
    if !buf.is_empty() {
        pending.push(buf);
    }

    let last_idx = pending.len() - 1;
    for (i, chunk) in pending.into_iter().enumerate() {
        let mut params = vec![target.to_string(), subcmd.to_string()];
        if use_continuation && i != last_idx {
            params.push("*".into());
        }
        params.push(chunk);
        ctx.client.read().await.send(Message::with_source(
            server,
            Command::Cap,
            params,
        ));
    }
}

/// Validate a nickname.
pub fn is_valid_nick(nick: &str) -> bool {
    if nick.is_empty() || nick.len() > 30 {
        return false;
    }

    let first = nick.as_bytes()[0];
    // First character must be a letter or special
    if !first.is_ascii_alphabetic() && !is_nick_special(first) {
        return false;
    }

    // Rest can be letters, digits, special, or hyphens
    nick.bytes()
        .all(|b| b.is_ascii_alphanumeric() || is_nick_special(b) || b == b'-')
}

fn is_nick_special(b: u8) -> bool {
    // RFC 2812 special chars: [ ] \ ` _ ^ { | }
    matches!(b, b'[' | b']' | b'\\' | b'`' | b'_' | b'^' | b'{' | b'|' | b'}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_nicks() {
        assert!(is_valid_nick("nick"));
        assert!(is_valid_nick("Nick123"));
        assert!(is_valid_nick("[cool]"));
        assert!(is_valid_nick("nick-name"));
        assert!(is_valid_nick("_under"));
    }

    #[test]
    fn invalid_nicks() {
        assert!(!is_valid_nick(""));
        assert!(!is_valid_nick("123nick")); // starts with digit
        assert!(!is_valid_nick("-nick")); // starts with hyphen
        assert!(!is_valid_nick("nick name")); // space
        assert!(!is_valid_nick(&"a".repeat(31))); // too long
    }
}
