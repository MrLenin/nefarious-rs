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

    // Update the nick on the Client struct.
    {
        let mut client = ctx.client.write().await;
        client.nick = new_nick.clone();
    }

    // Propagate the nick change to the linked server.
    let nick_ts = chrono::Utc::now().timestamp() as u64;
    crate::s2s::routing::route_nick_change(&ctx.state, client_id, &new_nick, nick_ts).await;

    // Notify the client
    let nick_msg = Message::with_source(&old_prefix, Command::Nick, vec![new_nick.clone()]);

    // Notify all channels the client is in
    let channels: Vec<String> = {
        let client = ctx.client.read().await;
        client.channels.iter().cloned().collect()
    };

    // Send to the client themselves
    {
        let client = ctx.client.read().await;
        client.send(nick_msg.clone());
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
                    m.send(nick_msg.clone());
                }
            }
        }
    }
}

/// Handle CAP command (stub — just enough for clients to proceed).
pub async fn handle_cap(ctx: &HandlerContext, msg: &Message) {
    let subcmd = msg.params.first().map(|s| s.to_ascii_uppercase());

    match subcmd.as_deref() {
        Some("LS") => {
            // Advertise no capabilities for now
            let client = ctx.client.read().await;
            client.send(Message::with_source(
                ctx.server_name(),
                Command::Cap,
                vec!["*".into(), "LS".into(), "".into()],
            ));
        }
        Some("REQ") => {
            // Deny all capability requests for now
            let caps = msg.params.get(1).cloned().unwrap_or_default();
            let client = ctx.client.read().await;
            client.send(Message::with_source(
                ctx.server_name(),
                Command::Cap,
                vec!["*".into(), "NAK".into(), caps],
            ));
        }
        Some("END") => {
            // Client finished CAP negotiation — nothing to do
        }
        _ => {}
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
