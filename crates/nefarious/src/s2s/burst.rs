use tracing::{info, warn};

use p10_proto::numeric::ip_to_base64;

use crate::s2s::types::ServerLink;
use crate::state::ServerState;

/// Send our burst to a remote server: our users, channels, then END_OF_BURST.
pub async fn send_burst(state: &ServerState, link: &ServerLink) {
    let our_numeric = state.numeric.to_string();

    info!("sending burst to {}", link.name);

    // 1. Send NICK messages for all local users
    let mut nick_count = 0;
    let mut skipped_unregistered = 0;
    let mut skipped_no_numeric = 0;
    for entry in state.clients.iter() {
        let client = entry.value().read().await;
        if !client.is_registered() {
            skipped_unregistered += 1;
            continue;
        }

        // Each local client has an allocated 18-bit numeric; skip users
        // missing one (shouldn't happen for registered users, but be
        // defensive against a future refactor introducing a window).
        let Some(slot) = state.numeric_for(client.id) else {
            warn!(
                "burst: skipping registered client {nick} (id={id:?}) — no P10 numeric allocated",
                nick = client.nick,
                id = client.id
            );
            skipped_no_numeric += 1;
            continue;
        };
        let client_numeric = p10_proto::ClientNumeric {
            server: state.numeric,
            client: slot,
        };

        // Encode IP in the P10 wire form. `ip_to_base64` handles v4, v6,
        // and v4-mapped v6 correctly (matches nefarious2 iptobase64 with
        // v6_ok=1).
        let ip_encoded = ip_to_base64(client.addr.ip());

        // Format modes
        let modes: String = client.modes.iter().collect();
        let mode_str = if modes.is_empty() {
            String::new()
        } else {
            format!("+{modes}")
        };

        // N <nick> <hop> <nick_ts> <user> <host> [+<modes>] <ip> <numeric> :<realname>
        //
        // The `<numeric>` field is the 5-char combined YYXXX form
        // (2-char server numeric immediately followed by 3-char client
        // slot) in a SINGLE token. nefarious2 sends it via its
        // `NumNick()` macro joined with `%s%s`, and its `ms_nick`
        // parser reads it from `parv[parc-2]` as one field — splitting
        // across two whitespace-separated fields desyncs the position
        // of every later param, so the receiver ends up with just the
        // 3-char client slot in `parv[parc-2]`, can't resolve it to a
        // server, and silently drops the entire NICK line. That's how
        // our users never landed on the remote side.
        let nick_ts = client.nick_ts;
        let line = if mode_str.is_empty() {
            format!(
                "{our_numeric} N {nick} 1 {nick_ts} {user} {host} {ip_encoded} {client_numeric} :{realname}",
                nick = client.nick,
                user = client.user,
                host = client.host,
                realname = client.realname,
            )
        } else {
            format!(
                "{our_numeric} N {nick} 1 {nick_ts} {user} {host} {mode_str} {ip_encoded} {client_numeric} :{realname}",
                nick = client.nick,
                user = client.user,
                host = client.host,
                realname = client.realname,
            )
        };

        link.send_line(line).await;
        nick_count += 1;

        // 1b. If the user is logged in, follow the NICK with an AC
        // (ACCOUNT) token so the remote side records it. Matches
        // nefarious2/ircd/m_burst.c which sends ACCOUNT during burst
        // right after the corresponding NICK.
        if let Some(ref account) = client.account {
            link.send_line(format!(
                "{} AC {} R {} {}",
                our_numeric,
                client_numeric,
                account,
                client.nick_ts,
            ))
            .await;
        }
    }

    info!(
        "burst: sent {nick_count} NICK lines; skipped {skipped_unregistered} unregistered + {skipped_no_numeric} missing-numeric"
    );

    // 2. Send BURST messages for all channels with local members
    let mut channel_count = 0;
    for entry in state.channels.iter() {
        let chan = entry.value().read().await;

        if chan.members.is_empty() {
            continue;
        }

        // Build member list
        let mut members = Vec::new();
        for (&client_id, flags) in &chan.members {
            let Some(slot) = state.numeric_for(client_id) else {
                warn!(
                    "burst: #{chan} member id={id:?} has no P10 numeric — channel BURST will omit them",
                    chan = chan.name,
                    id = client_id
                );
                continue;
            };
            let client_numeric = p10_proto::ClientNumeric {
                server: state.numeric,
                client: slot,
            };
            let mut member_str = client_numeric.to_string();
            if flags.op {
                member_str.push_str(":o");
            } else if flags.voice {
                member_str.push_str(":v");
            }
            members.push(member_str);
        }

        let mode_str = chan.modes.to_mode_string();

        // B <channel> <create_ts> [+<modes>] [<members>]
        let mut line = format!(
            "{} B {} {}",
            our_numeric, chan.name, chan.created_ts
        );

        if mode_str != "+" {
            line.push(' ');
            line.push_str(&mode_str);
        }

        if !members.is_empty() {
            line.push(' ');
            line.push_str(&members.join(","));
        }

        // Add bans
        if !chan.bans.is_empty() {
            let ban_masks: Vec<&str> = chan.bans.iter().map(|b| b.mask.as_str()).collect();
            line.push_str(" :%");
            line.push_str(&ban_masks.join(" "));
        }

        link.send_line(line).await;
        channel_count += 1;
    }
    info!("burst: sent {channel_count} channel BURST lines");

    // 3. Send END_OF_BURST
    let eb = format!("{} EB", our_numeric);
    link.send_line(eb).await;

    info!("burst sent to {}", link.name);
}
