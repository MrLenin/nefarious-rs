use tracing::info;

use p10_proto::numeric::{capacity_to_base64, ipv4_to_base64};

use crate::s2s::types::ServerLink;
use crate::state::ServerState;

/// Send our burst to a remote server: our users, channels, then END_OF_BURST.
pub async fn send_burst(state: &ServerState, link: &ServerLink) {
    let our_numeric = state.numeric.to_string();

    info!("sending burst to {}", link.name);

    // 1. Send NICK messages for all local users
    for entry in state.clients.iter() {
        let client = entry.value().read().await;
        if !client.is_registered() {
            continue;
        }

        // Allocate a client numeric for this user
        // For simplicity, use the ClientId as the numeric index
        let client_numeric = p10_proto::ClientNumeric {
            server: state.numeric,
            client: client.id.0 as u32,
        };

        // Encode IP — use 127.0.0.1 as fallback for localhost connections
        let ip_encoded = if client.addr.ip().is_loopback() {
            ipv4_to_base64(std::net::Ipv4Addr::new(127, 0, 0, 1))
        } else {
            match client.addr.ip() {
                std::net::IpAddr::V4(v4) => ipv4_to_base64(v4),
                std::net::IpAddr::V6(_) => "AAAAAA".to_string(), // TODO: IPv6 encoding
            }
        };

        // Format modes
        let modes: String = client.modes.iter().collect();
        let mode_str = if modes.is_empty() {
            String::new()
        } else {
            format!("+{modes}")
        };

        // N <nick> <hop> <nick_ts> <user> <host> [+<modes>] <ip> <numeric> :<realname>
        let nick_ts = client.nick_ts;
        let line = if mode_str.is_empty() {
            format!(
                "{} N {} 1 {} {} {} {} {} {} :{}",
                our_numeric,
                client.nick,
                nick_ts,
                client.user,
                client.host,
                ip_encoded,
                state.numeric,
                p10_proto::inttobase64(client_numeric.client, 3),
                client.realname
            )
        } else {
            format!(
                "{} N {} 1 {} {} {} {} {} {} {} :{}",
                our_numeric,
                client.nick,
                nick_ts,
                client.user,
                client.host,
                mode_str,
                ip_encoded,
                state.numeric,
                p10_proto::inttobase64(client_numeric.client, 3),
                client.realname
            )
        };

        link.send_line(line).await;
    }

    // 2. Send BURST messages for all channels with local members
    for entry in state.channels.iter() {
        let chan = entry.value().read().await;

        if chan.members.is_empty() {
            continue;
        }

        // Build member list
        let mut members = Vec::new();
        for (&client_id, flags) in &chan.members {
            let client_numeric = p10_proto::ClientNumeric {
                server: state.numeric,
                client: client_id.0 as u32,
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
    }

    // 3. Send END_OF_BURST
    let eb = format!("{} EB", our_numeric);
    link.send_line(eb).await;

    info!("burst sent to {}", link.name);
}
