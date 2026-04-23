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
    let mut privs_count = 0;
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

        // 1c. If the user is an oper with a priv set, follow with
        // PRIVS so the remote side has the full state without waiting
        // for a steady-state PRIVS emission. Mirrors s_serv.c which
        // invokes client_send_privs for every bursted oper.
        if !client.privs.is_empty() {
            // Same packing rule as route_privs: flush at ~400 bytes.
            let mut line = format!("{our_numeric} PRIVS {client_numeric}");
            let base_len = line.len();
            for p in &client.privs {
                if line.len() + 1 + p.len() > 400 {
                    link.send_line(line.clone()).await;
                    privs_count += 1;
                    line.truncate(base_len);
                }
                line.push(' ');
                line.push_str(p);
            }
            if line.len() > base_len {
                link.send_line(line).await;
                privs_count += 1;
            }
        }

        // 1d. If the user is away, follow with A token so peers can
        // drive their own away-notify emissions from burst onwards
        // without waiting for a state change. Matches nefarious2
        // m_burst.c / s_serv.c which emit CMD_AWAY during burst.
        if let Some(ref away) = client.away_message {
            link.send_line(format!("{client_numeric} A :{away}")).await;
        }

        // 1e. If SILENCE_CHANMSGS is enabled, burst each local
        // user's silence list so remote peers can drop matching
        // channel messages at their end (otherwise we'd receive
        // the message and filter it locally, wasting link
        // bandwidth). Matches nefarious2 s_serv.c:331-360.
        // Each line carries up to ~400 bytes of comma-joined
        // entries (same chunking C uses) to stay under the 512
        // wire limit with room for the prefix and tags.
        if state.config.load().silence_chanmsgs() && !client.silence.is_empty() {
            let mut buf = String::new();
            for entry in &client.silence {
                let sigil = if entry.exception { "~" } else { "" };
                let piece = format!("+{sigil}{mask}", mask = entry.mask);
                if !buf.is_empty() && buf.len() + 1 + piece.len() > 400 {
                    link.send_line(format!("{client_numeric} U * {buf}")).await;
                    buf.clear();
                }
                if !buf.is_empty() {
                    buf.push(',');
                }
                buf.push_str(&piece);
            }
            if !buf.is_empty() {
                link.send_line(format!("{client_numeric} U * {buf}")).await;
            }
        }
    }

    info!(
        "burst: sent {nick_count} NICK lines ({privs_count} PRIVS); skipped {skipped_unregistered} unregistered + {skipped_no_numeric} missing-numeric"
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

        // Bans and ban-excepts share one `:%` trailing, with a bare `~`
        // token separating the two lists. Matches nefarious2
        // channel.c ms_burst_channel byte-for-byte:
        //   bans only   : ":%ban1 ban2"          (no space after %)
        //   both        : ":%ban1 ban2 ~ except1 except2"
        //   excepts only: ":% ~ except1 except2" (space after %, nothing
        //                                         between % and ~)
        // Peers that don't understand `~` keep consuming bans, so the
        // `~` token effectively hides excepts from them. Emit excepts
        // even when there are no bans, so the trailing always starts
        // with `:%` if either list has entries.
        if !chan.bans.is_empty() || !chan.excepts.is_empty() {
            line.push_str(" :%");
            let mut first = true;
            for ban in &chan.bans {
                if first {
                    line.push_str(&ban.mask);
                    first = false;
                } else {
                    line.push(' ');
                    line.push_str(&ban.mask);
                }
            }
            if !chan.excepts.is_empty() {
                line.push_str(" ~");
                for exc in &chan.excepts {
                    line.push(' ');
                    line.push_str(&exc.mask);
                }
            }
        }

        link.send_line(line).await;
        channel_count += 1;

        // 2b. Follow with TOPIC if the channel has one. Matches
        // nefarious2 m_burst.c:384 TOPIC_BURST behaviour — without
        // this, new peers see topic-less channels until the next
        // /TOPIC set. The 3-arg form (chan <chan_ts> <topic_ts>
        // :<topic>) is used when we don't track a specific setter
        // as a user; we store setter as a prefix string so use the
        // 4-arg form with our server name as setter when unknown.
        if let Some(ref topic) = chan.topic {
            let topic_ts = chan
                .topic_time
                .map(|t| t.timestamp() as u64)
                .unwrap_or(chan.created_ts);
            let setter = chan
                .topic_setter
                .clone()
                .unwrap_or_else(|| state.server_name.clone());
            let chan_ts = chan.created_ts;
            link.send_line(format!(
                "{our_numeric} T {name} {setter} {chan_ts} {topic_ts} :{topic}",
                name = chan.name,
            ))
            .await;
        }
    }
    info!("burst: sent {channel_count} channel BURST lines");

    // 3. Send all known global G-lines before EB so peers have the
    // full ban set before they start announcing users that could
    // match. Wire (nefarious2 gline.c gline_burst):
    //   <server_name> GL * [+/-]<mask> <expire_offset> <lastmod> <lifetime> :<reason>
    // We use origin=server_name (not numeric) because gline_burst
    // uses `&me` which serializes to the server name. Inactive
    // glines still go out so their state (and lastmod) replicates;
    // peers can then activate if their local state says so.
    let mut gline_count = 0;
    let now_secs = chrono::Utc::now().timestamp();
    for entry in state.glines.iter() {
        let gl = entry.value().read().await;
        // Skip entries with no lastmod — matches C gliter filter.
        if gl.lastmod == 0 {
            continue;
        }
        let sign = if gl.active { '+' } else { '-' };
        let expire_offset = match gl.expires_at {
            Some(exp) => (exp.timestamp() - now_secs).max(0),
            None => 0,
        };
        let lifetime = gl.lifetime.unwrap_or(0);
        link.send_line(format!(
            "{server} GL * {sign}{mask} {expire_offset} {lastmod} {lifetime} :{reason}",
            server = state.server_name,
            mask = gl.mask,
            lastmod = gl.lastmod,
            reason = gl.reason,
        ))
        .await;
        gline_count += 1;
    }
    if gline_count > 0 {
        info!("burst: sent {gline_count} GLINE entries");
    }

    // 3b. SHUNs share the same pattern as GLINEs — one SU per
    // stored entry. Same filter (lastmod > 0) applies.
    let mut shun_count = 0;
    for entry in state.shuns.iter() {
        let sh = entry.value().read().await;
        if sh.lastmod == 0 {
            continue;
        }
        let sign = if sh.active { '+' } else { '-' };
        let expire_offset = match sh.expires_at {
            Some(exp) => (exp.timestamp() - now_secs).max(0),
            None => 0,
        };
        let lifetime = sh.lifetime.unwrap_or(0);
        link.send_line(format!(
            "{server} SU * {sign}{mask} {expire_offset} {lastmod} {lifetime} :{reason}",
            server = state.server_name,
            mask = sh.mask,
            lastmod = sh.lastmod,
            reason = sh.reason,
        ))
        .await;
        shun_count += 1;
    }
    if shun_count > 0 {
        info!("burst: sent {shun_count} SHUN entries");
    }

    // 3c. ZLINEs — same shape as G-lines on the wire (no user@host
    // split, just a single mask field).
    let mut zline_count = 0;
    for entry in state.zlines.iter() {
        let zl = entry.value().read().await;
        if zl.lastmod == 0 {
            continue;
        }
        let sign = if zl.active { '+' } else { '-' };
        let expire_offset = match zl.expires_at {
            Some(exp) => (exp.timestamp() - now_secs).max(0),
            None => 0,
        };
        let lifetime = zl.lifetime.unwrap_or(0);
        link.send_line(format!(
            "{server} ZL * {sign}{mask} {expire_offset} {lastmod} {lifetime} :{reason}",
            server = state.server_name,
            mask = zl.mask,
            lastmod = zl.lastmod,
            reason = zl.reason,
        ))
        .await;
        zline_count += 1;
    }
    if zline_count > 0 {
        info!("burst: sent {zline_count} ZLINE entries");
    }

    // 3d. JUPEs — simpler wire shape (no lifetime, no user@host
    // split) but same position in the burst stream.
    let mut jupe_count = 0;
    for entry in state.jupes.iter() {
        let ju = entry.value().read().await;
        if ju.lastmod == 0 {
            continue;
        }
        let sign = if ju.active { '+' } else { '-' };
        let expire_offset = match ju.expires_at {
            Some(exp) => (exp.timestamp() - now_secs).max(0),
            None => 0,
        };
        link.send_line(format!(
            "{server_name} JU * {sign}{name} {expire_offset} {lastmod} :{reason}",
            server_name = state.server_name,
            name = ju.server,
            lastmod = ju.lastmod,
            reason = ju.reason,
        ))
        .await;
        jupe_count += 1;
    }
    if jupe_count > 0 {
        info!("burst: sent {jupe_count} JUPE entries");
    }

    // 4. Send END_OF_BURST
    let eb = format!("{} EB", our_numeric);
    link.send_line(eb).await;

    info!("burst sent to {}", link.name);
}
