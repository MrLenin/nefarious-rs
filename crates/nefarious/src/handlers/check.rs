//! /CHECK oper command — audit a user, channel, or server.
//!
//! Dispatches on the argument's shape:
//!   - starts with `#` or `&` → channel audit
//!   - looks like a hostname with `.` → server audit
//!   - otherwise → user audit (local first, then remote)
//!
//! Output is one NOTICE per line, prefixed with field labels so
//! opers can grep the results. Format is intentionally friendly to
//! `less` and `grep`; matches the spirit of nefarious2 m_check.c
//! without chasing its field-by-field ordering (that file is 1100+
//! lines of pretty-printing over every user/channel/server struct).

use irc_proto::Message;

use crate::numeric::*;

use super::HandlerContext;

pub async fn handle_check(ctx: &HandlerContext, msg: &Message) {
    let is_oper = ctx.client.read().await.modes.contains(&'o');
    if !is_oper {
        ctx.send_numeric(
            ERR_NOPRIVILEGES,
            vec!["Permission Denied - You're not an IRC operator".into()],
        )
        .await;
        return;
    }

    let target = match msg.params.first() {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            ctx.send_numeric(
                ERR_NEEDMOREPARAMS,
                vec!["CHECK".into(), "Not enough parameters".into()],
            )
            .await;
            return;
        }
    };

    if target.starts_with('#') || target.starts_with('&') {
        check_channel(ctx, &target).await;
    } else if target.contains('.')
        && ctx.state.find_client_by_nick(&target).is_none()
        && ctx.state.find_remote_by_nick(&target).is_none()
    {
        // `.`-style and not a nick we know → treat as server name.
        check_server(ctx, &target).await;
    } else {
        check_user(ctx, &target).await;
    }

    notice(ctx, &format!("End of /CHECK for {target}")).await;
}

async fn check_user(ctx: &HandlerContext, nick: &str) {
    // Local user → we have everything including idle and account.
    if let Some(arc) = ctx.state.find_client_by_nick(nick) {
        let c = arc.read().await;
        let idle = (chrono::Utc::now() - c.last_active).num_seconds().max(0);
        let prefix = c.prefix();
        let channels: Vec<String> = c.channels.iter().cloned().collect();
        let account = c.account.clone().unwrap_or_else(|| "*".into());
        let modes: String = c.modes.iter().collect();
        let tls = c.tls;
        let real_host = c.real_host.clone();
        let addr = c.addr;
        let geo = c.geoip.clone();
        let dnsbl_mark = c.dnsbl_mark.clone();
        drop(c);

        notice(ctx, &format!("USER   {prefix}")).await;
        notice(ctx, &format!("  real host: {real_host}")).await;
        notice(ctx, &format!("  address:   {addr}")).await;
        notice(ctx, &format!("  modes:     +{modes}")).await;
        notice(ctx, &format!("  tls:       {tls}")).await;
        notice(ctx, &format!("  account:   {account}")).await;
        notice(ctx, &format!("  idle:      {idle}s")).await;
        if let Some(g) = geo {
            notice(
                ctx,
                &format!(
                    "  geoip:     {} / {} ({})",
                    g.country_code, g.continent_code, g.country_name
                ),
            )
            .await;
        }
        if let Some(m) = dnsbl_mark {
            notice(ctx, &format!("  dnsbl:     {m}")).await;
        }
        notice(ctx, &format!("  channels:  {}", channels.join(" "))).await;
        return;
    }

    // Remote user → only what burst/NICK gave us.
    if let Some(arc) = ctx.state.find_remote_by_nick(nick) {
        let r = arc.read().await;
        let prefix = r.prefix();
        let account = r.account.clone().unwrap_or_else(|| "*".into());
        let server_name = ctx
            .state
            .remote_servers
            .get(&r.server)
            .map(|e| e.value().clone());
        let server_label = match server_name {
            Some(s) => s.read().await.name.clone(),
            None => format!("{}", r.server),
        };
        let modes: String = r.modes.iter().collect();
        let channels: Vec<String> = r.channels.iter().cloned().collect();
        drop(r);

        notice(ctx, &format!("USER   {prefix} (remote)")).await;
        notice(ctx, &format!("  server:    {server_label}")).await;
        notice(ctx, &format!("  modes:     +{modes}")).await;
        notice(ctx, &format!("  account:   {account}")).await;
        notice(ctx, &format!("  channels:  {}", channels.join(" "))).await;
        return;
    }

    notice(ctx, &format!("No user matches {nick}")).await;
}

async fn check_channel(ctx: &HandlerContext, name: &str) {
    let channel = match ctx.state.get_channel(name) {
        Some(c) => c,
        None => {
            notice(ctx, &format!("No channel matches {name}")).await;
            return;
        }
    };
    let chan = channel.read().await;

    let mode_str = chan.modes.to_mode_string();
    let local_members = chan.members.len();
    let remote_members = chan.remote_members.len();
    let bans = chan.bans.len();
    let excepts = chan.excepts.len();
    let topic = chan
        .topic
        .clone()
        .unwrap_or_else(|| "(none)".into());
    let topic_setter = chan
        .topic_setter
        .clone()
        .unwrap_or_else(|| "-".into());
    let created = chan.created_at.to_rfc3339();

    notice(ctx, &format!("CHANNEL {name}")).await;
    notice(ctx, &format!("  modes:     {mode_str}")).await;
    notice(ctx, &format!("  created:   {created}")).await;
    notice(ctx, &format!("  topic:     {topic}")).await;
    notice(ctx, &format!("  topic by:  {topic_setter}")).await;
    notice(ctx, &format!("  members:   {local_members} local, {remote_members} remote")).await;
    notice(ctx, &format!("  bans:      {bans}")).await;
    notice(ctx, &format!("  excepts:   {excepts}")).await;

    // Per-member lines so the oper can see who's op/voice and which
    // server each remote member belongs to.
    for (id, flags) in &chan.members {
        if let Some(arc) = ctx.state.clients.get(id) {
            let c = arc.read().await;
            let prefix = flags.highest_prefix();
            notice(ctx, &format!(
                "  MEMBER  {prefix}{nick} ({user}@{host}) [local]",
                nick = c.nick,
                user = c.user,
                host = c.host,
            ))
            .await;
        }
    }
    for (num, flags) in &chan.remote_members {
        if let Some(arc) = ctx.state.remote_clients.get(num) {
            let r = arc.read().await;
            if r.is_alias {
                continue;
            }
            let prefix = flags.highest_prefix();
            notice(ctx, &format!(
                "  MEMBER  {prefix}{nick} ({user}@{host}) [remote {num}]",
                nick = r.nick,
                user = r.user,
                host = r.host,
            ))
            .await;
        }
    }
}

async fn check_server(ctx: &HandlerContext, name: &str) {
    // Home server?
    if name.eq_ignore_ascii_case(&ctx.state.server_name) {
        let uptime = (chrono::Utc::now() - ctx.state.created_at).num_seconds().max(0);
        let clients = ctx.state.client_count();
        let remote = ctx.state.remote_clients.len();
        notice(ctx, &format!("SERVER {} (this server)", ctx.state.server_name)).await;
        notice(ctx, &format!("  numeric:   {}", ctx.state.numeric)).await;
        notice(ctx, &format!("  version:   {}", ctx.state.version)).await;
        notice(ctx, &format!("  uptime:    {uptime}s")).await;
        notice(ctx, &format!("  clients:   {clients} local, {remote} remote")).await;
        notice(ctx, &format!("  links:     {}", ctx.state.links.len())).await;
        return;
    }

    for entry in ctx.state.remote_servers.iter() {
        let s = entry.value().read().await;
        if s.name.eq_ignore_ascii_case(name) {
            let client_count = ctx
                .state
                .remote_clients
                .iter()
                .filter(|e| e.key().server == s.numeric)
                .count();
            notice(ctx, &format!("SERVER {}", s.name)).await;
            notice(ctx, &format!("  numeric:   {}", s.numeric)).await;
            notice(ctx, &format!("  uplink:    {}", s.uplink)).await;
            notice(ctx, &format!("  hops:      {}", s.hop_count)).await;
            notice(ctx, &format!("  clients:   {client_count}")).await;
            notice(ctx, &format!("  descr:     {}", s.description)).await;
            return;
        }
    }
    notice(ctx, &format!("No server matches {name}")).await;
}

async fn notice(ctx: &HandlerContext, text: &str) {
    let c = ctx.client.read().await;
    c.send(irc_proto::Message::with_source(
        &ctx.state.server_name,
        irc_proto::Command::Notice,
        vec![c.nick.clone(), text.to_string()],
    ));
}
