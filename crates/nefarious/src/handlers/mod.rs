pub mod channel;
pub mod messaging;
pub mod mode;
pub mod query;
pub mod registration;
pub mod server_query;

use std::sync::Arc;

use irc_proto::message::Tag;
use irc_proto::{Command, Message};
use tokio::sync::RwLock;
use tracing::debug;

use crate::capabilities::Capability;
use crate::client::Client;
use crate::numeric::*;
use crate::state::ServerState;

/// Context for handling a message from a registered client.
///
/// `current_batch` is populated while the handler is executing inside a
/// labeled-response batch so every reply attaches `@batch=<id>` and the
/// encompassing `BATCH +<id>` / `BATCH -<id>` pair is emitted around the
/// handler.
pub struct HandlerContext {
    pub state: Arc<ServerState>,
    pub client: Arc<RwLock<Client>>,
    pub current_batch: Option<String>,
}

impl HandlerContext {
    /// Create a fresh context for a connection (no active batch).
    pub fn new(state: Arc<ServerState>, client: Arc<RwLock<Client>>) -> Self {
        Self {
            state,
            client,
            current_batch: None,
        }
    }

    /// Dispatch a message to the appropriate handler.
    ///
    /// Before dispatching, inspect the inbound message for `@label=...`
    /// and, if the sending client has `labeled-response` enabled, wrap
    /// the handler's replies in a `BATCH +id labeled-response` / `-id`
    /// pair. The inner handlers receive a context with `current_batch`
    /// set so `ctx.send_numeric` / `ctx.reply` tag each reply with
    /// `@batch=id` automatically.
    pub async fn dispatch(&self, msg: &Message) {
        let label = msg
            .tags
            .iter()
            .find(|t| t.key == "label")
            .and_then(|t| t.value.clone());

        let use_batch = if let Some(ref _lbl) = label {
            self.client.read().await.has_cap(Capability::LabeledResponse)
        } else {
            false
        };

        let batch_id = if use_batch {
            let id = self.client.read().await.next_batch_id();
            // Emit `@label=lbl :server BATCH +id labeled-response`. The
            // BATCH open is the only message that carries the @label
            // tag; each enclosed reply carries @batch=<id>.
            let mut open = Message::with_source(
                &self.state.server_name,
                Command::Batch,
                vec![format!("+{id}"), "labeled-response".into()],
            );
            if let Some(ref lbl) = label {
                open.tags.push(Tag {
                    key: "label".to_string(),
                    value: Some(lbl.clone()),
                });
            }
            self.client.read().await.send(open);
            Some(id)
        } else {
            None
        };

        let ctx = HandlerContext {
            state: Arc::clone(&self.state),
            client: Arc::clone(&self.client),
            current_batch: batch_id.clone(),
        };

        match &msg.command {
            // Messaging
            Command::Privmsg => messaging::handle_privmsg(&ctx, msg).await,
            Command::Notice => messaging::handle_notice(&ctx, msg).await,

            // Channel operations
            Command::Join => channel::handle_join(&ctx, msg).await,
            Command::Part => channel::handle_part(&ctx, msg).await,
            Command::Topic => channel::handle_topic(&ctx, msg).await,
            Command::Kick => channel::handle_kick(&ctx, msg).await,
            Command::Invite => channel::handle_invite(&ctx, msg).await,
            Command::Names => channel::handle_names(&ctx, msg).await,
            Command::List => channel::handle_list(&ctx, msg).await,

            // Modes
            Command::Mode => mode::handle_mode(&ctx, msg).await,

            // Queries
            Command::Who => query::handle_who(&ctx, msg).await,
            Command::Whois => query::handle_whois(&ctx, msg).await,
            Command::Motd => query::handle_motd(&ctx, msg).await,
            Command::Lusers => query::handle_lusers(&ctx, msg).await,
            Command::Version => query::handle_version(&ctx, msg).await,
            Command::Away => query::handle_away(&ctx, msg).await,
            Command::Userhost => query::handle_userhost(&ctx, msg).await,
            Command::Ison => query::handle_ison(&ctx, msg).await,
            Command::Oper => query::handle_oper(&ctx, msg).await,

            // IRCv3 identity-change commands
            Command::Setname => query::handle_setname(&ctx, msg).await,
            Command::Chghost => query::handle_chghost(&ctx, msg).await,

            // Server queries
            Command::Stats => server_query::handle_stats(&ctx, msg).await,
            Command::Time => server_query::handle_time(&ctx, msg).await,
            Command::Admin => server_query::handle_admin(&ctx, msg).await,
            Command::Info => server_query::handle_info(&ctx, msg).await,
            Command::Links => server_query::handle_links(&ctx, msg).await,
            Command::Map => server_query::handle_map(&ctx, msg).await,
            Command::Trace => server_query::handle_trace(&ctx, msg).await,

            // Wallops (operator broadcast)
            Command::Wallops => messaging::handle_wallops(&ctx, msg).await,

            // Registration (nick change after registration)
            Command::Nick => registration::handle_nick_change(&ctx, msg).await,

            // PING/PONG
            Command::Ping => {
                let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let reply = Message::with_source(
                    &ctx.state.server_name,
                    Command::Pong,
                    vec![ctx.state.server_name.clone(), token.to_string()],
                );
                ctx.reply(reply).await;
            }
            Command::Pong => {
                // Client responded to our PING — update last_active
                let mut client = ctx.client.write().await;
                client.last_active = chrono::Utc::now();
            }

            // QUIT is handled in the connection loop, not here
            Command::Quit => {}

            // CAP
            Command::Cap => registration::handle_cap(&ctx, msg).await,
            // AUTHENTICATE — SASL surface, mechanisms stubbed until
            // Phase 3. Accepted during both pre- and post-registration
            // so clients can negotiate SASL as part of CAP.
            Command::Authenticate => registration::handle_authenticate(&ctx, msg).await,

            // Unknown
            Command::Unknown(cmd) => {
                debug!("unknown command from client: {cmd}");
                ctx.send_numeric(
                    ERR_UNKNOWNCOMMAND,
                    vec![cmd.clone(), "Unknown command".to_string()],
                )
                .await;
            }

            // Other known commands we haven't implemented yet
            _ => {
                ctx.send_numeric(
                    ERR_UNKNOWNCOMMAND,
                    vec![msg.command.to_string(), "Not yet implemented".to_string()],
                )
                .await;
            }
        }

        // Close the labeled-response batch, if we opened one.
        if let Some(id) = batch_id {
            let close = Message::with_source(
                &self.state.server_name,
                Command::Batch,
                vec![format!("-{id}")],
            );
            self.client.read().await.send(close);
        }
    }

    /// Helper: read client nick.
    pub async fn nick(&self) -> String {
        self.client.read().await.nick.clone()
    }

    /// Helper: read client prefix.
    pub async fn prefix(&self) -> String {
        self.client.read().await.prefix()
    }

    /// Helper: read client id.
    pub async fn client_id(&self) -> crate::client::ClientId {
        self.client.read().await.id
    }

    /// Helper: server name.
    pub fn server_name(&self) -> &str {
        &self.state.server_name
    }

    /// Apply IRCv3 reply-path tags to `msg` before sending it to the
    /// requesting client: `@time` if they have `server-time`, and
    /// `@batch=<id>` if we're inside a labeled-response batch.
    pub fn apply_reply_tags(&self, msg: &mut Message, client: &Client) {
        if client.has_cap(Capability::ServerTime) {
            msg.tags.push(Tag {
                key: "time".to_string(),
                value: Some(crate::tags::format_server_time(chrono::Utc::now())),
            });
        }
        if let Some(ref id) = self.current_batch {
            msg.tags.push(Tag {
                key: "batch".to_string(),
                value: Some(id.clone()),
            });
        }
    }

    /// Send a server-originated reply message to the requesting client,
    /// attaching the reply-path tags (server-time + batch) first.
    pub async fn reply(&self, mut msg: Message) {
        let client = self.client.read().await;
        self.apply_reply_tags(&mut msg, &client);
        client.send(msg);
    }

    /// Send a user-originated reply (notably an `echo-message` self-copy
    /// of a PRIVMSG/NOTICE) to the requesting client. Attaches
    /// @server-time and @account via `tagged_for`, plus @batch if we're
    /// inside a labeled-response batch. Deduplicated so @time isn't
    /// attached twice.
    pub async fn reply_from(&self, msg: Message, src: &crate::tags::SourceInfo) {
        let client = self.client.read().await;
        let mut out = crate::tags::tagged_for(msg, &client, src);
        if let Some(ref id) = self.current_batch {
            out.tags.push(Tag {
                key: "batch".to_string(),
                value: Some(id.clone()),
            });
        }
        client.send(out);
    }

    /// Send a numeric to the client with reply-path tags applied.
    pub async fn send_numeric(&self, numeric: u16, params: Vec<String>) {
        let client = self.client.read().await;
        let mut full_params = vec![client.nick.clone()];
        full_params.extend(params);
        let mut msg = Message::with_source(
            &self.state.server_name,
            Command::Numeric(numeric),
            full_params,
        );
        self.apply_reply_tags(&mut msg, &client);
        client.send(msg);
    }

    /// IRCv3 standard-replies FAIL. Emitted only when the client has
    /// the cap — silently dropped otherwise so older clients don't get
    /// duplicated error deliveries (they're expected to rely on
    /// numerics).
    ///
    /// Wire: `FAIL <command> <code> [<context>...] :<description>`.
    #[allow(dead_code)]
    pub async fn fail(&self, command: &str, code: &str, context: &[&str], description: &str) {
        self.standard_reply(Command::Fail, command, code, context, description)
            .await;
    }

    /// IRCv3 standard-replies WARN.
    #[allow(dead_code)]
    pub async fn warn(&self, command: &str, code: &str, context: &[&str], description: &str) {
        self.standard_reply(Command::Warn, command, code, context, description)
            .await;
    }

    /// IRCv3 standard-replies NOTE.
    #[allow(dead_code)]
    pub async fn note(&self, command: &str, code: &str, context: &[&str], description: &str) {
        self.standard_reply(Command::Note, command, code, context, description)
            .await;
    }

    #[allow(dead_code)]
    async fn standard_reply(
        &self,
        verb: Command,
        command: &str,
        code: &str,
        context: &[&str],
        description: &str,
    ) {
        let client = self.client.read().await;
        if !client.has_cap(Capability::StandardReplies) {
            return;
        }
        let mut params: Vec<String> = Vec::with_capacity(3 + context.len());
        params.push(command.to_string());
        params.push(code.to_string());
        for c in context {
            params.push((*c).to_string());
        }
        params.push(description.to_string());
        let mut msg = Message::with_source(&self.state.server_name, verb, params);
        self.apply_reply_tags(&mut msg, &client);
        client.send(msg);
    }
}
