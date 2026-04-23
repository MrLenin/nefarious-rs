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
pub struct HandlerContext {
    pub state: Arc<ServerState>,
    pub client: Arc<RwLock<Client>>,
}

impl HandlerContext {
    /// Create a fresh context for a connection.
    pub fn new(state: Arc<ServerState>, client: Arc<RwLock<Client>>) -> Self {
        Self { state, client }
    }

    /// Dispatch a message to the appropriate handler.
    ///
    /// If the inbound message carries an `@label=...` tag and the
    /// client has the `labeled-response` cap enabled, a task-local
    /// label capture is scoped over the handler run. Only sends the
    /// dispatching task makes to the originating client are
    /// captured — broadcasts from other tasks and sends from this
    /// task to other clients bypass the buffer. When the handler
    /// returns we pick the spec-correct shape by reply count:
    ///
    /// - 0 replies → `@label=X :server ACK`
    /// - 1 reply  → attach `@label=X` to the reply, emit as-is
    /// - ≥2       → emit `@label=X BATCH +id labeled-response`, each
    ///              reply with `@batch=id`, then `BATCH -id`
    ///
    /// Opening the batch eagerly regardless of reply count — which
    /// was our prior behaviour — violates the IRCv3 labeled-response
    /// spec ("a batch is not used when the response consists of only
    /// a single message"). Buffering preserves correctness without
    /// asking every handler to know how many replies it emits.
    pub async fn dispatch(&self, msg: &Message) {
        let label = msg
            .tags
            .iter()
            .find(|t| t.key == "label")
            .and_then(|t| t.value.clone());

        let originator_id = self.client.read().await.id;
        let capture_label = if let Some(ref lbl) = label {
            if self.client.read().await.has_cap(Capability::LabeledResponse) {
                Some(lbl.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(lbl) = capture_label {
            let capture = std::sync::Mutex::new(crate::client::LabelCapture {
                originator_id,
                label: lbl,
                replies: Vec::new(),
            });
            crate::client::LABEL_CAPTURE
                .scope(capture, async {
                    self.dispatch_inner(msg).await;
                    // Flush while still inside the scope so send_raw
                    // (which doesn't consult the capture) goes directly
                    // to mpsc — otherwise any nested send via `send()`
                    // from flush helpers would recurse into the
                    // capture. We take the payload out first.
                    let captured = crate::client::LABEL_CAPTURE.with(|cell| {
                        let mut guard = cell.lock().expect("label capture mutex poisoned");
                        crate::client::LabelCapture {
                            originator_id: guard.originator_id,
                            label: std::mem::take(&mut guard.label),
                            replies: std::mem::take(&mut guard.replies),
                        }
                    });
                    let c = self.client.read().await;
                    flush_label_capture(&self.state.server_name, &c, captured).await;
                })
                .await;
        } else {
            self.dispatch_inner(msg).await;
        }
    }

    async fn dispatch_inner(&self, msg: &Message) {
        let ctx = HandlerContext {
            state: Arc::clone(&self.state),
            client: Arc::clone(&self.client),
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
            Command::Whowas => query::handle_whowas(&ctx, msg).await,
            Command::Monitor => query::handle_monitor(&ctx, msg).await,
            Command::Watch => query::handle_watch(&ctx, msg).await,
            Command::Motd => query::handle_motd(&ctx, msg).await,
            Command::Lusers => query::handle_lusers(&ctx, msg).await,
            Command::Version => query::handle_version(&ctx, msg).await,
            Command::Away => query::handle_away(&ctx, msg).await,
            Command::Userhost => query::handle_userhost(&ctx, msg).await,
            Command::Userip => query::handle_userip(&ctx, msg).await,
            Command::Ison => query::handle_ison(&ctx, msg).await,
            Command::Silence => query::handle_silence(&ctx, msg).await,
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
    /// requesting client. Currently just `@time` when the client has
    /// `server-time`. `@batch` is no longer added here — labeled-
    /// response wrapping happens at flush time against the buffered
    /// reply count, and any future explicit batches are attached at
    /// their own emission site.
    pub fn apply_reply_tags(&self, msg: &mut Message, client: &Client) {
        if client.has_cap(Capability::ServerTime) {
            msg.tags.push(Tag {
                key: "time".to_string(),
                value: Some(crate::tags::format_server_time(chrono::Utc::now())),
            });
        }
    }

    /// Send a server-originated reply message to the requesting client,
    /// attaching the reply-path tags first.
    pub async fn reply(&self, mut msg: Message) {
        let client = self.client.read().await;
        self.apply_reply_tags(&mut msg, &client);
        client.send(msg);
    }

    /// Send a user-originated reply (notably an `echo-message` self-copy
    /// of a PRIVMSG/NOTICE) to the requesting client. Goes through
    /// `tagged_for` for per-cap tagging (server-time, account-tag,
    /// msgid). The labeled-response buffer (if active) captures this
    /// via `Client::send`.
    pub async fn reply_from(&self, msg: Message, src: &crate::tags::SourceInfo) {
        let client = self.client.read().await;
        let out = crate::tags::tagged_for(msg, &client, src);
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

/// Flush a labeled-response capture in the shape dictated by reply
/// count, per IRCv3 labeled-response spec:
///
/// - 0 replies → `@label=X :server ACK`  (empty-response ack)
/// - 1 reply  → attach `@label=X` to the reply, emit as-is
/// - ≥2       → `@label=X :server BATCH +id labeled-response`
///              followed by each reply tagged `@batch=id`, closed
///              by `:server BATCH -id`
///
/// Uses `send_raw` to bypass the capture — the task-local is still
/// set during flush (we flush inside the scope), so ordinary `send`
/// would loop the messages back into the capture we just drained.
async fn flush_label_capture(
    server_name: &str,
    client: &Client,
    cap: crate::client::LabelCapture,
) {
    use irc_proto::message::Tag;
    let crate::client::LabelCapture { label, replies, .. } = cap;
    match replies.len() {
        0 => {
            let mut ack = Message::with_source(server_name, Command::Ack, Vec::new());
            ack.tags.push(Tag {
                key: "label".to_string(),
                value: Some(label),
            });
            client.send_raw(ack);
        }
        1 => {
            let mut msg = replies.into_iter().next().unwrap();
            msg.tags.push(Tag {
                key: "label".to_string(),
                value: Some(label),
            });
            client.send_raw(msg);
        }
        _ => {
            let id = client.next_batch_id();
            let mut open = Message::with_source(
                server_name,
                Command::Batch,
                vec![format!("+{id}"), "labeled-response".into()],
            );
            open.tags.push(Tag {
                key: "label".to_string(),
                value: Some(label),
            });
            client.send_raw(open);
            for mut msg in replies {
                msg.tags.push(Tag {
                    key: "batch".to_string(),
                    value: Some(id.clone()),
                });
                client.send_raw(msg);
            }
            let close = Message::with_source(
                server_name,
                Command::Batch,
                vec![format!("-{id}")],
            );
            client.send_raw(close);
        }
    }
}
