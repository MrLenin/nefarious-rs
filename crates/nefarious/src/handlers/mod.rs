pub mod channel;
pub mod messaging;
pub mod mode;
pub mod query;
pub mod registration;

use std::sync::Arc;

use irc_proto::{Command, Message};
use tokio::sync::RwLock;
use tracing::debug;

use crate::client::Client;
use crate::numeric::*;
use crate::state::ServerState;

/// Context for handling a message from a registered client.
pub struct HandlerContext {
    pub state: Arc<ServerState>,
    pub client: Arc<RwLock<Client>>,
}

impl HandlerContext {
    /// Dispatch a message to the appropriate handler.
    pub async fn dispatch(&self, msg: &Message) {
        match &msg.command {
            // Messaging
            Command::Privmsg => messaging::handle_privmsg(self, msg).await,
            Command::Notice => messaging::handle_notice(self, msg).await,

            // Channel operations
            Command::Join => channel::handle_join(self, msg).await,
            Command::Part => channel::handle_part(self, msg).await,
            Command::Topic => channel::handle_topic(self, msg).await,
            Command::Kick => channel::handle_kick(self, msg).await,
            Command::Invite => channel::handle_invite(self, msg).await,
            Command::Names => channel::handle_names(self, msg).await,
            Command::List => channel::handle_list(self, msg).await,

            // Modes
            Command::Mode => mode::handle_mode(self, msg).await,

            // Queries
            Command::Who => query::handle_who(self, msg).await,
            Command::Whois => query::handle_whois(self, msg).await,
            Command::Motd => query::handle_motd(self, msg).await,
            Command::Lusers => query::handle_lusers(self, msg).await,
            Command::Version => query::handle_version(self, msg).await,
            Command::Away => query::handle_away(self, msg).await,
            Command::Userhost => query::handle_userhost(self, msg).await,
            Command::Ison => query::handle_ison(self, msg).await,
            Command::Oper => query::handle_oper(self, msg).await,

            // Registration (nick change after registration)
            Command::Nick => registration::handle_nick_change(self, msg).await,

            // PING/PONG
            Command::Ping => {
                let token = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                let client = self.client.read().await;
                client.send(Message::with_source(
                    &self.state.server_name,
                    Command::Pong,
                    vec![self.state.server_name.clone(), token.to_string()],
                ));
            }
            Command::Pong => {
                // Client responded to our PING — update last_active
                let mut client = self.client.write().await;
                client.last_active = chrono::Utc::now();
            }

            // QUIT is handled in the connection loop, not here
            Command::Quit => {}

            // CAP — stub for now
            Command::Cap => registration::handle_cap(self, msg).await,

            // Unknown
            Command::Unknown(cmd) => {
                debug!("unknown command from client: {cmd}");
                let client = self.client.read().await;
                client.send_numeric(
                    &self.state.server_name,
                    ERR_UNKNOWNCOMMAND,
                    vec![cmd.clone(), "Unknown command".to_string()],
                );
            }

            // Other known commands we haven't implemented yet
            _ => {
                let client = self.client.read().await;
                client.send_numeric(
                    &self.state.server_name,
                    ERR_UNKNOWNCOMMAND,
                    vec![msg.command.to_string(), "Not yet implemented".to_string()],
                );
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

    /// Helper: send a numeric to the client.
    pub async fn send_numeric(&self, numeric: u16, params: Vec<String>) {
        let client = self.client.read().await;
        client.send_numeric(&self.state.server_name, numeric, params);
    }
}
