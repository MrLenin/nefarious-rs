//! Account system + authentication backends.
//!
//! Stores the locally-known accounts and validates credentials on
//! behalf of SASL and IAuth. Backends implement the `AccountStore`
//! trait; Phase 3.1 ships only the in-memory variant. Later phases
//! plug in Keycloak / IAuth via additional implementations of the
//! same trait so the SASL code never grows a direct reference to
//! any particular backend.
//!
//! Authentication outcomes are wire-compatible with C Nefarious's
//! account propagation: `ServerState::login_local` populates
//! `Client.account`, emits `RPL_LOGGEDIN`, broadcasts IRCv3
//! `account-notify`, and sends the P10 `AC` token across any S2S
//! link.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Minimum description of a user's account — just enough to populate
/// Client.account and the P10 `AC` timestamp field. Backends may carry
/// richer metadata internally but expose only this on verify.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// Canonical account name used in P10 / CAP account fields.
    pub name: String,
    /// Registration timestamp (epoch seconds). Not verified by the
    /// local server; carried alongside for bouncer / metadata use.
    pub registered_ts: u64,
}

/// Backend that validates credentials. Each Phase 3 SASL mechanism
/// calls into this trait rather than reaching into any particular
/// datastore. Async so backends can do network I/O (Keycloak, IAuth).
#[async_trait::async_trait]
pub trait AccountStore: Send + Sync {
    /// Validate `user` / `password`. On success, return the account
    /// info (account name may differ from the login username, e.g.
    /// when a backend canonicalises it).
    async fn verify_plain(&self, user: &str, password: &str) -> Option<AccountInfo>;

    /// Look up an account by name without authenticating. Used on
    /// SASL EXTERNAL paths where the credential is the TLS cert, not
    /// a password. Phase 3.3 will lean on this. Default impl returns
    /// None so backends can opt in.
    async fn lookup(&self, name: &str) -> Option<AccountInfo> {
        let _ = name;
        None
    }
}

/// Simple in-memory account store for tests and the config-loaded
/// defaults. Passwords are stored in plaintext here — real backends
/// should layer bcrypt / PBKDF2 / SCRAM stored-key themselves.
#[derive(Debug, Default)]
pub struct InMemoryAccountStore {
    entries: RwLock<HashMap<String, InMemoryEntry>>,
}

#[derive(Debug, Clone)]
struct InMemoryEntry {
    password: String,
    registered_ts: u64,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a plaintext credential. Overwrites any existing entry with
    /// the same name. Returns the same store for chaining at startup.
    pub async fn with_account(
        self,
        name: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let password = password.into();
        let ts = chrono::Utc::now().timestamp() as u64;
        self.entries.write().await.insert(
            name,
            InMemoryEntry {
                password,
                registered_ts: ts,
            },
        );
        self
    }
}

#[async_trait::async_trait]
impl AccountStore for InMemoryAccountStore {
    async fn verify_plain(&self, user: &str, password: &str) -> Option<AccountInfo> {
        let entries = self.entries.read().await;
        let entry = entries.get(user)?;
        if entry.password == password {
            Some(AccountInfo {
                name: user.to_string(),
                registered_ts: entry.registered_ts,
            })
        } else {
            None
        }
    }

    async fn lookup(&self, name: &str) -> Option<AccountInfo> {
        let entries = self.entries.read().await;
        entries.get(name).map(|e| AccountInfo {
            name: name.to_string(),
            registered_ts: e.registered_ts,
        })
    }
}

/// Shared pointer type used on ServerState.
pub type SharedAccountStore = Arc<dyn AccountStore>;

/// Convenience builder: an empty in-memory store wrapped in an Arc.
pub fn empty_in_memory() -> SharedAccountStore {
    Arc::new(InMemoryAccountStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify_plain_accepts_correct_password() {
        let store = InMemoryAccountStore::new()
            .with_account("alice", "secret")
            .await;
        let info = store.verify_plain("alice", "secret").await.unwrap();
        assert_eq!(info.name, "alice");
    }

    #[tokio::test]
    async fn verify_plain_rejects_wrong_password() {
        let store = InMemoryAccountStore::new()
            .with_account("alice", "secret")
            .await;
        assert!(store.verify_plain("alice", "nope").await.is_none());
    }

    #[tokio::test]
    async fn verify_plain_rejects_unknown_user() {
        let store = InMemoryAccountStore::new();
        assert!(store.verify_plain("ghost", "anything").await.is_none());
    }

    #[tokio::test]
    async fn lookup_returns_registered_account() {
        let store = InMemoryAccountStore::new()
            .with_account("alice", "secret")
            .await;
        assert!(store.lookup("alice").await.is_some());
        assert!(store.lookup("bob").await.is_none());
    }
}
