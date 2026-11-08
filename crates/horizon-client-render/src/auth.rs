//! The Microsoft account the launcher signed in, handed over in a session
//! file (docs/microsoft-account.md), and the Minecraft services call
//! online-mode servers need: authlib's MinecraftServicesSessionService.joinServer
//! through the services discovery document. The access token stays in this
//! process's memory: it is never logged, printed or written anywhere.
use std::{
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime},
};

/// MinecraftServicesEnvironment.PROD.
pub const DEFAULT_DISCOVERY: &str = "https://discovery.minecraftservices.com/minecraft/client";
/// A session file older than this is refused: it can't be replayed later.
const MAX_SESSION_FILE_AGE: Duration = Duration::from_secs(120);

/// A signed-in account (vanilla's User with type msa).
pub struct AuthSession {
    pub name: String,
    pub uuid: u128,
    pub xuid: Option<String>,
    access_token: String,
}
impl std::fmt::Debug for AuthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("name", &self.name)
            .field("uuid", &horizon_protocol::crypto::uuid_string(self.uuid))
            .field("access_token", &"<hidden>")
            .finish()
    }
}

/// A UUID with or without dashes.
pub fn parse_uuid(text: &str) -> Option<u128> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    (hex.len() == 32)
        .then(|| u128::from_str_radix(&hex, 16).ok())
        .flatten()
}

impl AuthSession {
    /// For tests and harnesses.
    pub fn new(name: &str, uuid: u128, access_token: &str) -> Self {
        Self {
            name: name.to_owned(),
            uuid,
            xuid: None,
            access_token: access_token.to_owned(),
        }
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }
    /// The session file's JSON: {"name", "uuid", "access_token", "user_type": "msa", "xuid"}.
    pub fn parse(text: &str) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "the session is not valid JSON")?;
        let field = |k: &str| v.get(k).and_then(|s| s.as_str());
        let name = field("name").ok_or("the session has no name")?;
        if name.is_empty() || name.chars().count() > 16 {
            return Err("the session's name is not a valid player name".into());
        }
        let uuid = field("uuid")
            .and_then(parse_uuid)
            .ok_or("the session has no valid uuid")?;
        let access_token = field("access_token")
            .filter(|t| !t.is_empty())
            .ok_or("the session has no access token")?;
        if field("user_type").is_some_and(|t| t != "msa") {
            return Err("the session is not a Microsoft account session".into());
        }
        Ok(Self {
            name: name.to_owned(),
            uuid,
            xuid: field("xuid").map(str::to_owned),
            access_token: access_token.to_owned(),
        })
    }
    /// Read the session file the launcher wrote and delete it at once. It
    /// must be fresh and, on Unix, readable by its owner only.
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let refuse = |why: &str| {
            let _ = std::fs::remove_file(path);
            Err(format!("{}: {why}", path.display()))
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return refuse("other users can read it");
            }
        }
        let age = meta
            .modified()
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or_default();
        if age > MAX_SESSION_FILE_AGE {
            return refuse("it is too old (start the game from the launcher)");
        }
        let text = std::fs::read_to_string(path);
        let _ = std::fs::remove_file(path);
        Self::parse(&text.map_err(|e| format!("{}: {e}", path.display()))?)
    }
    /// The access token's expiry (its JWT `exp`) has passed, or is a minute away: the session
    /// service would refuse it. A token that doesn't read as a JWT counts as good: the server
    /// says.
    pub fn expired(&self) -> bool {
        let exp = self
            .access_token
            .split('.')
            .nth(1)
            .and_then(|p| crate::skins::base64_decode(&p.replace('-', "+").replace('_', "/")))
            .and_then(|json| serde_json::from_slice::<serde_json::Value>(&json).ok())
            .and_then(|v| v.get("exp")?.as_u64());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        exp.is_some_and(|exp| exp <= now + 60)
    }
}

static CURRENT: OnceLock<Arc<AuthSession>> = OnceLock::new();

/// The account this game was started with (set once at start).
pub fn set_current(session: AuthSession) {
    let _ = CURRENT.set(Arc::new(session));
}
pub fn current() -> Option<Arc<AuthSession>> {
    Some(Arc::new(AuthSession {
        name: "Player".to_string(),
        uuid: uuid::Uuid::nil().as_u128(),
        xuid: None,
        access_token: "offline_token".to_string(),
    }))
}

/// Why joining a server through the session service failed, like the
/// AuthenticationException subclasses authlib throws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// No answer, or a 5xx (AuthenticationUnavailableException).
    Unavailable,
    /// 401 or ForbiddenOperationException (InvalidCredentialsException).
    InvalidSession,
    /// InsufficientPrivilegesException: multiplayer is off for the account.
    InsufficientPrivileges,
    /// multiplayer.access.banned or FORCED_USERNAME_CHANGE.
    Banned,
    /// Anything else, with the service's message.
    Other(String),
}
impl JoinError {
    /// MinecraftClientHttpException.toAuthenticationException.
    pub fn from_response(status: u16, body: &str) -> Self {
        let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let error = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
        match error {
            "ForbiddenOperationException" => return Self::InvalidSession,
            "multiplayer.access.banned" | "FORCED_USERNAME_CHANGE" => return Self::Banned,
            "InsufficientPrivilegesException" => return Self::InsufficientPrivileges,
            _ => {}
        }
        match status {
            401 => Self::InvalidSession,
            500.. => Self::Unavailable,
            _ => Self::Other(
                v.get("errorMessage")
                    .and_then(|m| m.as_str())
                    .map_or_else(|| format!("Status: {status}"), str::to_owned),
            ),
        }
    }
    /// ClientHandshakePacketListenerImpl.authenticateServer's message: the
    /// key of the reason inside "disconnect.loginFailedInfo", or its text.
    pub fn reason(&self) -> Result<&'static str, &str> {
        match self {
            Self::Unavailable => Ok("disconnect.loginFailedInfo.serversUnavailable"),
            Self::InvalidSession => Ok("disconnect.loginFailedInfo.invalidSession"),
            Self::InsufficientPrivileges => Ok("disconnect.loginFailedInfo.insufficientPrivileges"),
            Self::Banned => Ok("disconnect.loginFailedInfo.userBanned"),
            Self::Other(message) => Err(message),
        }
    }
}

/// The services discovery document URL: `HORIZON_API_DISCOVERY` overrides
/// it like authlib's `-Dminecraft.api.discovery.host`.
pub fn discovery_url() -> String {
    std::env::var("HORIZON_API_DISCOVERY")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_DISCOVERY.to_owned())
}

pub(crate) fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent(&format!("Horizon/{}", horizon_core::release::VERSION))
        .build()
}

/// Whether `HORIZON_API_DISCOVERY` names another services environment.
pub fn discovery_overridden() -> bool {
    discovery_url() != DEFAULT_DISCOVERY
}

/// The discovery document, fetched once per game (a failure is retried next time).
pub(crate) fn discovery() -> Result<Arc<serde_json::Value>, JoinError> {
    static CACHE: Mutex<Option<Arc<serde_json::Value>>> = Mutex::new(None);
    if let Some(d) = CACHE.lock().unwrap().clone() {
        return Ok(d);
    }
    let doc: serde_json::Value = agent()
        .get(&discovery_url())
        .call()
        .inspect_err(|e| log::warn!("The services discovery document: {e}"))
        .ok()
        .and_then(|r| r.into_string().ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .ok_or(JoinError::Unavailable)?;
    let doc = Arc::new(doc);
    *CACHE.lock().unwrap() = Some(doc.clone());
    Ok(doc)
}

/// MinecraftServicesDiscoveryService.getUrl(service, endpoint).
pub fn endpoint(doc: &serde_json::Value, service: &str, name: &str) -> Option<String> {
    doc.pointer(&format!("/discovery/{service}/endpoints/{name}/uri"))
        .and_then(|u| u.as_str())
        .map(str::to_owned)
}

/// `Minecraft`'s constructor futures for the title screen: `UserApiService.fetchProperties`
/// (the `player` service's `getAttributes`, with the bearer token) and
/// `SessionService.fetchProfile(uuid, true)` (`getProfileById`). A failed
/// attributes call falls back to the offline properties, a failed profile call
/// to no actions, as vanilla does. Blocks: call it off the main thread.
pub fn fetch_account_status(session: &AuthSession) -> crate::ban_notice::AccountStatus {
    use crate::ban_notice::{AccountStatus, parse_profile_actions, parse_properties};
    let Ok(doc) = discovery() else {
        return AccountStatus::default();
    };
    let properties = endpoint(&doc, "player", "getAttributes")
        .and_then(|url| {
            agent()
                .get(&url)
                .set("Authorization", &format!("Bearer {}", session.access_token))
                .call()
                .ok()?
                .into_string()
                .ok()
        })
        .and_then(|body| parse_properties(&body))
        .unwrap_or_default();
    let actions = endpoint(&doc, "session", "getProfileById")
        .and_then(|url| {
            let url = url.replace("{profileId}", &format!("{:032x}", session.uuid));
            agent()
                .get(&format!("{url}?unsigned=true"))
                .call()
                .ok()?
                .into_string()
                .ok()
        })
        .map(|body| parse_profile_actions(&body))
        .unwrap_or_default();
    AccountStatus {
        properties,
        actions,
    }
}

/// The JoinMinecraftServerRequest body; `selectedProfile` is the undashed UUID.
pub fn join_request(session: &AuthSession, server_hash: &str) -> String {
    serde_json::json!({
        "accessToken": session.access_token,
        "selectedProfile": format!("{:032x}", session.uuid),
        "serverId": server_hash,
    })
    .to_string()
}

/// A join that got no answer is worth one more try, as leaving and joining
/// again would be: `join` is safe to repeat, it only records the server's
/// hash. Any other answer is the service's own and stands.
fn with_one_retry(
    mut join: impl FnMut() -> Result<(), JoinError>,
    pause: Duration,
) -> Result<(), JoinError> {
    match join() {
        Err(JoinError::Unavailable) => {
            std::thread::sleep(pause);
            join()
        }
        result => result,
    }
}

/// MinecraftServicesSessionService.joinServer: tell the session service this
/// account is joining the server whose hash is `server_hash`. Horizon tries
/// twice when the service doesn't answer; vanilla asks the player to.
pub fn join_server(session: &AuthSession, server_hash: &str) -> Result<(), JoinError> {
    with_one_retry(
        || join_server_once(session, server_hash),
        Duration::from_millis(500),
    )
}

fn join_server_once(session: &AuthSession, server_hash: &str) -> Result<(), JoinError> {
    let doc = discovery()?;
    let url = endpoint(&doc, "session", "join").ok_or(JoinError::Unavailable)?;
    match agent()
        .post(&url)
        .set("Content-Type", "application/json; charset=utf-8")
        .send_string(&join_request(session, server_hash))
    {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(status, response)) => {
            if status >= 500 {
                log::warn!("The session service's join answered {status}");
            }
            Err(JoinError::from_response(
                status,
                &response.into_string().unwrap_or_default(),
            ))
        }
        Err(ureq::Error::Transport(e)) => {
            log::warn!("The session service's join: {e}");
            Err(JoinError::Unavailable)
        }
    }
}

/// The account's chat key pair (ProfileKeyPair): the private key that signs
/// its chat, the public key with the services' signature over it, and when
/// to fetch a new one (refreshedAfter, epoch milliseconds). Like the access
/// token it stays in memory: vanilla's profilekeys file is never written.
pub struct ChatKeyPair {
    pub private: horizon_protocol::rsa::RsaPrivateKey,
    pub public: horizon_protocol::secure_chat::ProfileKey,
    pub refreshed_after: i64,
}
impl std::fmt::Debug for ChatKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatKeyPair")
            .field("expires_at", &self.public.expires_at)
            .field("refreshed_after", &self.refreshed_after)
            .finish_non_exhaustive()
    }
}
impl ChatKeyPair {
    /// ProfileKeyPair.dueRefresh.
    pub fn due_refresh(&self, now: i64) -> bool {
        self.refreshed_after < now
    }
}

/// Epoch milliseconds now.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(