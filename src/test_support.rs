use std::sync::{Arc, OnceLock};

use crate::{config, AppState};

pub const TEST_TOML: &str = r#"
[server]
issuer = "http://idp.test"

[[clients]]
client_id = "app"
redirect_uris = ["http://localhost:3000/cb"]
post_logout_redirect_uris = ["http://localhost:3000/loggedout"]
audiences = ["api://test"]

[[clients]]
client_id = "secure"
client_secret = "s3cret"
redirect_uris = ["http://localhost:3000/cb"]
require_pkce = true

[[clients]]
client_id = "svc"
client_secret = "svc-secret"
allow_client_credentials = true
client_credentials_claims = { tier = "machine" }

# secret with characters that RFC 6749 §2.3.1 requires clients to percent-encode
[[clients]]
client_id = "enc"
client_secret = "p+ss word%"
allow_client_credentials = true

[[users]]
username = "alice"
claims = { email = "alice@example.com", name = "Alice", roles = ["admin"] }

[[users]]
username = "bob"
claims = { sub = "custom-bob" }
"#;

/// One shared state per test binary: RSA keygen is expensive, reuse the key.
pub fn test_state() -> Arc<AppState> {
    static STATE: OnceLock<Arc<AppState>> = OnceLock::new();
    STATE
        .get_or_init(|| test_state_with_tweaked_config(|_| {}))
        .clone()
}

/// A fresh state sharing the generated key but with a tweaked config.
pub fn test_state_with_tweaked_config(tweak: impl FnOnce(&mut config::Config)) -> Arc<AppState> {
    static GENERATED: OnceLock<config::Generated> = OnceLock::new();
    let mut cfg = config::Config::from_toml(TEST_TOML).unwrap();
    cfg.generated = Some(GENERATED.get_or_init(config::generate_key_material).clone());
    tweak(&mut cfg);
    Arc::new(AppState::new(cfg).unwrap())
}

/// Extract a query parameter from a URL (test values need no percent-decoding).
pub fn extract_query_param(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(Into::into)
}
