use std::{collections::HashSet, path::Path};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use toml_edit::{value, DocumentMut};

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub cors: Cors,
    #[serde(default)]
    pub tokens: Tokens,
    #[serde(default)]
    pub session: Session,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub users: Vec<User>,
    pub generated: Option<Generated>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Server {
    pub bind: String,
    pub issuer: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8383".into(),
            issuer: "http://localhost:8383".into(),
        }
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Cors {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Tokens {
    pub access_ttl_secs: u64,
    pub id_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
    pub auth_code_ttl_secs: u64,
}

impl Default for Tokens {
    fn default() -> Self {
        Self {
            access_ttl_secs: 300,
            id_ttl_secs: 300,
            refresh_ttl_secs: 86400,
            auth_code_ttl_secs: 60,
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Session {
    pub ttl_secs: u64,
}

impl Default for Session {
    fn default() -> Self {
        Self { ttl_secs: 28800 }
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub require_pkce: bool,
    #[serde(default)]
    pub allow_client_credentials: bool,
    #[serde(default)]
    pub client_credentials_claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct User {
    pub username: String,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

impl User {
    pub fn sub(&self) -> &str {
        self.claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.username)
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Generated {
    pub kid: String,
    pub rsa_private_key_pem: String,
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Config, String> {
        let cfg: Config =
            toml_edit::de::from_str(text).map_err(|e| format!("invalid config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        let mut client_ids = HashSet::new();
        for client in &self.clients {
            if !client_ids.insert(&client.client_id) {
                return Err(format!("duplicate client_id {:?}", client.client_id));
            }
            if client.redirect_uris.is_empty() && !client.allow_client_credentials {
                return Err(format!(
                    "client {:?} has no redirect_uris and client_credentials disabled; \
                     it can never complete any flow",
                    client.client_id
                ));
            }
        }
        let mut names = HashSet::new();
        let mut subs = HashSet::new();
        for user in &self.users {
            if !names.insert(&user.username) {
                return Err(format!("duplicate username {:?}", user.username));
            }
            if user.claims.get("sub").is_some_and(|s| !s.is_string()) {
                return Err(format!(
                    "user {:?}: the sub claim must be a string",
                    user.username
                ));
            }
            if !subs.insert(user.sub()) {
                return Err(format!(
                    "users must have unique subjects, but {:?} resolves to the sub {:?} \
                     of an earlier user (sub defaults to the username)",
                    user.username,
                    user.sub()
                ));
            }
        }
        for origin in &self.cors.allowed_origins {
            if origin != "*"
                && (origin.contains(char::is_whitespace)
                    || origin.parse::<axum::http::HeaderValue>().is_err())
            {
                return Err(format!("invalid CORS origin {origin:?}"));
            }
        }
        Ok(())
    }
}

pub fn load_and_ensure_key_material(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let (text, changed) = ensure_generated_key_material(&text)?;
    if changed {
        std::fs::write(path, &text).map_err(|e| {
            format!(
                "config {} is missing [generated] key material and is not writable ({e}); \
                 run `dev-idp init <config>` on a writable copy first",
                path.display()
            )
        })?;
    }
    Config::from_toml(&text)
}

pub fn initialize_config_file(path: &Path) -> Result<(), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read config {}: {e}", path.display())),
    };
    let (text, changed) = ensure_generated_key_material(&text)?;
    if changed {
        std::fs::write(path, &text)
            .map_err(|e| format!("cannot write config {}: {e}", path.display()))?;
    }
    Ok(())
}

fn ensure_generated_key_material(text: &str) -> Result<(String, bool), String> {
    let mut doc: DocumentMut = text.parse().map_err(|e| format!("invalid TOML: {e}"))?;
    if doc.get("generated").is_some_and(|g| !g.is_table_like()) {
        return Err("`generated` must be a [generated] table".into());
    }
    let complete = ["kid", "rsa_private_key_pem"]
        .iter()
        .all(|k| doc.get("generated").and_then(|g| g.get(k)).is_some());
    if complete {
        return Ok((text.to_string(), false));
    }
    let generated = generate_key_material();
    doc["generated"]["kid"] = value(&generated.kid);
    doc["generated"]["rsa_private_key_pem"] = value(&generated.rsa_private_key_pem);
    Ok((doc.to_string(), true))
}

pub fn generate_key_material() -> Generated {
    let key =
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("RSA key generation failed");
    let pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, rsa::pkcs8::LineEnding::LF)
        .expect("PEM encoding failed")
        .to_string();
    Generated {
        kid: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
        rsa_private_key_pem: pem,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_generates_keys_and_preserves_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev-idp.toml");
        std::fs::write(
            &path,
            "# hand-written comment\n[server]\nissuer = \"http://x\"\n\n[[users]]\nusername = \"alice\"\n",
        )
        .unwrap();

        let cfg = load_and_ensure_key_material(&path).unwrap();
        let generated = cfg.generated.expect("keys generated");
        assert!(generated.rsa_private_key_pem.contains("PRIVATE KEY"));
        assert_eq!(cfg.server.issuer, "http://x");
        assert_eq!(cfg.users[0].username, "alice");

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# hand-written comment"),
            "comments preserved"
        );
        assert!(written.contains(&generated.kid));

        // Second load must reuse, not regenerate.
        let cfg2 = load_and_ensure_key_material(&path).unwrap();
        assert_eq!(cfg2.generated.unwrap().kid, generated.kid);
    }

    #[test]
    fn init_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.toml");
        initialize_config_file(&path).unwrap();
        let cfg = Config::from_toml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(cfg.generated.is_some());
    }

    #[test]
    fn scalar_generated_is_a_clean_error_not_a_panic() {
        let err = ensure_generated_key_material("generated = true\n").unwrap_err();
        assert!(err.contains("[generated]"), "got: {err}");
    }

    #[test]
    fn validation_rejects_unusable_configs() {
        let cases = [
            (
                "[[clients]]\nclient_id = \"a\"\nredirect_uris = [\"http://x\"]\n[[clients]]\nclient_id = \"a\"\nredirect_uris = [\"http://x\"]\n",
                "duplicate client_id",
            ),
            ("[[clients]]\nclient_id = \"a\"\n", "no redirect_uris"),
            (
                "[[users]]\nusername = \"a\"\n[[users]]\nusername = \"a\"\n",
                "duplicate username",
            ),
            (
                "[[users]]\nusername = \"a\"\nclaims = { sub = 12345 }\n",
                "must be a string",
            ),
            (
                "[[users]]\nusername = \"a\"\n[[users]]\nusername = \"b\"\nclaims = { sub = \"a\" }\n",
                "unique subjects",
            ),
            ("[cors]\nallowed_origins = [\"http://x \"]\n", "CORS origin"),
        ];
        for (toml, expected) in cases {
            let err = Config::from_toml(toml).unwrap_err();
            assert!(err.contains(expected), "config {toml:?} gave: {err}");
        }
    }
}
