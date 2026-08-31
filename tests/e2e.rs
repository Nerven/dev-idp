use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use dev_idp::test_support::extract_query_param;
use serde_json::Value;

const CONFIG: &str = r#"
[server]
bind = "127.0.0.1:0"
issuer = "http://mock-idp"

[cors]
allowed_origins = ["http://localhost:3000"]

[[clients]]
client_id = "my-app"
client_secret = "dev-secret"
redirect_uris = ["http://localhost:3000/callback"]
audiences = ["api://my-api"]

[[users]]
username = "alice"
claims = { email = "alice@example.com", name = "Alice", roles = ["admin"] }
"#;

struct Server {
    child: Child,
    base: String,
    config_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Server {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn restart(&mut self) {
        self.stop();
        (self.child, self.base) = spawn_server_process(&self.config_path);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn start_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("dev-idp.toml");
    std::fs::write(&config_path, CONFIG).unwrap();
    let (child, base) = spawn_server_process(&config_path);
    Server {
        child,
        base,
        config_path,
        _dir: dir,
    }
}

fn spawn_server_process(config_path: &Path) -> (Child, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dev-idp"))
        .arg(config_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    let addr = line
        .strip_prefix(dev_idp::STARTUP_LINE_PREFIX)
        .and_then(|l| l.split(',').next())
        .unwrap_or_else(|| panic!("unexpected startup line: {line:?}"));
    (child, format!("http://{addr}"))
}

#[tokio::test]
async fn full_oidc_flow() {
    let server = start_server();
    let base = &server.base;
    // don't follow redirects: the callback host doesn't exist, we want the Location header
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // key material was generated and written back to the config file
    let written = std::fs::read_to_string(&server.config_path).unwrap();
    assert!(
        written.contains("PRIVATE KEY"),
        "generated key written back to config"
    );
    assert!(written.contains("[cors]"), "original content preserved");

    // discovery
    let disc: Value = http
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disc["issuer"], "http://mock-idp");
    assert_eq!(disc["token_endpoint"], "http://mock-idp/token");

    // picker page lists the user
    let picker = http
        .get(format!(
            "{base}/authorize?client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code"
        ))
        .send()
        .await
        .unwrap();
    assert!(picker.status().is_success());
    assert!(picker.text().await.unwrap().contains("login_hint=alice"));

    // login_hint auto-login -> redirect with code and echoed state
    let res = http
        .get(format!(
            "{base}/authorize?client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback\
             &response_type=code&scope=openid&state=s1&nonce=n1&login_hint=alice"
        ))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_redirection(), "got {}", res.status());
    let loc = res.headers()["location"].to_str().unwrap().to_string();
    assert!(loc.starts_with("http://localhost:3000/callback?"));
    assert_eq!(extract_query_param(&loc, "state").as_deref(), Some("s1"));
    let code = extract_query_param(&loc, "code").unwrap();

    // token exchange
    let tokens: Value = http
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("client_id", "my-app"),
            ("client_secret", "dev-secret"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    let access = tokens["access_token"].as_str().unwrap();

    // the access token verifies against the JWKS served over the wire
    let jwks: Value = http
        .get(format!("{base}/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(
        key["kid"].as_str().unwrap(),
        jsonwebtoken::decode_header(access).unwrap().kid.unwrap()
    );
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(
        key["n"].as_str().unwrap(),
        key["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Value>(access, &decoding_key, &validation)
        .unwrap()
        .claims;
    assert_eq!(claims["iss"], "http://mock-idp");
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["aud"][0], "api://my-api");
    assert_eq!(claims["email"], "alice@example.com");

    // id_token nonce round-trip, signature-checked against the same JWKS
    let id_claims = jsonwebtoken::decode::<Value>(
        tokens["id_token"].as_str().unwrap(),
        &decoding_key,
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(id_claims["nonce"], "n1");
    assert_eq!(id_claims["aud"], "my-app");

    // userinfo
    let info: Value = http
        .get(format!("{base}/userinfo"))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["sub"], "alice");
    assert_eq!(info["email"], "alice@example.com");

    // codes are single-use
    let replay = http
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("client_id", "my-app"),
            ("client_secret", "dev-secret"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );

    // CORS preflight on the token endpoint
    let preflight = http
        .request(reqwest::Method::OPTIONS, format!("{base}/token"))
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        "http://localhost:3000",
        "CORS allows the configured origin"
    );
}

#[tokio::test]
async fn sessions_survive_a_restart() {
    let mut server = start_server();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    const AUTHORIZE_QS: &str =
        "client_id=my-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code";

    let res = http
        .get(format!(
            "{}/authorize?{AUTHORIZE_QS}&login_hint=alice",
            server.base
        ))
        .send()
        .await
        .unwrap();
    let cookie = res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    server.restart();

    // the session lives in the cookie and the key was reused, so the
    // restarted IdP still signs alice in silently — like a production IdP
    let res = http
        .get(format!("{}/authorize?{AUTHORIZE_QS}", server.base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_redirection(),
        "expected silent login after restart, got {}",
        res.status()
    );
    assert!(extract_query_param(res.headers()["location"].to_str().unwrap(), "code").is_some());
}

#[tokio::test]
async fn restart_reuses_generated_key() {
    let mut server = start_server();
    let kid_run1 = fetch_kid_from_jwks(&server).await;
    server.restart(); // same (now key-carrying) config file
    assert_eq!(
        fetch_kid_from_jwks(&server).await,
        kid_run1,
        "restart must reuse the key so previously issued tokens stay valid"
    );
}

async fn fetch_kid_from_jwks(server: &Server) -> String {
    let jwks: Value = reqwest::get(format!("{}/jwks", server.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    jwks["keys"][0]["kid"].as_str().unwrap().to_string()
}
