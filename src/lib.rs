pub mod config;
pub mod routes;
#[doc(hidden)]
pub mod test_support;
pub mod token;

use std::{collections::HashMap, sync::Arc, sync::Mutex, time::Instant};

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub const STARTUP_LINE_PREFIX: &str = "dev-idp listening on ";

pub struct AppState {
    pub cfg: config::Config,
    pub keys: token::Keys,
    pub codes: Mutex<HashMap<String, AuthCode>>,
}

pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub username: String,
    pub nonce: Option<String>,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: u64,
    pub expires_at: Instant,
}

impl AppState {
    pub fn new(cfg: config::Config) -> Result<Self, String> {
        let generated = cfg
            .generated
            .as_ref()
            .ok_or("config has no [generated] key material; run `dev-idp init` first")?;
        let keys = token::Keys::from_rsa_pem(&generated.kid, &generated.rsa_private_key_pem)?;
        Ok(AppState {
            cfg,
            keys,
            codes: Mutex::new(HashMap::new()),
        })
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let origins = &state.cfg.cors.allowed_origins;
    // Origins were validated at config load; parse failures cannot occur here.
    let origin = if origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins.iter().filter_map(|o| o.parse().ok()))
    };
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods(Any)
        .allow_headers(Any);
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(routes::serve_discovery_document),
        )
        .route("/authorize", get(routes::handle_authorization_request))
        .route("/end_session", get(routes::handle_end_session_request))
        .route("/token", post(routes::handle_token_request))
        .route("/jwks", get(routes::serve_jwks))
        .route(
            "/userinfo",
            get(routes::handle_userinfo_get).post(routes::handle_userinfo_post),
        )
        .layer(cors)
        .with_state(state)
}
