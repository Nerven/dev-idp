use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Form, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{config::Client, token::seconds_since_unix_epoch, AppState, AuthCode};

const SESSION_COOKIE: &str = "dev_idp_session";

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionCookie {
    username: String,
    auth_time: u64,
    exp: u64,
    kid: String,
}

pub async fn serve_discovery_document(State(state): State<Arc<AppState>>) -> Json<Value> {
    let issuer = &state.cfg.server.issuer;
    let claims: BTreeSet<&str> = std::iter::once("sub")
        .chain(
            state
                .cfg
                .users
                .iter()
                .flat_map(|u| u.claims.keys().map(String::as_str)),
        )
        .collect();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "end_session_endpoint": format!("{issuer}/end_session"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": claims,
    }))
}

pub async fn serve_jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": state.keys.kid,
            "n": state.keys.n,
            "e": state.keys.e,
        }]
    }))
}

pub async fn handle_authorization_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let param = |name: &str| query.get(name).map(String::as_str);

    let Some(client) = state
        .cfg
        .clients
        .iter()
        .find(|c| param("client_id") == Some(&c.client_id))
    else {
        return bad_request_response("unknown client_id");
    };
    let Some(redirect_uri) =
        param("redirect_uri").filter(|u| client.redirect_uris.iter().any(|r| r == u))
    else {
        return bad_request_response("redirect_uri missing or not registered for this client");
    };
    if param("response_type") != Some("code") {
        return bad_request_response("response_type must be 'code'");
    }
    let response_mode = param("response_mode");
    if !matches!(response_mode, None | Some("query") | Some("form_post")) {
        return bad_request_response("response_mode must be 'query' or 'form_post'");
    }
    let challenge = param("code_challenge");
    if client.require_pkce && challenge.is_none() {
        return bad_request_response("this client requires PKCE (S256 code_challenge)");
    }
    if challenge.is_some() && param("code_challenge_method") != Some("S256") {
        return bad_request_response("only the S256 code_challenge_method is supported");
    }

    let hinted_user = match param("login_hint") {
        // A hint of !<error> (e.g. !access_denied) simulates a failed
        // authentication: redirect back with that OAuth error, like a
        // production IdP when the user cancels or is rejected.
        Some(hint) if hint.starts_with('!') => {
            let mut params = vec![("error", &hint[1..])];
            if let Some(s) = param("state") {
                params.push(("state", s));
            }
            return send_authorization_response(redirect_uri, &params, response_mode);
        }
        Some(hint) => match state.cfg.users.iter().find(|u| u.username == hint) {
            Some(user) => Some(user),
            None => return bad_request_response("login_hint does not match any configured user"),
        },
        None => None,
    };
    let prompts: Vec<&str> = param("prompt")
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    // An explicit login_hint wins; otherwise a live IdP session signs the
    // user in silently, unless prompt=login forces re-authentication.
    let authentication = match hinted_user {
        Some(user) => Some((user, seconds_since_unix_epoch())),
        None if !prompts.contains(&"login") => extract_valid_session_cookie(&state, &headers)
            .and_then(|session| {
                state
                    .cfg
                    .users
                    .iter()
                    .find(|u| u.username == session.username)
                    .map(|user| (user, session.auth_time))
            }),
        None => None,
    };

    let Some((user, auth_time)) = authentication else {
        if prompts.contains(&"none") {
            let mut params = vec![("error", "login_required")];
            if let Some(s) = param("state") {
                params.push(("state", s));
            }
            return send_authorization_response(redirect_uri, &params, response_mode);
        }
        return render_user_picker_page(&state, &raw_query.unwrap_or_default());
    };

    let code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    {
        let mut codes = state.codes.lock().unwrap();
        codes.retain(|_, c| c.expires_at > Instant::now());
        codes.insert(
            code.clone(),
            AuthCode {
                client_id: client.client_id.clone(),
                redirect_uri: redirect_uri.to_string(),
                username: user.username.clone(),
                nonce: param("nonce").map(Into::into),
                scope: param("scope").map(Into::into),
                code_challenge: challenge.map(Into::into),
                auth_time,
                expires_at: Instant::now()
                    + Duration::from_secs(state.cfg.tokens.auth_code_ttl_secs),
            },
        );
    }

    let mut params = vec![("code", code.as_str())];
    if let Some(s) = param("state") {
        params.push(("state", s));
    }
    let mut response = send_authorization_response(redirect_uri, &params, response_mode);
    if hinted_user.is_some() {
        if let Some(cookie) = issue_session_cookie(&state, &user.username, auth_time) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
}

fn extract_valid_session_cookie(state: &AppState, headers: &HeaderMap) -> Option<SessionCookie> {
    let encoded_payload = extract_cookie_value_from_http_headers(headers, SESSION_COOKIE)?;
    let session: SessionCookie =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_payload).ok()?).ok()?;
    (session.exp > seconds_since_unix_epoch() && session.kid == state.keys.kid).then_some(session)
}

fn extract_cookie_value_from_http_headers<'a>(
    headers: &'a HeaderMap,
    cookie_name: &str,
) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(name, value)| (name == cookie_name).then_some(value))
}

fn issue_session_cookie(state: &AppState, username: &str, auth_time: u64) -> Option<HeaderValue> {
    let ttl_secs = state.cfg.session.ttl_secs;
    if ttl_secs == 0 {
        return None;
    }
    let payload = serde_json::to_string(&SessionCookie {
        username: username.to_string(),
        auth_time,
        exp: seconds_since_unix_epoch() + ttl_secs,
        kid: state.keys.kid.clone(),
    })
    .unwrap();
    Some(format_session_cookie_header(
        state,
        &URL_SAFE_NO_PAD.encode(payload),
        ttl_secs,
    ))
}

/// The Set-Cookie value deleting the session cookie: the session lives
/// entirely client-side, so this IS the logout.
fn delete_session_cookie(state: &AppState) -> HeaderValue {
    format_session_cookie_header(state, "", 0)
}

fn format_session_cookie_header(state: &AppState, value: &str, max_age_secs: u64) -> HeaderValue {
    let secure = if state.cfg.server.issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={value}; Max-Age={max_age_secs}; Path=/; HttpOnly; SameSite=Lax{secure}"
    ))
    .expect("valid cookie header")
}

pub async fn handle_end_session_request(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let mut response = build_end_session_response(&state, &query);
    response
        .headers_mut()
        .append(header::SET_COOKIE, delete_session_cookie(&state));
    response
}

fn build_end_session_response(state: &AppState, query: &HashMap<String, String>) -> Response {
    let param = |name: &str| query.get(name).map(String::as_str);
    let Some(redirect_uri) = param("post_logout_redirect_uri") else {
        return render_signed_out_page();
    };
    let client = match identify_logout_client(state, query) {
        Ok(client) => client,
        Err(rejection) => return rejection,
    };
    if !post_logout_redirect_uri_is_registered(state, client, redirect_uri) {
        return bad_request_response(
            "post_logout_redirect_uri is not registered; \
             add it to the client's post_logout_redirect_uris",
        );
    }
    let mut params = vec![];
    if let Some(s) = param("state") {
        params.push(("state", s));
    }
    redirect_with_query_params(redirect_uri, &params)
}

fn render_signed_out_page() -> Response {
    Html(
        "<!doctype html><title>dev-idp</title>\
         <style>body{font:16px sans-serif;max-width:24rem;margin:4rem auto}</style>\
         <h2>Signed out</h2><p>The dev-idp session has ended.</p>",
    )
    .into_response()
}

#[allow(clippy::result_large_err)]
fn identify_logout_client<'a>(
    state: &'a AppState,
    query: &HashMap<String, String>,
) -> Result<Option<&'a Client>, Response> {
    if let Some(client_id) = query.get("client_id") {
        return match state.cfg.clients.iter().find(|c| &c.client_id == client_id) {
            Some(client) => Ok(Some(client)),
            None => Err(bad_request_response("unknown client_id")),
        };
    }
    Ok(query
        .get("id_token_hint")
        .and_then(|token| state.keys.decode_jwt_allow_expired(token).ok())
        .and_then(|claims| {
            let audience = claims["aud"].as_str()?.to_string();
            state.cfg.clients.iter().find(|c| c.client_id == audience)
        }))
}

fn post_logout_redirect_uri_is_registered(
    state: &AppState,
    client: Option<&Client>,
    redirect_uri: &str,
) -> bool {
    let registered = |c: &Client| {
        c.post_logout_redirect_uris
            .iter()
            .any(|u| u == redirect_uri)
    };
    match client {
        Some(client) => registered(client),
        None => state.cfg.clients.iter().any(registered),
    }
}

fn render_user_picker_page(state: &AppState, raw_query: &str) -> Response {
    let buttons: String = state
        .cfg
        .users
        .iter()
        .map(|u| {
            format!(
                "<a class=\"user\" href=\"/authorize?{raw_query}&login_hint={}\">{}</a>\n",
                percent_encode_query_value(&u.username),
                u.username
            )
        })
        .collect();
    Html(format!(
        "<!doctype html><title>dev-idp login</title>\
         <style>body{{font:16px sans-serif;max-width:24rem;margin:4rem auto}}\
         .user{{display:block;padding:.7rem 1rem;margin:.5rem 0;border:1px solid #999;\
         border-radius:6px;text-decoration:none;color:#222}}.user:hover{{background:#eee}}\
         .cancel{{display:block;margin:1rem 0;text-align:center;color:#666}}</style>\
         <h2>Sign in as</h2>\n{buttons}\
         <a class=\"cancel\" href=\"/authorize?{raw_query}&login_hint=%21access_denied\">Cancel</a>"
    ))
    .into_response()
}

pub async fn handle_token_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut response = issue_tokens_for_grant(&state, &headers, &form);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn issue_tokens_for_grant(
    state: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Response {
    let client = match authenticate_client(state, headers, form) {
        Ok(client) => client,
        Err(rejection) => return rejection,
    };
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => exchange_authorization_code_for_tokens(state, client, form),
        Some("refresh_token") => exchange_refresh_token_for_new_tokens(state, client, form),
        Some("client_credentials") => {
            issue_access_token_for_client_credentials(state, client, form)
        }
        _ => oauth_error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be authorization_code, refresh_token or client_credentials",
        ),
    }
}

// The Err variant carries a ready-to-send rejection; its size is irrelevant
// on this once-per-request path.
#[allow(clippy::result_large_err)]
fn authenticate_client<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<&'a Client, Response> {
    let (client_id, client_secret) = extract_client_credentials(headers, form);
    let Some(client_id) = client_id else {
        return Err(invalid_request_response("missing client_id"));
    };
    let Some(client) = state.cfg.clients.iter().find(|c| c.client_id == client_id) else {
        return Err(oauth_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "unknown client",
        ));
    };
    if let Some(required) = &client.client_secret {
        if client_secret.as_deref() != Some(required) {
            return Err(oauth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "bad client_secret",
            ));
        }
    }
    Ok(client)
}

fn exchange_authorization_code_for_tokens(
    state: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
) -> Response {
    let param = |name: &str| form.get(name).map(String::as_str);
    let Some(code) = param("code") else {
        return invalid_request_response("missing code");
    };
    let stored = state.codes.lock().unwrap().remove(code);
    let Some(auth_code) = stored.filter(|c| c.expires_at > Instant::now()) else {
        return invalid_grant_response("authorization code is unknown, already used, or expired");
    };
    if auth_code.client_id != client.client_id {
        return invalid_grant_response("code was issued to a different client");
    }
    if let Some(uri) = param("redirect_uri") {
        if uri != auth_code.redirect_uri {
            return invalid_grant_response("redirect_uri does not match the authorization request");
        }
    }
    if let Some(challenge) = &auth_code.code_challenge {
        let verified = param("code_verifier")
            .is_some_and(|v| URL_SAFE_NO_PAD.encode(Sha256::digest(v)) == *challenge);
        if !verified {
            return invalid_grant_response("PKCE code_verifier verification failed");
        }
    }
    let Some(user) = state
        .cfg
        .users
        .iter()
        .find(|u| u.username == auth_code.username)
    else {
        return invalid_grant_response("user no longer configured");
    };
    Json(state.build_token_response(
        client,
        user.sub(),
        &user.claims,
        auth_code.scope.as_deref(),
        auth_code.nonce.as_deref(),
        auth_code.auth_time,
    ))
    .into_response()
}

fn exchange_refresh_token_for_new_tokens(
    state: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
) -> Response {
    let Some(refresh_token) = form.get("refresh_token") else {
        return invalid_request_response("missing refresh_token");
    };
    let Ok(claims) = state.keys.verify_jwt(refresh_token) else {
        return invalid_grant_response("refresh token is invalid or expired");
    };
    if claims["token_use"] != "refresh" {
        return invalid_grant_response("not a refresh token");
    }
    if claims["client_id"] != client.client_id.as_str() {
        return invalid_grant_response("refresh token was issued to a different client");
    }
    let sub = claims["sub"].as_str().unwrap_or_default();
    let Some(user) = state.cfg.users.iter().find(|u| u.sub() == sub) else {
        return invalid_grant_response("unknown subject");
    };
    let scope = claims["scope"].as_str();
    let auth_time = claims["auth_time"]
        .as_u64()
        .unwrap_or_else(seconds_since_unix_epoch);
    Json(state.build_token_response(client, user.sub(), &user.claims, scope, None, auth_time))
        .into_response()
}

fn issue_access_token_for_client_credentials(
    state: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
) -> Response {
    if !client.allow_client_credentials {
        return oauth_error_response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "client_credentials grant is not enabled for this client",
        );
    }
    let scope = form.get("scope").map(String::as_str);
    let access_token = state.issue_access_token(
        client,
        &client.client_id,
        &client.client_credentials_claims,
        scope,
    );
    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.cfg.tokens.access_ttl_secs,
    }))
    .into_response()
}

pub async fn handle_userinfo_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    respond_with_user_claims(&state, extract_bearer_token_from_http_headers(&headers))
}

pub async fn handle_userinfo_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let token = extract_bearer_token_from_http_headers(&headers)
        .or_else(|| form.get("access_token").map(String::as_str));
    respond_with_user_claims(&state, token)
}

fn respond_with_user_claims(state: &AppState, token: Option<&str>) -> Response {
    let Some(claims) = token.and_then(|t| state.keys.verify_jwt(t).ok()) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
            "invalid or missing bearer token",
        )
            .into_response();
    };
    let sub = claims["sub"].as_str().unwrap_or_default();
    let mut user_claims = state
        .cfg
        .users
        .iter()
        .find(|u| u.sub() == sub)
        .map(|u| u.claims.clone())
        .unwrap_or_default();
    user_claims.insert("sub".into(), json!(sub));
    Json(Value::Object(user_claims)).into_response()
}

/// Accepts both client_secret_basic (Authorization header) and
/// client_secret_post (form body) per RFC 6749 §2.3.1.
fn extract_client_credentials(
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> (Option<String>, Option<String>) {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    match basic {
        Some(credentials) => {
            let (id, secret) = credentials
                .split_once(':')
                .unwrap_or((credentials.as_str(), ""));
            (
                Some(decode_form_urlencoded_value(id)),
                Some(decode_form_urlencoded_value(secret)),
            )
        }
        None => (
            form.get("client_id").cloned(),
            form.get("client_secret").cloned(),
        ),
    }
}

fn extract_bearer_token_from_http_headers(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    // the auth scheme is case-insensitive per RFC 7235
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim_start())
}

fn bad_request_response(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}

fn oauth_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn invalid_request_response(description: &str) -> Response {
    oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", description)
}

fn invalid_grant_response(description: &str) -> Response {
    oauth_error_response(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

fn send_authorization_response(
    redirect_uri: &str,
    params: &[(&str, &str)],
    response_mode: Option<&str>,
) -> Response {
    match response_mode {
        Some("form_post") => form_post_response(redirect_uri, params),
        _ => redirect_with_query_params(redirect_uri, params),
    }
}

fn form_post_response(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let inputs: String = params
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                escape_html_attribute(value)
            )
        })
        .collect();
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(format!(
            "<!doctype html><title>dev-idp</title>\
             <body onload=\"document.forms[0].submit()\">\
             <form method=\"post\" action=\"{}\">{inputs}</form>",
            escape_html_attribute(redirect_uri)
        )),
    )
        .into_response()
}

fn escape_html_attribute(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn redirect_with_query_params(uri: &str, params: &[(&str, &str)]) -> Response {
    if params.is_empty() {
        return Redirect::to(uri).into_response();
    }
    let query_string = serde_urlencoded::to_string(params).unwrap();
    let separator = if uri.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{uri}{separator}{query_string}")).into_response()
}

fn percent_encode_query_value(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn decode_form_urlencoded_value(s: &str) -> String {
    form_urlencoded::parse(format!("v={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}
