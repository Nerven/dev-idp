use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use dev_idp::test_support::{extract_query_param, test_state, test_state_with_tweaked_config};
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn build_test_router() -> Router {
    dev_idp::build_router(test_state())
}

async fn send_get_request(uri: &str) -> Response<Body> {
    send_get_request_on(build_test_router(), uri).await
}

async fn send_get_request_on(app: Router, uri: &str) -> Response<Body> {
    app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn send_get_request_with_cookie(uri: &str, cookie: &str) -> Response<Body> {
    send_get_request_with_cookie_on(build_test_router(), uri, cookie).await
}

async fn send_get_request_with_cookie_on(app: Router, uri: &str, cookie: &str) -> Response<Body> {
    app.oneshot(
        Request::builder()
            .uri(uri)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

/// The `name=value` pair from the response's Set-Cookie header.
fn extract_session_cookie_from_response(res: &Response<Body>) -> String {
    res.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A hand-crafted session cookie: the session lives entirely client-side.
fn craft_session_cookie(username: &str, auth_time: u64, exp: u64, kid: &str) -> String {
    let payload = serde_json::json!({
        "username": username, "auth_time": auth_time, "exp": exp, "kid": kid,
    });
    format!(
        "dev_idp_session={}",
        URL_SAFE_NO_PAD.encode(payload.to_string())
    )
}

async fn send_post_form_request(
    uri: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Response<Body> {
    send_post_form_request_on(build_test_router(), uri, form, basic).await
}

async fn send_post_form_request_on(
    app: Router,
    uri: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Response<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some((id, secret)) = basic {
        req = req.header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
        );
    }
    let body = serde_urlencoded::to_string(form).unwrap();
    app.oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn read_body_as_string(res: Response<Body>) -> String {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn read_body_as_json(res: Response<Body>) -> Value {
    serde_json::from_str(&read_body_as_string(res).await).unwrap()
}

fn extract_location_header(res: &Response<Body>) -> String {
    res.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

async fn send_userinfo_request_with_authorization(auth: &str) -> Response<Body> {
    build_test_router()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn obtain_authorization_code_for_alice() -> String {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await;
    assert!(res.status().is_redirection());
    extract_query_param(&extract_location_header(&res), "code").unwrap()
}

async fn exchange_code_for_tokens(code: &str) -> Response<Body> {
    send_post_form_request(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "http://localhost:3000/cb"),
            ("client_id", "app"),
        ],
        None,
    )
    .await
}

async fn obtain_tokens_for_alice() -> Value {
    let res = exchange_code_for_tokens(&obtain_authorization_code_for_alice().await).await;
    assert_eq!(res.status(), StatusCode::OK);
    read_body_as_json(res).await
}

async fn obtain_client_credentials_access_token() -> String {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "client_credentials")],
        Some(("svc", "svc-secret")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    read_body_as_json(res).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

const AUTH_QS: &str = "client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code&scope=openid+profile&state=xyz&nonce=n-1";

#[tokio::test]
async fn discovery_document_is_sane() {
    let res = send_get_request("/.well-known/openid-configuration").await;
    assert_eq!(res.status(), StatusCode::OK);
    let doc = read_body_as_json(res).await;
    assert_eq!(doc["issuer"], "http://idp.test");
    assert_eq!(doc["authorization_endpoint"], "http://idp.test/authorize");
    assert_eq!(doc["token_endpoint"], "http://idp.test/token");
    assert_eq!(doc["jwks_uri"], "http://idp.test/jwks");
    assert_eq!(doc["userinfo_endpoint"], "http://idp.test/userinfo");
    assert_eq!(doc["end_session_endpoint"], "http://idp.test/end_session");
    assert_eq!(doc["response_types_supported"][0], "code");
    assert_eq!(doc["response_modes_supported"][0], "query");
    assert_eq!(doc["response_modes_supported"][1], "form_post");
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    assert!(doc["claims_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "email"));
}

#[tokio::test]
async fn picker_login_full_flow() {
    // 1. authorize without login_hint renders the user picker
    let res = send_get_request(&format!("/authorize?{AUTH_QS}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = read_body_as_string(res).await;
    assert!(
        html.contains(">alice<") && html.contains(">bob<"),
        "picker lists all users"
    );

    // 2. follow alice's link
    let href = html
        .split("href=\"")
        .find(|s| s.contains("login_hint=alice"))
        .and_then(|s| s.split('"').next())
        .expect("alice link present");
    let res = send_get_request(href).await;
    assert!(res.status().is_redirection(), "got {}", res.status());
    let loc = extract_location_header(&res);
    assert!(loc.starts_with("http://localhost:3000/cb?"));
    assert_eq!(
        extract_query_param(&loc, "state").as_deref(),
        Some("xyz"),
        "state echoed"
    );
    let code = extract_query_param(&loc, "code").unwrap();

    // 3. exchange the code
    let res = exchange_code_for_tokens(&code).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()[header::CACHE_CONTROL],
        "no-store",
        "token responses must not be cached"
    );
    let tokens = read_body_as_json(res).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 300);
    assert_eq!(tokens["scope"], "openid profile");

    let idp_state = test_state();
    let access = tokens["access_token"].as_str().unwrap();
    let header = jsonwebtoken::decode_header(access).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some(idp_state.keys.kid.as_str()));
    let claims = idp_state.keys.verify_jwt(access).unwrap();
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["aud"][0], "api://test");
    assert_eq!(claims["email"], "alice@example.com");

    let id_claims = idp_state
        .keys
        .verify_jwt(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(id_claims["aud"], "app");
    assert_eq!(id_claims["nonce"], "n-1");
    assert_eq!(id_claims["name"], "Alice");
    assert!(id_claims["auth_time"].is_u64(), "auth_time present");

    // 4. userinfo with the access token
    let res = send_userinfo_request_with_authorization(&format!("Bearer {access}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let info = read_body_as_json(res).await;
    assert_eq!(info["sub"], "alice");
    assert_eq!(info["email"], "alice@example.com");

    // 5. codes are single-use
    let res = exchange_code_for_tokens(&code).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn error_login_hint_simulates_a_failed_authentication() {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=%21access_denied")).await;
    assert!(res.status().is_redirection());
    let loc = extract_location_header(&res);
    assert!(loc.starts_with("http://localhost:3000/cb?"));
    assert_eq!(
        extract_query_param(&loc, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        extract_query_param(&loc, "state").as_deref(),
        Some("xyz"),
        "state echoed"
    );
    assert!(
        extract_query_param(&loc, "code").is_none(),
        "no code on simulated failure"
    );
}

/// The value of the hidden `<input name="..." value="...">` in a form_post page.
fn extract_hidden_input_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    html[start..].split('"').next().map(str::to_string)
}

#[tokio::test]
async fn form_post_response_mode_posts_the_code_back() {
    let res = send_get_request(&format!(
        "/authorize?{AUTH_QS}&response_mode=form_post&login_hint=alice"
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()[header::CACHE_CONTROL],
        "no-store",
        "form_post responses must not be cached"
    );
    let html = read_body_as_string(res).await;
    assert!(html.contains("method=\"post\""), "form posts back");
    assert!(
        html.contains("action=\"http://localhost:3000/cb\""),
        "form targets the redirect_uri"
    );
    assert_eq!(
        extract_hidden_input_value(&html, "state").as_deref(),
        Some("xyz"),
        "state echoed"
    );
    let code = extract_hidden_input_value(&html, "code").expect("code input present");

    // the code redeems exactly like one delivered via query redirect
    let res = exchange_code_for_tokens(&code).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(read_body_as_json(res).await["token_type"], "Bearer");
}

#[tokio::test]
async fn form_post_response_mode_applies_to_simulated_errors() {
    let res = send_get_request(&format!(
        "/authorize?{AUTH_QS}&response_mode=form_post&login_hint=%21access_denied"
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = read_body_as_string(res).await;
    assert_eq!(
        extract_hidden_input_value(&html, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        extract_hidden_input_value(&html, "state").as_deref(),
        Some("xyz"),
        "state echoed"
    );
    assert!(!html.contains("name=\"code\""), "no code on failure");
}

#[tokio::test]
async fn form_post_escapes_html_in_parameter_values() {
    let qs = AUTH_QS.replace("state=xyz", "state=%22%3E%3Cscript%3E");
    let res = send_get_request(&format!(
        "/authorize?{qs}&response_mode=form_post&login_hint=alice"
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = read_body_as_string(res).await;
    assert!(!html.contains("<script>"), "state must not inject markup");
    assert!(html.contains("value=\"&quot;&gt;&lt;script&gt;\""));
}

#[tokio::test]
async fn explicit_query_response_mode_still_redirects() {
    let res = send_get_request(&format!(
        "/authorize?{AUTH_QS}&response_mode=query&login_hint=alice"
    ))
    .await;
    assert!(res.status().is_redirection());
    assert!(extract_query_param(&extract_location_header(&res), "code").is_some());
}

#[tokio::test]
async fn picker_offers_a_cancel_link_that_denies_access() {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}")).await;
    let html = read_body_as_string(res).await;
    assert!(
        html.contains("login_hint=%21access_denied"),
        "cancel link present"
    );
}

#[tokio::test]
async fn login_hint_skips_picker() {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await;
    assert!(res.status().is_redirection());
    assert!(extract_query_param(&extract_location_header(&res), "code").is_some());
}

#[tokio::test]
async fn interactive_login_sets_a_session_cookie() {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await;
    let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(
        set_cookie.starts_with("dev_idp_session="),
        "got {set_cookie}"
    );
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn a_session_skips_the_picker_and_signs_in_silently() {
    let cookie = extract_session_cookie_from_response(
        &send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await,
    );

    let res = send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}"), &cookie).await;
    assert!(
        res.status().is_redirection(),
        "expected silent re-auth, got {}",
        res.status()
    );
    let code = extract_query_param(&extract_location_header(&res), "code").unwrap();
    let res = exchange_code_for_tokens(&code).await;
    assert_eq!(res.status(), StatusCode::OK);
    let tokens = read_body_as_json(res).await;
    let claims = test_state()
        .keys
        .verify_jwt(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["sub"], "alice", "session belongs to alice");
}

#[tokio::test]
async fn prompt_none_succeeds_with_a_session() {
    let cookie = extract_session_cookie_from_response(
        &send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await,
    );
    let res =
        send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}&prompt=none"), &cookie).await;
    assert!(res.status().is_redirection());
    assert!(extract_query_param(&extract_location_header(&res), "code").is_some());
}

#[tokio::test]
async fn prompt_login_forces_the_picker_despite_a_session() {
    let cookie = extract_session_cookie_from_response(
        &send_get_request(&format!("/authorize?{AUTH_QS}&login_hint=alice")).await,
    );
    let res =
        send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}&prompt=login"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        read_body_as_string(res).await.contains("Sign in as"),
        "picker shown"
    );
}

#[tokio::test]
async fn expired_sessions_are_ignored() {
    let cookie = craft_session_cookie("alice", 1_000_000, 1_000_001, &test_state().keys.kid);
    let res = send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK, "picker, not silent re-auth");
}

#[tokio::test]
async fn a_session_from_another_key_generation_is_ignored() {
    // rotating the signing key is the "sign everyone out" lever, and cookies
    // from a different dev-idp project on the same port must not leak in
    let cookie = craft_session_cookie("alice", 1_000_000, current_unix_time() + 60, "other-kid");
    let res = send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK, "picker, not silent re-auth");
}

#[tokio::test]
async fn a_garbage_session_cookie_is_ignored() {
    let res = send_get_request_with_cookie(
        &format!("/authorize?{AUTH_QS}"),
        "dev_idp_session=not-base64-json",
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "picker, not an error");
}

#[tokio::test]
async fn silent_reauth_preserves_the_original_auth_time() {
    let cookie = craft_session_cookie(
        "alice",
        1_000_000,
        current_unix_time() + 60,
        &test_state().keys.kid,
    );
    let res = send_get_request_with_cookie(&format!("/authorize?{AUTH_QS}"), &cookie).await;
    assert!(res.status().is_redirection(), "got {}", res.status());
    let code = extract_query_param(&extract_location_header(&res), "code").unwrap();
    let res = exchange_code_for_tokens(&code).await;
    assert_eq!(res.status(), StatusCode::OK);
    let tokens = read_body_as_json(res).await;
    let claims = test_state()
        .keys
        .verify_jwt(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        claims["auth_time"], 1_000_000,
        "auth_time is the session's original login time, not token issuance"
    );
}

#[tokio::test]
async fn sessions_can_be_disabled_in_config() {
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| c.session.ttl_secs = 0));
    let res = send_get_request_on(app, &format!("/authorize?{AUTH_QS}&login_hint=alice")).await;
    assert!(res.status().is_redirection());
    assert!(
        !res.headers().contains_key(header::SET_COOKIE),
        "no session cookie when sessions are disabled"
    );
}

#[tokio::test]
async fn end_session_clears_the_cookie_and_redirects_with_state() {
    let res = send_get_request(
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Floggedout\
         &client_id=app&state=bye",
    )
    .await;
    assert!(res.status().is_redirection(), "got {}", res.status());
    let loc = extract_location_header(&res);
    assert!(loc.starts_with("http://localhost:3000/loggedout?"), "{loc}");
    assert_eq!(extract_query_param(&loc, "state").as_deref(), Some("bye"));
    // the session lives in the cookie, so deleting it IS the logout
    let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.starts_with("dev_idp_session="), "{set_cookie}");
    assert!(
        set_cookie.contains("Max-Age=0"),
        "cookie cleared: {set_cookie}"
    );
}

#[tokio::test]
async fn end_session_identifies_the_client_via_id_token_hint() {
    let tokens = obtain_tokens_for_alice().await;
    let id_token = tokens["id_token"].as_str().unwrap();
    let res = send_get_request(&format!(
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Floggedout\
         &id_token_hint={id_token}"
    ))
    .await;
    assert!(res.status().is_redirection(), "got {}", res.status());
}

#[tokio::test]
async fn end_session_without_client_accepts_any_registered_uri() {
    let res = send_get_request(
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Floggedout",
    )
    .await;
    assert!(res.status().is_redirection(), "got {}", res.status());
}

#[tokio::test]
async fn end_session_rejects_an_unregistered_redirect_uri() {
    let res = send_get_request(
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Fevil.test%2F&client_id=app",
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// A `post_logout_redirect_uri` is registered per client. Identifying the caller
/// must actually narrow the check, otherwise any client's URI is accepted for all.
#[tokio::test]
async fn end_session_rejects_a_uri_registered_to_another_client() {
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| {
        c.clients[1].post_logout_redirect_uris = vec!["http://localhost:3000/secure-out".into()];
    }));
    let res = send_get_request_on(
        app,
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsecure-out\
         &client_id=app",
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "`app` does not register `secure`'s post-logout uri"
    );
}

/// Same narrowing, but the client is identified by decoding `id_token_hint` --
/// which only works if the hint's signature is actually verified.
#[tokio::test]
async fn end_session_hint_narrows_the_redirect_uri_check() {
    let tokens = obtain_tokens_for_alice().await;
    let id_token = tokens["id_token"].as_str().unwrap();
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| {
        c.clients[1].post_logout_redirect_uris = vec!["http://localhost:3000/secure-out".into()];
    }));
    let res = send_get_request_on(
        app,
        &format!(
            "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fsecure-out\
             &id_token_hint={id_token}"
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "the hint identifies `app`, which does not register this uri"
    );
}

#[tokio::test]
async fn end_session_rejects_an_unknown_client_id() {
    let res = send_get_request(
        "/end_session?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Floggedout\
         &client_id=nope",
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_string(res).await, "unknown client_id");
}

/// Pruning expired codes must not take live ones with it. Uses a dedicated
/// router: the shared `test_state()` is a process-wide singleton, so a second
/// authorization from a parallel test would make this racy rather than decisive.
#[tokio::test]
async fn issuing_a_second_code_leaves_the_first_redeemable() {
    let app = dev_idp::build_router(test_state_with_tweaked_config(|_| {}));
    let res = send_get_request_on(
        app.clone(),
        &format!("/authorize?{AUTH_QS}&login_hint=alice"),
    )
    .await;
    let first = extract_query_param(&extract_location_header(&res), "code").unwrap();

    let res =
        send_get_request_on(app.clone(), &format!("/authorize?{AUTH_QS}&login_hint=bob")).await;
    extract_query_param(&extract_location_header(&res), "code").expect("second code issued");

    let res = send_post_form_request_on(
        app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &first),
            ("redirect_uri", "http://localhost:3000/cb"),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the first code must outlive the second authorization"
    );
}

/// `exp` is a whole-second unix timestamp, so the boundary is reachable: a
/// session expiring exactly now is expired, not still valid.
#[tokio::test]
async fn a_session_expiring_this_very_second_is_rejected() {
    // Align to a second boundary first. Without this the clock usually ticks
    // between stamping `exp` and the handler reading the time, so `exp == now`
    // is never actually exercised and the assertion holds either way.
    let subsec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    tokio::time::sleep(std::time::Duration::from_nanos(
        1_000_000_000 - u64::from(subsec),
    ))
    .await;

    let now = current_unix_time();
    let kid = &test_state().keys.kid.clone();
    let res = send_get_request_with_cookie(
        &format!("/authorize?{AUTH_QS}&prompt=none"),
        &craft_session_cookie("alice", now, now, kid),
    )
    .await;
    let loc = extract_location_header(&res);
    assert_eq!(
        extract_query_param(&loc, "error").as_deref(),
        Some("login_required"),
        "session with exp == now must not sign alice in: {loc}"
    );
}

/// The session cookie carries its own expiry; nothing server-side tracks it.
#[tokio::test]
async fn session_cookie_expires_one_ttl_from_now() {
    const TTL: u64 = 1234;
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| c.session.ttl_secs = TTL));
    let before = current_unix_time();
    let res = send_get_request_on(app, &format!("/authorize?{AUTH_QS}&login_hint=alice")).await;
    let cookie = extract_session_cookie_from_response(&res);
    let payload = cookie.split_once('=').unwrap().1;
    let session: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    let exp = session["exp"].as_u64().unwrap();
    assert!(
        (before + TTL..=current_unix_time() + TTL).contains(&exp),
        "exp {exp} should be about {} + {TTL}",
        before
    );
}

/// A token request missing a required parameter is `invalid_request`, not just
/// "some failure": the OAuth error code and status are part of the contract.
#[tokio::test]
async fn token_request_without_a_code_is_an_invalid_request() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "authorization_code"), ("client_id", "app")],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_request");
}

#[tokio::test]
async fn end_session_without_redirect_uri_renders_a_signed_out_page() {
    let res = send_get_request("/end_session").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(read_body_as_string(res).await.contains("Signed out"));
}

#[tokio::test]
async fn prompt_none_gets_login_required_redirect() {
    let res = send_get_request(&format!("/authorize?{AUTH_QS}&prompt=none")).await;
    assert!(res.status().is_redirection(), "got {}", res.status());
    let loc = extract_location_header(&res);
    assert!(loc.starts_with("http://localhost:3000/cb?"));
    assert_eq!(
        extract_query_param(&loc, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(extract_query_param(&loc, "state").as_deref(), Some("xyz"));
}

async fn assert_authorize_rejected(query: &str) {
    let res = send_get_request(&format!("/authorize?{query}")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "query: {query}");
}

#[tokio::test]
async fn authorize_rejects_unsupported_response_modes() {
    assert_authorize_rejected(&format!("{AUTH_QS}&response_mode=fragment")).await;
}

#[tokio::test]
async fn authorize_rejects_unknown_client() {
    assert_authorize_rejected(
        "client_id=nope&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code",
    )
    .await;
}

#[tokio::test]
async fn authorize_rejects_unregistered_redirect_uri() {
    assert_authorize_rejected(
        "client_id=app&redirect_uri=http%3A%2F%2Fevil.test%2Fcb&response_type=code",
    )
    .await;
}

#[tokio::test]
async fn authorize_enforces_pkce_for_pkce_clients() {
    assert_authorize_rejected(
        "client_id=secure&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code",
    )
    .await;
}

#[tokio::test]
async fn authorize_rejects_challenge_methods_other_than_s256() {
    // An omitted code_challenge_method means "plain" per RFC 7636.
    assert_authorize_rejected(
        "client_id=secure&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code&code_challenge=xyz",
    )
    .await;
    assert_authorize_rejected(
        "client_id=secure&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code&code_challenge=xyz&code_challenge_method=plain",
    )
    .await;
}

const PKCE_VERIFIER: &str = "correct-horse-battery-staple-correct-horse-battery-staple";

/// Authorize as bob against the PKCE-requiring "secure" client, return the code.
async fn obtain_pkce_code_for_bob() -> String {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(PKCE_VERIFIER));
    let res = send_get_request(&format!(
        "/authorize?client_id=secure&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb\
         &response_type=code&code_challenge={challenge}&code_challenge_method=S256&login_hint=bob"
    ))
    .await;
    assert!(res.status().is_redirection());
    extract_query_param(&extract_location_header(&res), "code").unwrap()
}

async fn exchange_pkce_code_for_tokens(code: &str, verifier: &str) -> Response<Body> {
    send_post_form_request(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "http://localhost:3000/cb"),
            ("client_id", "secure"),
            ("client_secret", "s3cret"),
            ("code_verifier", verifier),
        ],
        None,
    )
    .await
}

#[tokio::test]
async fn pkce_verifier_accepted() {
    let res = exchange_pkce_code_for_tokens(&obtain_pkce_code_for_bob().await, PKCE_VERIFIER).await;
    assert_eq!(res.status(), StatusCode::OK);
    let tokens = read_body_as_json(res).await;
    let claims = test_state()
        .keys
        .verify_jwt(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["sub"], "custom-bob", "sub claim override respected");
}

#[tokio::test]
async fn pkce_wrong_verifier_rejected() {
    let res = exchange_pkce_code_for_tokens(
        &obtain_pkce_code_for_bob().await,
        "wrong-verifier-wrong-verifier-wrong-verifier",
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn code_issued_to_another_client_is_rejected() {
    let code = obtain_authorization_code_for_alice().await;
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/cb"),
            ("client_id", "secure"),
            ("client_secret", "s3cret"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn code_with_mismatched_redirect_uri_is_rejected() {
    let code = obtain_authorization_code_for_alice().await;
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/other"),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn redirect_uri_may_be_omitted_at_redemption() {
    let code = obtain_authorization_code_for_alice().await;
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn expired_codes_are_rejected() {
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| {
        c.tokens.auth_code_ttl_secs = 0
    }));
    let res = send_get_request_on(
        app.clone(),
        &format!("/authorize?{AUTH_QS}&login_hint=alice"),
    )
    .await;
    let code = extract_query_param(&extract_location_header(&res), "code").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let res = send_post_form_request_on(
        app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/cb"),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_grant_issues_new_tokens() {
    let tokens = obtain_tokens_for_alice().await;
    let original_auth_time = test_state()
        .keys
        .verify_jwt(tokens["id_token"].as_str().unwrap())
        .unwrap()["auth_time"]
        .clone();
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let refreshed = read_body_as_json(res).await;
    assert_eq!(
        refreshed["scope"], "openid profile",
        "scope carried through refresh"
    );
    assert!(
        refreshed["refresh_token"].as_str().is_some(),
        "new refresh token issued"
    );
    let claims = test_state()
        .keys
        .verify_jwt(refreshed["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["sub"], "alice");
    let id_claims = test_state()
        .keys
        .verify_jwt(refreshed["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        id_claims["auth_time"], original_auth_time,
        "refresh must not move auth_time (oidc-client-ts verifies this)"
    );
}

#[tokio::test]
async fn refresh_token_is_bound_to_its_client() {
    let tokens = obtain_tokens_for_alice().await;
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", "secure"),
            ("client_secret", "s3cret"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn access_token_is_not_accepted_as_refresh_token() {
    let tokens = obtain_tokens_for_alice().await;
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["access_token"].as_str().unwrap()),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = read_body_as_json(res).await;
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "not a refresh token");
}

#[tokio::test]
async fn garbage_refresh_token_is_rejected() {
    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", "not.a.jwt"),
            ("client_id", "app"),
        ],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_grant");
}

#[tokio::test]
async fn client_credentials_grant_via_basic_auth() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "client_credentials")],
        Some(("svc", "svc-secret")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let tokens = read_body_as_json(res).await;
    assert!(tokens["id_token"].is_null() && tokens["refresh_token"].is_null());
    let claims = test_state()
        .keys
        .verify_jwt(tokens["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims["sub"], "svc");
    assert_eq!(claims["tier"], "machine");
}

#[tokio::test]
async fn client_credentials_wrong_secret_is_unauthorized() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "client_credentials")],
        Some(("svc", "wrong")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(read_body_as_json(res).await["error"], "invalid_client");
}

#[tokio::test]
async fn client_credentials_must_be_enabled_per_client() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "client_credentials"), ("client_id", "app")],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_body_as_json(res).await["error"], "unauthorized_client");
}

#[tokio::test]
async fn basic_auth_credentials_are_form_urldecoded() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "client_credentials")],
        Some(("enc", "p%2Bss+word%25")),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "percent-encoded Basic secret accepted"
    );

    let res = send_post_form_request(
        "/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "enc"),
            ("client_secret", "p+ss word%"),
        ],
        None,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "client_secret_post unaffected"
    );
}

#[tokio::test]
async fn unsupported_grant_type() {
    let res = send_post_form_request(
        "/token",
        &[("grant_type", "password"), ("client_id", "app")],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        read_body_as_json(res).await["error"],
        "unsupported_grant_type"
    );
}

#[tokio::test]
async fn userinfo_without_token_is_unauthorized() {
    let res = send_get_request("/userinfo").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn userinfo_rejects_a_garbage_token() {
    let res = send_userinfo_request_with_authorization("Bearer not.a.jwt").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn userinfo_scheme_is_case_insensitive() {
    // RFC 7235: auth schemes are case-insensitive.
    let res = send_userinfo_request_with_authorization(&format!(
        "bearer {}",
        obtain_client_credentials_access_token().await
    ))
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn userinfo_accepts_post_with_form_token() {
    // OIDC Core §5.3: the token may arrive as an access_token form parameter.
    let res = send_post_form_request(
        "/userinfo",
        &[(
            "access_token",
            &obtain_client_credentials_access_token().await,
        )],
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(read_body_as_json(res).await["sub"], "svc");
}

#[tokio::test]
async fn cors_wildcard_config() {
    let app = dev_idp::build_router(test_state_with_tweaked_config(|c| {
        c.cors.allowed_origins = vec!["*".into()];
    }));
    let res = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/token")
                .header("Origin", "http://anywhere.test")
                .header("Access-Control-Request-Method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.headers()["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn jwks_serves_the_signing_key() {
    let res = send_get_request("/jwks").await;
    assert_eq!(res.status(), StatusCode::OK);
    let jwks = read_body_as_json(res).await;
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], test_state().keys.kid.as_str());
    assert_eq!(key["n"], test_state().keys.n.as_str());
}
