use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Map, Value};

use crate::config::Client;
use crate::AppState;

pub struct Keys {
    pub kid: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// base64url modulus / exponent, as served in the JWK set
    pub n: String,
    pub e: String,
}

impl Keys {
    pub fn from_rsa_pem(kid: &str, pem: &str) -> Result<Self, String> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        let private = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| format!("invalid rsa_private_key_pem: {e}"))?;
        let public = private.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        Ok(Keys {
            kid: kid.to_string(),
            encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| e.to_string())?,
            decoding_key: DecodingKey::from_rsa_components(&n, &e).map_err(|e| e.to_string())?,
            n,
            e,
        })
    }

    pub fn sign_jwt(&self, typ: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).expect("JWT signing failed")
    }

    pub fn verify_jwt(&self, token: &str) -> Result<Value, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        Ok(jsonwebtoken::decode::<Value>(token, &self.decoding_key, &validation)?.claims)
    }

    pub fn decode_jwt_allow_expired(
        &self,
        token: &str,
    ) -> Result<Value, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.validate_exp = false;
        Ok(jsonwebtoken::decode::<Value>(token, &self.decoding_key, &validation)?.claims)
    }
}

pub(crate) fn seconds_since_unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl AppState {
    fn build_base_claims(
        &self,
        sub: &str,
        ttl_secs: u64,
        extra: &Map<String, Value>,
    ) -> Map<String, Value> {
        let now = seconds_since_unix_epoch();
        let mut claims = extra.clone();
        claims.insert("iss".into(), json!(self.cfg.server.issuer));
        claims.insert("sub".into(), json!(sub));
        claims.insert("exp".into(), json!(now + ttl_secs));
        claims.insert("iat".into(), json!(now));
        claims
    }

    pub fn issue_access_token(
        &self,
        client: &Client,
        sub: &str,
        extra: &Map<String, Value>,
        scope: Option<&str>,
    ) -> String {
        let aud = if client.audiences.is_empty() {
            json!(client.client_id)
        } else {
            json!(client.audiences)
        };
        let mut claims = self.build_base_claims(sub, self.cfg.tokens.access_ttl_secs, extra);
        claims.insert("aud".into(), aud);
        claims.insert("client_id".into(), json!(client.client_id));
        if let Some(s) = scope {
            claims.insert("scope".into(), json!(s));
        }
        self.keys.sign_jwt("at+jwt", &Value::Object(claims))
    }

    pub fn issue_id_token(
        &self,
        client: &Client,
        sub: &str,
        extra: &Map<String, Value>,
        nonce: Option<&str>,
        auth_time: u64,
    ) -> String {
        let mut claims = self.build_base_claims(sub, self.cfg.tokens.id_ttl_secs, extra);
        claims.insert("aud".into(), json!(client.client_id));
        claims.insert("auth_time".into(), json!(auth_time));
        if let Some(n) = nonce {
            claims.insert("nonce".into(), json!(n));
        }
        self.keys.sign_jwt("JWT", &Value::Object(claims))
    }

    pub fn issue_refresh_token(
        &self,
        client: &Client,
        sub: &str,
        scope: Option<&str>,
        auth_time: u64,
    ) -> String {
        let mut claims = self.build_base_claims(sub, self.cfg.tokens.refresh_ttl_secs, &Map::new());
        claims.insert("client_id".into(), json!(client.client_id));
        claims.insert("token_use".into(), json!("refresh"));
        claims.insert("auth_time".into(), json!(auth_time));
        if let Some(s) = scope {
            claims.insert("scope".into(), json!(s));
        }
        self.keys.sign_jwt("JWT", &Value::Object(claims))
    }

    pub fn build_token_response(
        &self,
        client: &Client,
        sub: &str,
        extra: &Map<String, Value>,
        scope: Option<&str>,
        nonce: Option<&str>,
        auth_time: u64,
    ) -> Value {
        let mut body = Map::new();
        body.insert(
            "access_token".into(),
            json!(self.issue_access_token(client, sub, extra, scope)),
        );
        body.insert(
            "id_token".into(),
            json!(self.issue_id_token(client, sub, extra, nonce, auth_time)),
        );
        body.insert(
            "refresh_token".into(),
            json!(self.issue_refresh_token(client, sub, scope, auth_time)),
        );
        body.insert("token_type".into(), json!("Bearer"));
        body.insert("expires_in".into(), json!(self.cfg.tokens.access_ttl_secs));
        if let Some(s) = scope {
            body.insert("scope".into(), json!(s));
        }
        Value::Object(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;

    #[test]
    fn access_token_claims_and_header() {
        let state = test_state();
        let client = &state.cfg.clients[0];
        let user = &state.cfg.users[0];
        let token =
            state.issue_access_token(client, user.sub(), &user.claims, Some("openid profile"));

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.kid.as_deref(), Some(state.keys.kid.as_str()));

        let claims = state.keys.verify_jwt(&token).unwrap();
        assert_eq!(claims["iss"], state.cfg.server.issuer);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["aud"], json!(["api://test"]));
        assert_eq!(claims["client_id"], "app");
        assert_eq!(claims["scope"], "openid profile");
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["roles"], json!(["admin"]));
    }

    #[test]
    fn id_token_claims() {
        let state = test_state();
        let client = &state.cfg.clients[0];
        let user = &state.cfg.users[0];
        let token =
            state.issue_id_token(client, user.sub(), &user.claims, Some("nonce-1"), 1_234_567);
        let claims = state.keys.verify_jwt(&token).unwrap();
        assert_eq!(claims["aud"], "app");
        assert_eq!(claims["nonce"], "nonce-1");
        assert_eq!(claims["name"], "Alice");
        assert_eq!(
            claims["auth_time"], 1_234_567,
            "auth_time is the original interactive login, not issuance time"
        );
    }

    #[test]
    fn sub_override_and_refresh_claims() {
        let state = test_state();
        let client = &state.cfg.clients[0];
        let bob = state
            .cfg
            .users
            .iter()
            .find(|u| u.username == "bob")
            .unwrap();
        assert_eq!(bob.sub(), "custom-bob");
        let token = state.issue_refresh_token(client, bob.sub(), None, 1_234_567);
        let claims = state.keys.verify_jwt(&token).unwrap();
        assert_eq!(claims["token_use"], "refresh");
        assert_eq!(claims["sub"], "custom-bob");
        assert_eq!(claims["client_id"], "app");
        assert_eq!(
            claims["auth_time"], 1_234_567,
            "refresh tokens carry auth_time so refreshed id_tokens keep it"
        );
    }
}
