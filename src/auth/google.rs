use crate::auth::{self, AuthorizationCode};
use crate::memory_store::MemoryStore;
use eyre::{eyre, Result};
use jsonwebtoken::{decode_header, jwk::JwkSet, DecodingKey, Validation};
use log::warn;
use serde::Deserialize;

use super::AccessToken;

#[derive(Debug, Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub access_token_url: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub auth_url: String,
    pub jwks_uri: String,
    pub issuers: Vec<String>,
}

impl GoogleOAuthConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            client_id: std::env::var("GOOGLE_CLIENT_ID")?,
            client_secret: std::env::var("GOOGLE_CLIENT_SECRET")?,
            access_token_url: std::env::var("GOOGLE_ACCESS_TOKEN_URL")?,
            redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")?,
            response_type: std::env::var("GOOGLE_RESPONSE_TYPE")?,
            scope: std::env::var("GOOGLE_SCOPE")?,
            auth_url: std::env::var("GOOGLE_AUTH_URL")?,
            jwks_uri: std::env::var("GOOGLE_JWKS_URI")?,
            issuers: vec![std::env::var("GOOGLE_ISSUER")?],
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct GoogleIdTokenClaims {
    pub aud: String,                  // Audience (Client ID)
    pub exp: u64,                     // Expiration time (Unix timestamp)
    pub iat: u64,                     // Issued at (Unix timestamp)
    pub iss: String,                  // Issuer (Google accounts)
    pub sub: String,                  // Unique user ID
    pub at_hash: Option<String>,      // Access token hash (if present)
    pub azp: Option<String>,          // Authorized presenter (if present)
    pub email: Option<String>,        // Email (if scope included)
    pub email_verified: Option<bool>, // Email verification status
    pub family_name: Option<String>,  // Last name
    pub given_name: Option<String>,   // First name
    pub hd: Option<String>,           // Google Workspace domain
    pub locale: Option<String>,       // User's locale (e.g., "en-US")
    pub name: Option<String>,         // Full name
    pub nonce: Option<String>,        // Nonce for replay attack protection
    pub picture: Option<String>,      // Profile picture URL
    pub profile: Option<String>,      // Profile page URL
}

#[derive(Clone)]
pub(crate) struct GoogleOAuthManager {
    pub config: GoogleOAuthConfig,
    memory_store: MemoryStore,
    http_client: reqwest::Client,
}

impl GoogleOAuthManager {
    pub fn new(memory_store: MemoryStore, http_client: reqwest::Client) -> Self {
        let config = GoogleOAuthConfig::from_env().expect("Failed to load Google OAuth config");
        Self {
            config,
            memory_store,
            http_client,
        }
    }

    pub async fn generate_redirect_uri(&self) -> Result<String> {
        let csrf_token = auth::generate_token();
        self.memory_store.set(&csrf_token, 0).await?;
        let redirect_uri = format!(
            "{}?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
            self.config.auth_url,
            self.config.client_id,
            self.config.redirect_uri,
            self.config.response_type,
            self.config.scope,
            csrf_token
        );

        Ok(redirect_uri)
    }

    async fn get_decoding_key_set(jwks_set: &str) -> Result<JwkSet> {
        let http_client = reqwest::Client::new();

        let response_body = http_client.get(jwks_set).send().await?.text().await?;

        let jwk_set: JwkSet = serde_json::from_str(&response_body)?;

        Ok(jwk_set)
    }

    pub async fn get_access_token(
        &self,
        authorization_code: AuthorizationCode,
    ) -> Result<AccessToken> {
        let params = format!(
            "client_id={}&client_secret={}&code={}&grant_type={}&redirect_uri={}",
            self.config.client_id,
            self.config.client_secret,
            authorization_code.code,
            "authorization_code",
            self.config.redirect_uri
        );

        let response_body = self
            .http_client
            .post(&self.config.access_token_url)
            .body(params)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?
            .text()
            .await?;

        let access_token: AccessToken = serde_json::from_str(&response_body)?;

        Ok(access_token)
    }

    pub async fn get_claims(&self, access_token: &AccessToken) -> Result<GoogleIdTokenClaims> {
        let client_id = &self.config.client_id.clone();
        let issuers = &self.config.issuers;
        let jwks_set = &self.config.jwks_uri;

        let jwk_set = Self::get_decoding_key_set(jwks_set).await?;
        if jwk_set.keys.is_empty() {
            return Err(eyre!("Key set for google token validation is empty"));
        }

        let Some(id_token) = &access_token.id_token else {
            return Err(eyre!("Id token is not present in the access token"));
        };

        let alg = decode_header(id_token)?.alg;
        let mut validation = Validation::new(alg);
        validation.set_audience(&[client_id]);
        validation.set_issuer(issuers);

        for key in jwk_set.keys {
            let decoding_key = DecodingKey::from_jwk(&key)?;
            match jsonwebtoken::decode::<GoogleIdTokenClaims>(id_token, &decoding_key, &validation)
            {
                Ok(token_data) => return Ok(token_data.claims),
                Err(e) => {
                    warn!(
                        r#"
                            Error while decoding google id token at get_claims with the following error: {e}.
                            Skipping to try with another key...
                        "#
                    );
                }
            };
        }

        Err(eyre!("Could not validate id token from google"))
    }
}
