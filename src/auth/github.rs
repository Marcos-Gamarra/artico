//use jsonwebtoken::{decode_header, jwk::JwkSet, DecodingKey, Validation};
//use log::warn;
use crate::{
    auth::{self, AuthorizationCode},
    memory_store::MemoryStore,
};
use eyre::Result;
use serde::Deserialize;

use super::AccessToken;

#[derive(Debug, Clone)]
pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub access_token_url: String,
    pub redirect_uri: String,
    pub auth_url: String,
    // pub issuers: Vec<String>,
}

impl GithubOAuthConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            client_id: std::env::var("GITHUB_CLIENT_ID")?,
            client_secret: std::env::var("GITHUB_CLIENT_SECRET")?,
            access_token_url: std::env::var("GITHUB_ACCESS_TOKEN_URL")?,
            redirect_uri: std::env::var("GITHUB_REDIRECT_URI")?,
            auth_url: std::env::var("GITHUB_AUTH_URL")?,
            // issuers: vec![std::env::var("GITHUB_ISSUER")?],
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct IdTokenClaims {
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
pub(crate) struct GithubOAuthManager {
    pub config: GithubOAuthConfig,
    memory_store: MemoryStore,
    http_client: reqwest::Client,
}

impl GithubOAuthManager {
    pub fn new(memory_store: MemoryStore, http_client: reqwest::Client) -> Self {
        let config = GithubOAuthConfig::from_env().expect("Failed to load Google OAuth config");
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
            "{}?client_id={}&redirect_uri={}&state={}",
            self.config.auth_url, self.config.client_id, self.config.redirect_uri, csrf_token
        );

        Ok(redirect_uri)
    }

    pub async fn get_access_token(
        &self,
        authorization_code: AuthorizationCode,
    ) -> Result<AccessToken> {
        let params = format!(
            "client_id={}&client_secret={}&code={}&redirect_uri={}",
            self.config.client_id,
            self.config.client_secret,
            authorization_code.code,
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

        let access_token: AccessToken = serde_urlencoded::from_str(&response_body)?;

        Ok(access_token)
    }

    pub async fn get_user_info(&self, access_token: &str) -> Result<String> {
        let url = format!("https://api.github.com/user");

        let response = self
            .http_client
            .get(url)
            .header("User-Agent", "molyana-app")
            .bearer_auth(access_token)
            .send()
            .await?
            .text()
            .await?;

        Ok(response)
    }
}
