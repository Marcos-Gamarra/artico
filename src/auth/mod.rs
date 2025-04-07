pub mod github;
pub mod google;
pub mod session;

use crate::{db::DbPool, memory_store::MemoryStore};
use eyre::{eyre, Result};
use log::info;
use rand::{distr::Alphanumeric, rngs::StdRng, Rng, SeedableRng};

use self::session::{Session, SessionManager};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthorizationCode {
    code: String,
    state: String,
}

impl AuthorizationCode {
    pub async fn is_state_token_valid(&self, memory_store: &MemoryStore) -> Result<bool> {
        Ok(memory_store.exists(&self.state).await?)
    }

    pub async fn remove_state_token(&self, memory_store: MemoryStore) -> Result<i64> {
        Ok(memory_store.remove(&self.state).await?)
    }
}

#[derive(Debug, Deserialize)]
pub struct AccessToken {
    pub access_token: String,
    expires_in: i64,
    pub id_token: Option<String>,
    scope: String,
    token_type: String,
    refresh_token: Option<String>,
    refresh_token_expires_in: Option<i64>,
}

#[derive(Deserialize)]
pub struct UserCredentials {
    username: String,
    password: String,
}

impl UserCredentials {
    pub async fn signup(self, db_pool: DbPool) -> Result<i64> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2
            .hash_password(self.password.as_bytes(), &salt)?
            .to_string();

        let query = "insert into users(username, password_hash) values ($1, $2) returning id";

        let row = db_pool
            .get()
            .await?
            .query_one(query, &[&self.username, &password_hash])
            .await?;

        Ok(row.get("id"))
    }

    pub async fn login(self, db_pool: DbPool, session_manager: SessionManager) -> Result<Session> {
        let conn = db_pool.get().await?;
        let query = "select id, password_hash from users where username = $1";

        let user_data = conn.query_one(query, &[&self.username]).await?;

        let password_hash = user_data.get("password_hash");

        let parsed_hash = PasswordHash::new(password_hash)?;

        Argon2::default()
            .verify_password(self.password.as_bytes(), &parsed_hash)
            .map_err(|e| {
                info!("Password verification failed: {}", e);
                eyre!("Password verification failed")
            })?;

        let user_id = user_data.get("id");

        Ok(session_manager.create_session(user_id).await?)
    }
}

pub fn generate_token() -> String {
    StdRng::from_os_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}
