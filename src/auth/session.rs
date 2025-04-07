use crate::memory_store::MemoryStore;
use eyre::Result;

pub struct Session {
    pub id: String,
    pub user_id: i64,
}

impl Session {
    pub fn new(user_id: i64) -> Self {
        let id = super::generate_token();

        Session { id, user_id }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    pub memory_store: MemoryStore,
}

impl SessionManager {
    pub async fn new(redis_pool: MemoryStore) -> Self {
        SessionManager {
            memory_store: redis_pool,
        }
    }

    pub async fn create_session(&self, user_id: i64) -> Result<Session> {
        let session = Session::new(user_id);
        self.memory_store.set(&session.id, session.user_id).await?;
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<i64> {
        Ok(self.memory_store.get(session_id).await?)
    }

    pub async fn remove_session(&self, session_id: &str) -> Result<i64> {
        Ok(self.memory_store.remove::<&str, i64>(session_id).await?)
    }
}
