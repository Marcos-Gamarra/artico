use bb8_redis::{
    bb8,
    redis::{AsyncCommands, FromRedisValue, ToRedisArgs},
    RedisConnectionManager,
};
use eyre::Result;

#[derive(Clone)]
pub struct MemoryStore {
    pub pool: bb8::Pool<RedisConnectionManager>,
}

impl MemoryStore {
    pub async fn new() -> Self {
        let manager = RedisConnectionManager::new("redis://localhost:6379")
            .expect("Could not connect to redis instance. Stopping execution...");

        let pool = bb8::Pool::builder()
            .build(manager)
            .await
            .expect("Could not create connection pool for redis. Stopping execution...");

        MemoryStore { pool }
    }

    pub async fn exists<K>(&self, key: K) -> Result<bool>
    where
        K: ToRedisArgs + Sync + Send,
    {
        let mut conn = self.pool.get().await?;

        Ok(conn.exists(key).await?)
    }

    pub async fn get<K, RV>(&self, key: K) -> Result<RV>
    where
        K: ToRedisArgs + Sync + Send,
        RV: FromRedisValue + Sync + Send,
    {
        let mut conn = self.pool.get().await?;

        Ok(conn.get::<_, RV>(key).await?)
    }

    pub async fn set<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: ToRedisArgs + Sync + Send,
        V: ToRedisArgs + Sync + Send,
    {
        let mut conn = self.pool.get().await?;
        () = conn.set(key, value).await?;
        Ok(())
    }

    pub async fn remove<K, RV>(&self, key: K) -> Result<RV>
    where
        K: ToRedisArgs + Sync + Send,
        RV: FromRedisValue + Sync + Send,
    {
        let removed_value = self.pool.get().await?.del::<K, RV>(key).await?;
        Ok(removed_value)
    }
}
