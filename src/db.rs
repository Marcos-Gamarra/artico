use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use eyre::Result;
use std::str::FromStr;
use tokio_postgres::NoTls;

#[derive(Clone)]
pub struct DbPool {
    pub pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl DbPool {
    pub async fn new() -> Self {
        let db_config =
            tokio_postgres::config::Config::from_str("postgresql://artico:artico@localhost:6432")
                .expect("Could not connect to database");
        let db_manager =
            bb8_postgres::PostgresConnectionManager::new(db_config, tokio_postgres::NoTls);

        let db_pool = Pool::builder()
            .build(db_manager)
            .await
            .expect("Could not create connection pool");

        DbPool { pool: db_pool }
    }

    pub async fn get(&self) -> Result<PooledConnection<PostgresConnectionManager<NoTls>>> {
        Ok(self.pool.get().await?)
    }
}
