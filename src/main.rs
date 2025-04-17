mod auth;
mod custom_middleware;
mod db;
mod error;
mod handler;
mod memory_store;
mod router;

refinery::embed_migrations!("migrations");

#[tokio::main]
async fn main() {
    env_logger::builder()
        .target(env_logger::Target::Stdout)
        .init();
    log::info!("Starting server");
    let api_router = router::ApiRouter::new().await;

    // run migrations
    let mut conn = api_router
        .db_pool
        .pool
        .dedicated_connection()
        .await
        .expect("Could not get a connection from the pool");

    migrations::runner()
        .run_async(&mut conn)
        .await
        .expect("Could not run migrations");

    api_router.init().await;
}
