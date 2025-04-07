mod auth;
mod custom_middleware;
mod db;
mod handler;
mod memory_store;
mod router;
mod error;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .target(env_logger::Target::Stdout)
        .init();
    log::info!("Starting server");
    let api_router = router::ApiRouter::new().await;
    api_router.init().await;
}
