use crate::db::DbPool;
use crate::memory_store::MemoryStore;
use crate::{auth::session::SessionManager, custom_middleware};

use super::handler;
use axum::routing::get;
use axum::{middleware, routing::post, Router};

#[derive(Clone)]
pub struct ApiRouter {
    pub db_pool: crate::db::DbPool,
    pub memory_store: crate::memory_store::MemoryStore,
    pub session_manager: SessionManager,
    pub http_client: reqwest::Client,
    pub google_oauth_manager: crate::auth::google::GoogleOAuthManager,
    pub github_oauth_manager: crate::auth::github::GithubOAuthManager,
}

impl ApiRouter {
    pub async fn new() -> Self {
        let db_pool = DbPool::new().await;
        let memory_store = MemoryStore::new().await;
        let session_manager = SessionManager::new(memory_store.clone()).await;
        let http_client = reqwest::Client::new();
        let google_oauth_manager =
            crate::auth::google::GoogleOAuthManager::new(memory_store.clone(), http_client.clone());

        let github_oauth_manager =
            crate::auth::github::GithubOAuthManager::new(memory_store.clone(), http_client.clone());

        ApiRouter {
            db_pool,
            memory_store,
            session_manager,
            http_client,
            google_oauth_manager,
            github_oauth_manager,
        }
    }

    pub async fn init(self) {
        let unprotected_routes = Router::new()
            .route("/signup", post(handler::signup))
            .route("/login", post(handler::login))
            .route("/auth/google/login", get(handler::login_with_google))
            .route("/auth/google/callback", get(handler::google_auth_callback))
            .route("/auth/github/login", get(handler::login_with_github))
            .route("/auth/github/callback", get(handler::github_auth_callback));

        let protected_routes = Router::new()
            .route("/authorize", post(handler::authorize))
            .route("/logout", post(handler::logout))
            .route("/otp", get(handler::generate_otp))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                custom_middleware::authorize,
            ));

        let routes = Router::new()
            .merge(unprotected_routes)
            .merge(protected_routes)
            .layer(custom_middleware::cors())
            .with_state(self);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
            .await
            .expect("Could not initialize listener");

        axum::serve(listener, routes)
            .await
            .expect("Could not initialize server")
    }
}
