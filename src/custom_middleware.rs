use crate::router::ApiRouter;

use axum::{
    body::Body,
    extract::{self, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
};

use axum_extra::extract::CookieJar;
use reqwest::Method;
use tower_http::cors::CorsLayer;

pub async fn authorize(
    extract::State(state): State<ApiRouter>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let session_id = match jar.get("session_id") {
        Some(session_id_cookie) => session_id_cookie.value(),
        None => {
            log::debug!("Authorization request failed: session_id not present in request");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if let Ok(user_id) = state.session_manager.get_session(session_id).await {
        log::debug!("User with id: {} has been authorized", user_id);
        let response = next.run(request).await;
        return Ok(response);
    } else {
        log::debug!("Authorization request failed: No session was found for the given session_id");
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub fn cors() -> CorsLayer {
    let origins = ["http://localhost:5173"
        .parse()
        .expect("Could not parse origin address for CORS.")];

    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(origins)
}
