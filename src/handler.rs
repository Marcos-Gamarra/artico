use crate::{
    auth::{self, AuthorizationCode, UserCredentials},
    error::ArticoError,
    router::ApiRouter,
};
use axum::{
    extract::{self, Query, State},
    http::StatusCode,
    response::Response,
};
use axum_extra::extract::CookieJar;
use log::{error, warn};

pub async fn signup(
    extract::State(state): State<ApiRouter>,
    extract::Json(user_credentials): extract::Json<UserCredentials>,
) -> Result<StatusCode, ArticoError> {
    let db_pool = state.db_pool;
    match user_credentials.signup(db_pool).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            warn!("Could not signup user -> {e}");
            Err(ArticoError::InternalServerError)
        }
    }
}

pub async fn login(
    extract::State(state): State<ApiRouter>,
    extract::Json(user_builder): extract::Json<UserCredentials>,
) -> Result<StatusCode, ArticoError> {
    let db_pool = state.db_pool;
    let session_manager = state.session_manager;
    if let Ok(_) = user_builder.login(db_pool, session_manager).await {
        Ok(StatusCode::OK)
    } else {
        Err(ArticoError::Unauthorized)
    }
}

pub async fn logout(
    extract::State(state): State<ApiRouter>,
    jar: CookieJar,
) -> Result<StatusCode, ArticoError> {
    let session_id = match jar.get("session_id") {
        Some(session_id_cookie) => session_id_cookie.value(),
        None => {
            log::debug!("Authorization request failed: session_id not present in request");
            return Err(ArticoError::Unauthorized);
        }
    };

    match state.session_manager.remove_session(session_id).await {
        Ok(_) => Ok(StatusCode::OK),

        Err(e) => {
            error!("Error while attemting to logout user -> {e}",);
            Err(ArticoError::InternalServerError)
        }
    }
}

pub async fn login_with_google(
    extract::State(state): State<ApiRouter>,
) -> Result<Response, ArticoError> {
    let redirect_url_generation_result = state.google_oauth_manager.generate_redirect_uri().await;

    let redirect_url = match redirect_url_generation_result {
        Ok(url) => url,
        Err(e) => {
            warn!("Could not generate redirect uri at login_with_google -> {e}",);
            return Err(ArticoError::InternalServerError);
        }
    };

    match Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", redirect_url)
        .body(axum::body::Body::empty())
    {
        Ok(response) => Ok(response),
        Err(_) => {
            return Err(ArticoError::GenericAppError);
        }
    }
}

pub async fn google_auth_callback(
    extract::State(state): State<ApiRouter>,
    Query(authorization_code): Query<AuthorizationCode>,
) -> Result<StatusCode, ArticoError> {
    let is_state_valid = authorization_code
        .is_state_token_valid(&state.memory_store)
        .await;

    if let Err(e) = authorization_code
        .remove_state_token(state.memory_store)
        .await
    {
        error!("Could not remove session from memory_store at google_auth_callback -> {e}",);
        return Err(ArticoError::InternalServerError);
    }

    if let Err(e) = is_state_valid {
        warn!("Failed to validate state param for google_auth_callback. Error -> {e}");
        return Err(ArticoError::Unauthorized);
    }

    let access_token_result = state
        .google_oauth_manager
        .get_access_token(authorization_code)
        .await;

    match access_token_result {
        Ok(access_token) => {
            let claims = state
                .google_oauth_manager
                .get_claims(&access_token)
                .await
                .map_err(|e| {
                    warn!("Could not get claims for id_token at google_auth_callback -> {e}",);
                    return ArticoError::ExternalServiceError;
                })?;

            println!("sub: {}", claims.sub);

            return Ok(StatusCode::OK);
        }

        Err(e) => {
            warn!("Failed to get access token from google. Error -> {e}");
            Err(ArticoError::ExternalServiceError)
        }
    }
}

pub async fn login_with_github(
    extract::State(state): State<ApiRouter>,
) -> Result<Response, ArticoError> {
    let redirect_url_generation_result = state.github_oauth_manager.generate_redirect_uri().await;

    let redirect_url = match redirect_url_generation_result {
        Ok(url) => url,
        Err(e) => {
            warn!("Could not generate redirect uri at login_with_google -> {e}",);
            return Err(ArticoError::InternalServerError);
        }
    };

    match Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", redirect_url)
        .body(axum::body::Body::empty())
    {
        Ok(response) => Ok(response),
        Err(_) => {
            return Err(ArticoError::GenericAppError);
        }
    }
}

pub async fn github_auth_callback(
    extract::State(state): State<ApiRouter>,
    Query(authorization_code): Query<AuthorizationCode>,
) -> Result<StatusCode, ArticoError> {
    let is_state_valid = authorization_code
        .is_state_token_valid(&state.memory_store)
        .await;

    if let Err(e) = authorization_code
        .remove_state_token(state.memory_store)
        .await
    {
        warn!("Could not remove session from memory_store at github_auth_callback -> {e}",);
        return Err(ArticoError::InternalServerError);
    }

    if let Err(e) = is_state_valid {
        warn!("Failed to validate state param for github_auth_callback. Error -> {e}");
        return Err(ArticoError::Unauthorized);
    }

    let access_token_result = state
        .github_oauth_manager
        .get_access_token(authorization_code)
        .await;

    match access_token_result {
        Ok(access_token) => {
            let user_info_result = state
                .github_oauth_manager
                .get_user_info(&access_token.access_token)
                .await;

            println!("user_info_result: {:?}", user_info_result);

            return Ok(StatusCode::OK);
        }

        Err(e) => {
            warn!("Failed to get access token from github. Error -> {e}");
            Err(ArticoError::ExternalServiceError)
        }
    }
}

pub async fn authorize() -> Result<StatusCode, ()> {
    Ok(StatusCode::OK)
}

pub async fn generate_otp() -> Result<String, StatusCode> {
    let otp = auth::generate_token();

    Ok(otp)
}
