use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArticoError {
    //App errors
    #[error("Memory store error.")]
    MemStoreError,

    #[error("Database error.")]
    DbError,

    #[error("External service error.")]
    ExternalServiceError,

    #[error("Generic application error.")]
    GenericAppError,

    #[error("Internal server error.")]
    InternalServerError,

    //Client errors
    #[error("Unauthorized request.")]
    Unauthorized,

    #[error("Bad request.")]
    BadRequest,

    #[error("Not found.")]
    NotFound,

    #[error("Forbidden request.")]
    Forbidden,
}

impl IntoResponse for ArticoError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            // Internal errors
            ArticoError::InternalServerError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server Error")
            }
            ArticoError::MemStoreError => (StatusCode::INTERNAL_SERVER_ERROR, "Memory store error"),
            ArticoError::ExternalServiceError => {
                (StatusCode::SERVICE_UNAVAILABLE, "External service error")
            }
            ArticoError::DbError => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            ArticoError::GenericAppError => (StatusCode::INTERNAL_SERVER_ERROR, "Generic error"),

            // Client errors
            ArticoError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            ArticoError::BadRequest => (StatusCode::BAD_REQUEST, "Bad request"),
            ArticoError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            ArticoError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
        };

        (status, message).into_response()
    }
}

impl From<reqwest::Error> for ArticoError {
    fn from(_: reqwest::Error) -> Self {
        ArticoError::ExternalServiceError
    }
}
