use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AppError {
    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("PGP error: {0}")]
    Pgp(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Relay error: {0}")]
    Relay(String),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Smtp(e.to_string())
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = format!("Error: {self}");
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
