pub mod routes;
pub mod templates;

use axum::{
    routing::{delete, get, post},
    Router,
};

use routes::AppState;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::config::Config;

pub fn build_router(pool: Arc<SqlitePool>, config: Arc<Config>) -> Router {
    let state = AppState { pool, config };

    Router::new()
        .route("/", get(routes::dashboard))
        .route("/keys", get(routes::keys_page))
        .route("/keys", post(routes::add_key))
        .route("/keys/:id", delete(routes::delete_key))
        .route("/policies", get(routes::policies_page))
        .route("/policies", post(routes::add_policy))
        .route("/policies/:id", delete(routes::delete_policy))
        .route("/logs", get(routes::logs_page))
        .route("/logs/partial", get(routes::logs_partial))
        .route("/config", get(routes::config_page))
        .route("/users", get(routes::users_page))
        .route("/users", post(routes::add_user))
        .route("/users/:email", delete(routes::delete_user))
        .route("/private-keys", get(routes::private_keys_page))
        .route("/private-keys", post(routes::add_private_key))
        .route("/private-keys/:id", delete(routes::delete_private_key))
        .route("/mailbox", get(routes::mailbox_page))
        .route("/queue", get(routes::queue_page))
        .route("/queue/partial", get(routes::queue_partial))
        .route("/queue/:id", delete(routes::delete_queue_entry))
        .with_state(state)
}
