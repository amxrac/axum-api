use crate::state::AppState;
use axum::{Json, extract::State};
use serde_json::{Value, json};

pub async fn health_check(State(state): State<AppState>) -> Json<Value> {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Server is running"
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Json(json!({
                "status": "error",
                "database": "disconnected",
                "error": e.to_string()
            }))
        }
    }
}
