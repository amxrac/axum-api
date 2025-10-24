use axum::{
    Router,
    routing::{get, post},
};
use std::env;

use realworld_axum_api::{
    handlers::{
        current_user, forgot_password, health_check, login, register, reset_password, verify_email,
    },
    state::AppState,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file or environment");

    let app_state = AppState::new(&database_url)
        .await
        .expect("Failed to connect to database");

    println!("Connected to database successfully!");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/users", post(register))
        .route("/api/users/login", post(login))
        .route("/api/user", get(current_user))
        .route("/api/auth/verify-email", get(verify_email))
        .route("api/auth/forgot-password", post(forgot_password))
        .route("api/auth/reset-password", post(reset_password))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("server is running on http://0.0.0.0:3000");
    println!("Available endpoints:");
    println!("  POST /api/users         - Register new user");
    println!("  POST /api/users/login   - Login existing user");
    println!("  GET  /api/user          - Get current user (requires auth)");
    println!("  GET  /health            - Health check");
    println!("  GET /api/auth/verify-email - Verify email");

    axum::serve(listener, app).await.unwrap();
}
