use crate::{auth::jwt::validate_token, models::User, state::AppState};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, StatusCode, request::Parts},
};
use uuid::Uuid;

pub struct RequireAuth(pub User);

pub struct OptionalAuth(pub Option<User>);

impl<S> FromRequestParts<S> for RequireAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let headers = &parts.headers;
        let token = extract_token_from_headers(headers).ok_or(StatusCode::UNAUTHORIZED)?;

        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let claims = validate_token(&token, &jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

        let user = app_state
            .user_repository
            .find_by_id(user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(RequireAuth(user))
    }
}

impl<S> FromRequestParts<S> for OptionalAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let headers = &parts.headers;
        let token = match extract_token_from_headers(headers) {
            Some(token) => token,
            None => return Ok(OptionalAuth(None)),
        };

        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let claims = match validate_token(&token, &jwt_secret) {
            Ok(claims) => claims,
            Err(_) => return Ok(OptionalAuth(None)),
        };

        let user_id = match Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return Ok(OptionalAuth(None)),
        };

        let user = app_state
            .user_repository
            .find_by_id(user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(OptionalAuth(user))
    }
}

fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization")?.to_str().ok()?;

    if auth_header.starts_with("Token ") {
        Some(auth_header[6..].to_string())
    } else {
        None
    }
}
