use crate::repositories::{
    EmailVerificationRepository, EmailVerificationRepositoryTrait, PasswordResetRepository,
    PasswordResetRepositoryTrait, UserRepository, UserRepositoryTrait,
};
use crate::services::EmailService;
use axum::extract::FromRef;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: Arc<dyn UserRepositoryTrait>,
    pub email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait>,
    pub email_service: Arc<EmailService>,
    pub password_reset_repository: Arc<dyn PasswordResetRepositoryTrait>,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = PgPool::connect(database_url).await?;

        sqlx::migrate!("./migrations").run(&db).await?;

        let user_repository: Arc<dyn UserRepositoryTrait> =
            Arc::new(UserRepository::new(db.clone()));

        let email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait> =
            Arc::new(EmailVerificationRepository::new(db.clone()));

        let email_service =
            Arc::new(EmailService::new().expect("Failed to initialize email service"));

        let password_reset_repository = Arc::new(PasswordResetRepository::new(db.clone()));

        Ok(Self {
            db,
            user_repository,
            email_verification_repository,
            email_service,
            password_reset_repository,
        })
    }
}
