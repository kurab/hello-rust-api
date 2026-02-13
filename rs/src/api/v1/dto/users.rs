/*
 * Responsibility
 * - Users の request/response DTO
 * - validation (形式チェック) 用の validate() を持たせても良い
 */
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub user_name: String,
    pub image_url: Option<String>,
}

impl CreateUserRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.user_name.trim().is_empty() {
            return Err("user_name is required");
        }
        if let Some(url) = &self.image_url
            && url.len() > 256
        {
            return Err("image_url must be <= 256 chars");
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub user_name: Option<String>,
    // Tri-state:
    // - None: field missing (do not update)
    // - Some(None): null (set NULL)
    // - Some(Some(v)): set value
    pub image_url: Option<Option<String>>,
}

impl UpdateUserRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(name) = &self.user_name
            && name.trim().is_empty()
        {
            return Err("user_name cannot be empty");
        }
        if let Some(Some(url)) = &self.image_url
            && url.len() > 256
        {
            return Err("image_url must be <= 256 chars");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub user_name: String,
    pub image_url: Option<String>,
}
