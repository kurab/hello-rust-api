/*
 * Responsibility
 * - Posts の request/response DTO
 * - 公開 ID を返す場合は、encode 済みの値を返す (内部 ID を漏らさない)
 */
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreatePostRequest {
    pub title: String,
    pub content: String,
    pub author_id: String, // UUID (users.userId)
}

impl CreatePostRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.title.trim().is_empty() {
            return Err("title is required");
        }
        if self.content.trim().is_empty() {
            return Err("content is required");
        }
        if self.author_id.trim().is_empty() {
            return Err("author_id is required");
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdatePostRequest {
    pub title: Option<String>,
    pub content: Option<String>,
}

impl UpdatePostRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(title) = &self.title
            && title.trim().is_empty()
        {
            return Err("title cannot be empty");
        }
        if let Some(content) = &self.content
            && content.trim().is_empty()
        {
            return Err("content cannot be empty");
        }

        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct PostResponse {
    pub id: String, // encoded
    pub title: String,
    pub content: String,
    pub author_id: String, // UUID
}
