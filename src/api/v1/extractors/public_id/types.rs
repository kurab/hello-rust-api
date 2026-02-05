/**
 * Responsibility
 *
 * 主な責務
 *  - リソースごとの「意味付きID型」を宣言する
 *  - scaffold によって機械的に増える部分を集約する
 *
 * 置くもの
 *  - PostTag, BookmarkTag などのタグ型
 *  - type PublicPostId = PublicId<PostTag> のような alias
 *  - 将来増える Comment / Like / Attachment など
 *
 * 置かないもの
 *  - decode ロジック
 *  - extractor 実装
 *  - AppState / codec 参照
 *
 * 変更理由
 *  - API が増えた
 *  - 新しいリソースを scaffold した
 */
use super::core::PublicId;

/**
 * 以下に pub で列挙するものは、./mod.rs 経由で全て公開されるため注意
 * pub use types::*;
 */
// posts
pub enum PostTag {}
pub type PublicPostId = PublicId<PostTag>;

// bookmarks
//pub enum BookmarkTag {}
//pub type PublicBookmarkId = PublicId<BookmarkTag>;
