-- Add migration script here

-- eneble uuid generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users
CREATE TABLE users (
    "userId" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "userName" TEXT NOT NULL UNIQUE,
    "imageUrl" VARCHAR(256),
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- posts
CREATE TABLE posts (
    "postId" BIGSERIAL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "authorId" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT posts_author_fk
        FOREIGN KEY("authorId")
        REFERENCES users ("userId")
        ON DELETE CASCADE
);

-- bookmarks
CREATE TABLE bookmarks (
    "bookmarkId" BIGSERIAL PRIMARY KEY,
    "postId" BIGINT NOT NULL,
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT bookmarks_post_fk
        FOREIGN KEY("postId")
        REFERENCES posts ("postId")
        ON DELETE SET NULL,
    CONSTRAINT bookmarks_user_fk
        FOREIGN KEY("userId")
        REFERENCES users ("userId")
        ON DELETE CASCADE
);

-- indexes
CREATE INDEX idx_posts_authorId ON posts ("authorId");
CREATE INDEX idx_bookmarks_userId ON bookmarks ("userId");
CREATE INDEX idx_bookmarks_postId ON bookmarks ("postId");

-- updatedAt auto update triggers
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW."updatedAt" = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_posts_updated_at
BEFORE UPDATE ON posts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
