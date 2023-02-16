-----
---
-- Zartbitter Database Model
---
-----

-- Artifacts are primarily identified by a name and must have a mandatory
-- description for documentation.
CREATE TABLE IF NOT EXISTS "artifacts"
(
  "identifier"  TEXT    NOT NULL PRIMARY KEY, -- artifact identifier, no version attached
  "description" TEXT    NOT NULL DEFAULT '',

  "file_name"   TEXT    NOT NULL, -- must contain {v}, is the version pattern match

  "is_public"   INTEGER NOT NULL DEFAULT 0, -- if non-zero, the artifact can be accessed without token

  CHECK(length("identifier") > 0),
  CHECK ("file_name" LIKE '%{v}%' AND length("file_name") > 3)
);

-- Each artifact can have one or more versions, where each version
-- contains a blob, checksums and some basic meta data.
CREATE TABLE IF NOT EXISTS "revisions"
(
  "artifact"          TEXT    NOT NULL REFERENCES "artifacts"("identifier"),

  "blob_storage_path" TEXT    NOT NULL,

  -- Checksums for this blob
  "md5sum"            TEXT    NOT NULL,
  "sha1sum"           TEXT    NOT NULL,
  "sha256sum"         TEXT    NOT NULL,
  "sha512sum"         TEXT    NOT NULL,

  "creation_date"     TEXT    NOT NULL,
  "size"              INTEGER NOT NULL,
  "mime_type"         TEXT    NOT NULL DEFAULT 'application/octet-stream',
  "version"           TEXT    NOT NULL
);

-- If any access token is provided, the access to an artifact is restricted.
-- There can be more than one access tokens per artifact.
CREATE TABLE IF NOT EXISTS "access_tokens"
(
  "artifact"   TEXT NOT NULL REFERENCES "artifacts"("identifier"),
  "token"      TEXT NOT NULL,
  "expires_at" TEXT DEFAULT NULL, -- optional timestamp with expiration date

  UNIQUE ("artifact", "token")
);

-- Artifacts can only be updated via upload tokens. Each token is composed
-- of a public and a private part. The public part can be used as an identification
-- of the artifact and must be unique, the secret part authenticates to upload
-- the artifact.
CREATE TABLE IF NOT EXISTS "upload_tokens"
(
  "artifact"       TEXT NOT NULL REFERENCES "artifacts"("identifier"),
  "upload_token"   TEXT NOT NULL UNIQUE,
  "security_token" TEXT NOT NULL,
  "expires_at"     TEXT DEFAULT NULL, -- optional timestamp with expiration date

  UNIQUE ("artifact", "upload_token")
);

-- Additional, arbitrary metadata per artifact. Basically a set of key-value pairs
-- that can add more information to artifacts if needed.
--
-- This is especially useful if the artifact is listed in indices, as a simple
-- metadata tag ("nuget", "") can be enough to expose artifacts into a repository.
CREATE TABLE IF NOT EXISTS "metadata"
(
  "artifact" TEXT NOT NULL REFERENCES "artifacts"("identifier"),
  
  "key"       TEXT    NOT NULL,
  "value"     TEXT    NOT NULL,
  "is_public" INTEGER NOT NULL DEFAULT 0, -- if non-zero, the metadata is displayed in the artifact information query

	UNIQUE("artifact", "key"),
  CHECK(length("key") > 0)
);
