-- Realmora backend schema.
--
-- Identity comes from account.harithkavish.com's OAuth server: `users.id` is
-- that account's stable UUID (the token's `sub`), never a Realmora-invented
-- id. Realmora never sees a password or the ecosystem session cookie -- only
-- this id and the profile fields userinfo hands back.

CREATE TABLE users (
  id TEXT PRIMARY KEY,               -- account UUID (oauth `sub`)
  username TEXT,                     -- `preferred_username`, may be null
  name TEXT NOT NULL,
  picture TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Opaque bearer sessions, DB-backed rather than signed, so a session can be
-- revoked (sign-out, or a credential-compromise cleanup) by deleting the row
-- instead of waiting out a JWT's expiry.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,               -- random token, held in an httpOnly cookie
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- One row per (user, provider). AES-GCM ciphertext; the key never leaves the
-- Worker's environment and the plaintext never leaves the token-exchange
-- and chat/provisioning code paths -- it is never sent back to a client.
CREATE TABLE credentials (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,            -- 'nvidia' | 'groq' | 'atlas'
  ciphertext TEXT NOT NULL,          -- base64
  iv TEXT NOT NULL,                  -- base64, 12-byte AES-GCM nonce
  -- Atlas credentials are a client_id:client_secret pair, not a bare key;
  -- everything else stores its whole secret in `ciphertext` and leaves this
  -- null.
  client_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, provider)
);

CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  system_prompt TEXT NOT NULL,
  memory_enabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_agents_user ON agents(user_id);

-- What's already been provisioned in a friend's own Atlas project, so
-- provisioning is a check-then-create instead of an unconditional create on
-- every agent. One collection and one vector index per user, shared across
-- all of that user's agents (tagged by agent_id at write/query time) --
-- Atlas free-tier (M0) clusters cap out at 3 search indexes per cluster, so
-- one-index-per-agent would strand a user after their third agent.
CREATE TABLE atlas_connections (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  cluster_name TEXT NOT NULL,
  database_name TEXT NOT NULL DEFAULT 'realmora',
  collection_name TEXT NOT NULL DEFAULT 'agent_memories',
  index_name TEXT NOT NULL DEFAULT 'vector_index',
  provisioned_at INTEGER NOT NULL
);
