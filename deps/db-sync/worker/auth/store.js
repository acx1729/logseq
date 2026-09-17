"use strict";

const AUTH_MIGRATIONS = [
  {
    id: "0002-auth-tables",
    statements: [
      "create table if not exists auth_nonces (" +
        "nonce TEXT primary key," +
        "created_at INTEGER not null," +
        "expires_at INTEGER not null" +
        ")",
      "create table if not exists auth_codes (" +
        "code_hash TEXT primary key," +
        "user_id TEXT not null," +
        "code_challenge TEXT not null," +
        "redirect_uri TEXT not null," +
        "created_at INTEGER not null," +
        "expires_at INTEGER not null" +
        ")",
    ],
  },
  {
    id: "0004-drop-auth-codes",
    statements: ["drop table if exists auth_codes"],
  },
];

/**
 * Nonce storage on the adapter's index database (better-sqlite3). The table
 * is created by the index migrations (AUTH_MIGRATIONS, applied by
 * logseq.db-sync.index/<index-init!), so the store must be created after
 * they ran.
 */
function createAuthStore(db) {
  const insertNonce = db.prepare("insert into auth_nonces (nonce, created_at, expires_at) values (?, ?, ?)");
  const deleteNonce = db.prepare("delete from auth_nonces where nonce = ? and expires_at > ?");
  const pruneNonces = db.prepare("delete from auth_nonces where expires_at <= ?");

  return {
    putNonce(nonce, createdAt, expiresAt) {
      insertNonce.run(nonce, createdAt, expiresAt);
    },
    /** Deletes the nonce; true only when it existed and had not expired. */
    consumeNonce(nonce, now) {
      return deleteNonce.run(nonce, now).changes === 1;
    },
    prune(now) {
      pruneNonces.run(now);
    },
  };
}

module.exports = { AUTH_MIGRATIONS, createAuthStore };
