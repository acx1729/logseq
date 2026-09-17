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
];

/**
 * Nonce and authorization-code storage on the adapter's index database
 * (better-sqlite3). The tables are created by the index migrations
 * (AUTH_MIGRATIONS, applied by logseq.db-sync.index/<index-init!>), so the
 * store must be created after they ran.
 */
function createAuthStore(db) {
  const insertNonce = db.prepare("insert into auth_nonces (nonce, created_at, expires_at) values (?, ?, ?)");
  const deleteNonce = db.prepare("delete from auth_nonces where nonce = ? and expires_at > ?");
  const insertCode = db.prepare(
    "insert into auth_codes (code_hash, user_id, code_challenge, redirect_uri, created_at, expires_at) values (?, ?, ?, ?, ?, ?)",
  );
  const selectCode = db.prepare(
    "select user_id, code_challenge, redirect_uri from auth_codes where code_hash = ? and expires_at > ?",
  );
  const deleteCode = db.prepare("delete from auth_codes where code_hash = ?");
  const pruneNonces = db.prepare("delete from auth_nonces where expires_at <= ?");
  const pruneCodes = db.prepare("delete from auth_codes where expires_at <= ?");

  return {
    putNonce(nonce, createdAt, expiresAt) {
      insertNonce.run(nonce, createdAt, expiresAt);
    },
    /** Deletes the nonce; true only when it existed and had not expired. */
    consumeNonce(nonce, now) {
      return deleteNonce.run(nonce, now).changes === 1;
    },
    putCode(codeHash, { userId, codeChallenge, redirectUri }, createdAt, expiresAt) {
      insertCode.run(codeHash, userId, codeChallenge, redirectUri, createdAt, expiresAt);
    },
    /** Returns the code record once and deletes it; null when unknown, used or expired. */
    consumeCode(codeHash, now) {
      const row = selectCode.get(codeHash, now);
      deleteCode.run(codeHash);
      if (!row) return null;
      return { userId: row.user_id, codeChallenge: row.code_challenge, redirectUri: row.redirect_uri };
    },
    prune(now) {
      pruneNonces.run(now);
      pruneCodes.run(now);
    },
  };
}

module.exports = { AUTH_MIGRATIONS, createAuthStore };
