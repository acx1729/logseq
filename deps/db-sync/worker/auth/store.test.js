"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const Database = require("better-sqlite3");
const { AUTH_MIGRATIONS, createAuthStore } = require("./store");

function openDb() {
  const db = new Database(":memory:");
  for (const migration of AUTH_MIGRATIONS) {
    for (const statement of migration.statements) db.exec(statement);
  }
  return db;
}

test("nonces are single use and expire", () => {
  const store = createAuthStore(openDb());
  store.putNonce("n1", 1000, 2000);
  assert.equal(store.consumeNonce("n1", 1500), true);
  assert.equal(store.consumeNonce("n1", 1500), false);
  store.putNonce("n2", 1000, 2000);
  assert.equal(store.consumeNonce("n2", 2000), false);
  assert.equal(store.consumeNonce("unknown", 0), false);
});

test("codes are returned once with their record and expire", () => {
  const store = createAuthStore(openDb());
  const record = { userId: "0xabc", codeChallenge: "c", redirectUri: "logseq://auth/callback" };
  store.putCode("h1", record, 1000, 2000);
  assert.deepEqual(store.consumeCode("h1", 1500), record);
  assert.equal(store.consumeCode("h1", 1500), null);
  store.putCode("h2", record, 1000, 2000);
  assert.equal(store.consumeCode("h2", 2500), null);
  assert.equal(store.consumeCode("h2", 1500), null);
});

test("prune removes expired rows only", () => {
  const db = openDb();
  const store = createAuthStore(db);
  store.putNonce("old", 0, 10);
  store.putNonce("new", 0, 100);
  store.putCode("old", { userId: "u", codeChallenge: "c", redirectUri: "r" }, 0, 10);
  store.prune(50);
  assert.equal(db.prepare("select count(*) as n from auth_nonces").get().n, 1);
  assert.equal(db.prepare("select count(*) as n from auth_codes").get().n, 0);
  assert.equal(store.consumeNonce("new", 50), true);
});

test("migration statements are idempotent and portable", () => {
  const db = openDb();
  for (const migration of AUTH_MIGRATIONS) {
    assert.match(migration.id, /^\d{4}-[a-z-]+$/);
    for (const statement of migration.statements) {
      assert.doesNotMatch(statement, /autoincrement|json_each|pragma|insert or replace/i);
      db.exec(statement);
    }
  }
  const store = createAuthStore(db);
  store.putNonce("n", 0, 10);
  assert.equal(store.consumeNonce("n", 5), true);
});
