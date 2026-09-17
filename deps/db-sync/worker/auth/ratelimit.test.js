"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createRateLimiter } = require("./ratelimit");

test("rate limiter allows `limit` hits per window and resets afterwards", () => {
  let t = 0;
  const limiter = createRateLimiter({ limit: 2, windowMs: 1000, now: () => t });
  assert.equal(limiter.allow("a"), true);
  assert.equal(limiter.allow("a"), true);
  assert.equal(limiter.allow("a"), false);
  assert.equal(limiter.allow("b"), true);
  t = 1000;
  assert.equal(limiter.allow("a"), true);
});

test("rate limiter prunes stale keys when the key cap is reached", () => {
  let t = 0;
  const limiter = createRateLimiter({ limit: 1, windowMs: 10, now: () => t, maxKeys: 2 });
  limiter.allow("a");
  limiter.allow("b");
  t = 20;
  assert.equal(limiter.allow("c"), true);
  assert.equal(limiter.allow("a"), true);
});
