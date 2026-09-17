"use strict";

/** Fixed-window counter per key. `allow(key)` returns false once `limit` is hit. */
function createRateLimiter({ limit, windowMs, now = Date.now, maxKeys = 10000 }) {
  const buckets = new Map();

  function prune(t) {
    for (const [key, bucket] of buckets) {
      if (t - bucket.windowStart >= windowMs) buckets.delete(key);
    }
  }

  function allow(key) {
    const t = now();
    let bucket = buckets.get(key);
    if (!bucket || t - bucket.windowStart >= windowMs) {
      if (buckets.size >= maxKeys) prune(t);
      bucket = { windowStart: t, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count <= limit;
  }

  return { allow };
}

module.exports = { createRateLimiter };
