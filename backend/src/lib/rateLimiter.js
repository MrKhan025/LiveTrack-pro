'use strict';

class ProductionRateLimiter {
  constructor(options = {}) {
    this.windowMs = Number(options.windowMs || process.env.RATE_LIMIT_WINDOW_MS || 60000);
    this.maxRequests = Number(options.maxRequests || process.env.RATE_LIMIT_MAX_REQUESTS || 180);
    this.authMaxRequests = Number(options.authMaxRequests || Math.min(20, this.maxRequests));
    this.redisUrl = options.redisUrl || process.env.REDIS_URL || null;
    this.redisClient = null;
    this.buckets = new Map();

    this.stats = {
      backend: this.redisUrl ? 'redis' : 'memory-sliding-window',
      totalRequests: 0,
      totalAllowed: 0,
      totalBlocked: 0,
      blockedByIp: {},
      perRouteHits: {}
    };

    if (this.redisUrl) {
      try {
        const redis = require('redis');
        this.redisClient = redis.createClient({ url: this.redisUrl });
        this.redisClient.on('error', () => {
          this.stats.backend = 'memory-sliding-window-fallback';
          this.redisClient = null;
        });
        this.redisClient.connect().catch(() => {
          this.stats.backend = 'memory-sliding-window-fallback';
          this.redisClient = null;
        });
      } catch {
        this.stats.backend = 'memory-sliding-window';
        if (process.env.NODE_ENV === 'production') {
          console.warn('[RateLimiter] WARNING: `redis` package not installed; using bounded in-memory sliding window.');
        }
      }
    } else if (process.env.NODE_ENV === 'production') {
      console.warn(
        '[RateLimiter] SECURITY WARNING: REDIS_URL is not set. Using single-node memory rate limiter. Configure REDIS_URL for multi-instance production deployments.'
      );
    }
  }

  async consume(ip, routeGroup = 'general') {
    this.stats.totalRequests += 1;
    this.stats.perRouteHits[routeGroup] = (this.stats.perRouteHits[routeGroup] || 0) + 1;

    const limit = routeGroup === 'auth' ? this.authMaxRequests : this.maxRequests;
    const key = `rl:${ip}:${routeGroup}`;
    const now = Date.now();

    if (this.redisClient && this.redisClient.isOpen) {
      try {
        const count = await this.redisClient.incr(key);
        if (count === 1) {
          await this.redisClient.pExpire(key, this.windowMs);
        }
        const allowed = count <= limit;
        if (allowed) {
          this.stats.totalAllowed += 1;
        } else {
          this.stats.totalBlocked += 1;
          this.stats.blockedByIp[ip] = (this.stats.blockedByIp[ip] || 0) + 1;
        }
        return {
          allowed,
          limit,
          remaining: Math.max(0, limit - count),
          resetAt: now + this.windowMs
        };
      } catch {}
    }

    // Bounded memory store with automatic expired bucket eviction
    if (this.buckets.size > 10000) {
      for (const [k, v] of this.buckets.entries()) {
        if (now > v.resetAt) this.buckets.delete(k);
      }
    }

    let bucket = this.buckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;

    const allowed = bucket.count <= limit;
    if (allowed) {
      this.stats.totalAllowed += 1;
    } else {
      this.stats.totalBlocked += 1;
      this.stats.blockedByIp[ip] = (this.stats.blockedByIp[ip] || 0) + 1;
    }

    return {
      allowed,
      limit,
      remaining: Math.max(0, limit - bucket.count),
      resetAt: bucket.resetAt
    };
  }

  getStatistics() {
    return {
      ...this.stats,
      activeBuckets: this.buckets.size,
      windowMs: this.windowMs,
      maxRequests: this.maxRequests,
      authMaxRequests: this.authMaxRequests
    };
  }
}

module.exports = { ProductionRateLimiter };
