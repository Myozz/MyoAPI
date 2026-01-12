/**
 * =============================================================================
 * MyoAPI - Rate Limiting Middleware
 * =============================================================================
 *
 * Sliding window rate limiting using Cloudflare KV.
 * Each IP/API key has a counter that resets after each window.
 *
 * Limits:
 * - Anonymous: 100 requests/minute
 * - Authenticated: 1000 requests/minute
 */

import type { MiddlewareHandler } from 'hono';
import type { AppType } from '../types';

// =============================================================================
// TYPES
// =============================================================================

interface RateLimitEntry {
    count: number;
    windowStart: number;
}

interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    reset: number;
    limit: number;
}

// =============================================================================
// CONSTANTS
// =============================================================================

/** Window duration: 60 seconds */
const WINDOW_MS = 60 * 1000;

/** Anonymous limit: 100 req/min */
const ANONYMOUS_LIMIT = 100;

/** Authenticated limit: 1000 req/min */
const AUTHENTICATED_LIMIT = 1000;

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Get client IP from request headers
 * Cloudflare provides CF-Connecting-IP header
 */
function getClientIp(headers: Headers): string {
    const cfIp = headers.get('CF-Connecting-IP');
    if (cfIp) return cfIp;

    const forwarded = headers.get('X-Forwarded-For');
    if (forwarded) {
        const first = forwarded.split(',')[0];
        if (first) return first.trim();
    }

    return 'unknown';
}

/**
 * Get API key from request
 * Supports both header and query param
 */
function getApiKey(headers: Headers, url: URL): string | null {
    const headerKey = headers.get('X-API-Key');
    if (headerKey) return headerKey;

    const authHeader = headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }

    return url.searchParams.get('api_key');
}

/**
 * Generate rate limit key for KV storage
 */
function getRateLimitKey(identifier: string): string {
    return `rate:${identifier}`;
}

// =============================================================================
// RATE LIMITER
// =============================================================================

/**
 * Check and update rate limit for an identifier
 */
async function checkRateLimit(
    kv: KVNamespace,
    identifier: string,
    limit: number
): Promise<RateLimitResult> {
    const key = getRateLimitKey(identifier);
    const now = Date.now();

    const entryJson = await kv.get(key);
    let entry: RateLimitEntry;

    if (entryJson) {
        entry = JSON.parse(entryJson) as RateLimitEntry;

        if (now - entry.windowStart >= WINDOW_MS) {
            entry = { count: 0, windowStart: now };
        }
    } else {
        entry = { count: 0, windowStart: now };
    }

    if (entry.count >= limit) {
        const reset = entry.windowStart + WINDOW_MS;
        return {
            allowed: false,
            remaining: 0,
            reset: Math.ceil(reset / 1000),
            limit,
        };
    }

    entry.count++;

    await kv.put(key, JSON.stringify(entry), {
        expirationTtl: 120,
    });

    const reset = entry.windowStart + WINDOW_MS;
    return {
        allowed: true,
        remaining: limit - entry.count,
        reset: Math.ceil(reset / 1000),
        limit,
    };
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

/**
 * Rate limiting middleware for Hono
 *
 * Adds rate limit headers to response:
 * - X-RateLimit-Limit: Limit per window
 * - X-RateLimit-Remaining: Remaining requests
 * - X-RateLimit-Reset: Unix timestamp when window resets
 */
export function rateLimitMiddleware(): MiddlewareHandler<AppType> {
    return async (c, next) => {
        const env = c.env;
        const headers = c.req.raw.headers;
        const url = new URL(c.req.url);

        const apiKey = getApiKey(headers, url);
        const clientIp = getClientIp(headers);

        const isAuthenticated = !!apiKey;
        const limit = isAuthenticated
            ? parseInt(env.RATE_LIMIT_AUTHENTICATED || String(AUTHENTICATED_LIMIT))
            : parseInt(env.RATE_LIMIT_ANONYMOUS || String(ANONYMOUS_LIMIT));

        const identifier = apiKey ?? clientIp;

        const result = await checkRateLimit(env.METADATA, identifier, limit);

        c.header('X-RateLimit-Limit', String(result.limit));
        c.header('X-RateLimit-Remaining', String(result.remaining));
        c.header('X-RateLimit-Reset', String(result.reset));

        if (!result.allowed) {
            return c.json(
                {
                    error: {
                        code: 'RATE_LIMIT_EXCEEDED',
                        message: `Rate limit exceeded. Try again after ${new Date(result.reset * 1000).toISOString()}`,
                        details: {
                            limit: result.limit,
                            reset: result.reset,
                            retryAfter: result.reset - Math.floor(Date.now() / 1000),
                        },
                    },
                    meta: {
                        requestId: c.var.requestId ?? crypto.randomUUID(),
                        timestamp: new Date().toISOString(),
                    },
                },
                429
            );
        }

        c.set('rateLimit', result);
        c.set('isAuthenticated', isAuthenticated);
        c.set('clientIp', clientIp);

        await next();
        return;
    };
}

/**
 * Request ID middleware
 * Generates unique ID for each request for tracing
 */
export function requestIdMiddleware(): MiddlewareHandler<AppType> {
    return async (c, next) => {
        const requestId =
            c.req.header('X-Request-ID') ?? c.req.header('CF-Ray') ?? crypto.randomUUID();

        c.set('requestId', requestId);
        c.header('X-Request-ID', requestId);

        await next();
        return;
    };
}

/**
 * CORS middleware
 * Allow cross-origin requests for public API
 */
export function corsMiddleware(): MiddlewareHandler<AppType> {
    return async (c, next) => {
        if (c.req.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
                    'Access-Control-Max-Age': '86400',
                },
            });
        }

        c.header('Access-Control-Allow-Origin', '*');

        await next();
        return;
    };
}
