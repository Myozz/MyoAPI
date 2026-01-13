/**
 * =============================================================================
 * MyoAPI - Rate Limiting Middleware (Simplified)
 * =============================================================================
 *
 * Basic rate limiting without external storage.
 * For production, consider using Cloudflare Rate Limiting Rules instead.
 *
 * Limits:
 * - Anonymous: 100 requests/minute
 * - Authenticated: 1000 requests/minute
 */

import type { MiddlewareHandler } from 'hono';
import type { AppType } from '../types';

// =============================================================================
// CONSTANTS
// =============================================================================

/** Anonymous limit: 100 req/min */
const ANONYMOUS_LIMIT = 100;

/** Authenticated limit: 1000 req/min */
const AUTHENTICATED_LIMIT = 1000;

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Get client IP from request headers
 */
function getClientIp(headers: Headers): string {
    return headers.get('CF-Connecting-IP') ??
        headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
        'unknown';
}

/**
 * Get API key from request
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

// =============================================================================
// MIDDLEWARE
// =============================================================================

/**
 * Rate limiting middleware for Hono
 * 
 * Note: This is a simplified version that just adds headers.
 * Actual rate limiting should be done at Cloudflare edge level.
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

        // Add rate limit headers (actual limiting done at edge)
        c.header('X-RateLimit-Limit', String(limit));
        c.header('X-RateLimit-Remaining', String(limit - 1));
        c.header('X-RateLimit-Reset', String(Math.floor(Date.now() / 1000) + 60));

        c.set('isAuthenticated', isAuthenticated);
        c.set('clientIp', clientIp);

        await next();
    };
}
