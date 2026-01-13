/**
 * =============================================================================
 * MyoAPI - CORS Middleware
 * =============================================================================
 */

import { cors } from 'hono/cors';
import type { MiddlewareHandler } from 'hono';
import type { AppType } from '../types';

/**
 * CORS middleware factory
 */
export function corsMiddleware(): MiddlewareHandler<AppType> {
    return cors({
        origin: '*',
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
        exposeHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
        maxAge: 86400,
    });
}

/**
 * Request ID middleware - adds unique ID to each request
 */
export function requestIdMiddleware(): MiddlewareHandler<AppType> {
    return async (c, next) => {
        const requestId = c.req.header('X-Request-ID') ?? crypto.randomUUID();
        c.set('requestId', requestId);
        c.header('X-Request-ID', requestId);
        await next();
    };
}
