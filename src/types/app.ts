/**
 * =============================================================================
 * MyoAPI - Hono App Types
 * =============================================================================
 *
 * Type definitions for Hono context variables used across the app.
 */

import type { Env } from './env';

/**
 * Context variables stored via c.set() / c.get()
 */
export interface Variables {
    requestId: string;
    clientIp: string;
    isAuthenticated: boolean;
    rateLimit: {
        allowed: boolean;
        remaining: number;
        reset: number;
        limit: number;
    };
}

/**
 * Full Hono app type with bindings and variables
 */
export type AppType = {
    Bindings: Env;
    Variables: Variables;
};
