/**
 * =============================================================================
 * MyoAPI - Cloudflare Workers Environment Types
 * =============================================================================
 *
 * Type definitions for Cloudflare Workers bindings.
 * Now using Supabase PostgreSQL instead of KV.
 */

/**
 * Cloudflare Workers Environment Bindings
 */
export interface Env {
    // ---------------------------------------------------------------------------
    // Environment Variables
    // ---------------------------------------------------------------------------

    /** Current environment: "development" | "production" */
    ENVIRONMENT: string;

    /** API version prefix */
    API_VERSION: string;

    /** Rate limit for anonymous requests (per minute) */
    RATE_LIMIT_ANONYMOUS: string;

    /** Rate limit for authenticated requests (per minute) */
    RATE_LIMIT_AUTHENTICATED: string;

    // ---------------------------------------------------------------------------
    // Supabase
    // ---------------------------------------------------------------------------

    /** Supabase project URL */
    SUPABASE_URL: string;

    /** Supabase anon/public key for read access */
    SUPABASE_ANON_KEY: string;

    // ---------------------------------------------------------------------------
    // Secrets (optional)
    // ---------------------------------------------------------------------------

    /** NVD API key (optional, for sync scripts) */
    NVD_API_KEY?: string;
}

/**
 * Request context with execution metadata
 */
export interface RequestContext {
    /** Unique request ID for tracing */
    requestId: string;

    /** Request start time */
    startTime: number;

    /** Client IP address */
    clientIp: string;

    /** API key if present */
    apiKey?: string;

    /** Execution context from Cloudflare */
    ctx: ExecutionContext;
}

/**
 * Scheduled event context for cron jobs
 */
export interface ScheduledContext {
    /** Cron expression that triggered this event */
    cron: string;

    /** Scheduled time (Unix timestamp) */
    scheduledTime: number;
}
