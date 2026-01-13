/**
 * =============================================================================
 * MyoAPI - Cloudflare Workers Environment Types
 * =============================================================================
 *
 * Type definitions for Cloudflare Workers bindings (KV, Environment Variables).
 * Used for type-safe access to resources within Workers.
 */

/**
 * Cloudflare Workers Environment Bindings
 *
 * These bindings are defined in wrangler.toml and injected into Worker runtime.
 */
export interface Env {
    // ---------------------------------------------------------------------------
    // KV Namespaces
    // ---------------------------------------------------------------------------

    /**
     * Storage for CVE records
     * Key format: "cve:{CVE-ID}" -> JSON string of CveRecord
     */
    CVE_DATA: KVNamespace;

    /**
     * Storage for indexes for fast lookups
     * Key formats:
     * - "idx:eco:{ecosystem}" -> JSON array of CVE IDs
     * - "idx:sev:{severity}" -> JSON array of CVE IDs
     * - "idx:kev" -> JSON array of KEV CVE IDs
     * - "idx:recent" -> JSON array of recently modified CVE IDs
     */
    CVE_INDEX: KVNamespace;

    /**
     * Metadata and rate limiting
     * Key formats:
     * - "meta:stats" -> ApiStats JSON
     * - "meta:sync" -> SyncMetadata JSON
     * - "rate:{ip}" -> Rate limit counter
     */
    METADATA: KVNamespace;

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
    // Secrets (set via wrangler secret put)
    // ---------------------------------------------------------------------------

    /** NVD API key (optional, increases rate limit) */
    NVD_API_KEY?: string;

    // ---------------------------------------------------------------------------
    // Supabase
    // ---------------------------------------------------------------------------

    /** Supabase project URL */
    SUPABASE_URL: string;

    /** Supabase anon/public key for read access */
    SUPABASE_ANON_KEY: string;
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
