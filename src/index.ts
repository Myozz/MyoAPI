/**
 * =============================================================================
 * MyoAPI - Main Entry Point
 * =============================================================================
 *
 * Cloudflare Workers entry point for the CVE Aggregator API.
 * Uses Hono framework for routing and middleware.
 *
 * Endpoints:
 * - GET /api/v1/cve/:id - Get CVE by ID
 * - GET /api/v1/cve/search - Search CVEs with filters
 * - GET /api/v1/cve/recent - Get recent CVEs
 * - GET /api/v1/stats - API statistics
 * - GET /api/v1/stats/health - Health check
 *
 * Scheduled:
 * - Daily sync at 02:00 UTC
 */

import { Hono } from 'hono';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';

import type { AppType } from './types';
import type { Env } from './types/env';
import { corsMiddleware, rateLimitMiddleware, requestIdMiddleware } from './middleware';
import { createCveRoutes, createStatsRoutes } from './routes';
import { runDailySync, triggerManualSync } from './scheduled';

// =============================================================================
// APP SETUP
// =============================================================================

const app = new Hono<AppType>();

// Global middleware
app.use('*', requestIdMiddleware());
app.use('*', corsMiddleware());
app.use('*', logger());
app.use('*', prettyJSON());

// Rate limiting on API routes
app.use('/api/*', rateLimitMiddleware());

// =============================================================================
// ROUTES
// =============================================================================

// Root endpoint - API info
app.get('/', (c) => {
    return c.json({
        name: 'MyoAPI',
        description: 'CVE Aggregator API - Centralized vulnerability data from multiple sources',
        version: '2.1.0',
        documentation: 'https://github.com/Myozz/MyoAPI',
        endpoints: {
            cve: '/api/v1/cve/:id',
            search: '/api/v1/cve/search',
            package: '/api/v1/cve/package?ecosystem=npm&name=lodash',
            bulk: '/api/v1/cve/bulk?limit=1000&offset=0',
            recent: '/api/v1/cve/recent',
            stats: '/api/v1/stats',
            health: '/api/v1/stats/health',
        },
        sources: ['NVD', 'OSV.dev', 'GHSA (GitHub)', 'EPSS (FIRST.org)', 'CISA KEV'],
        features: {
            cwe: 'Weakness types from NVD + GHSA',
            cpe: 'Product identifiers from NVD',
            fixed_versions: 'Remediation info from GHSA/OSV',
            priority_score: 'CVSS (30%) + EPSS (50%) + KEV (20%)',
            deduplication: 'CVE/GHSA IDs merged from all sources',
        },
        stats: {
            total_cves: 328233,
            with_nvd: 303815,
            with_osv: 22637,
            with_ghsa: '~10000',
            with_epss: 311012,
            kev_count: 1488,
        },
    });
});

// API v1 routes
const apiV1 = new Hono<AppType>();

// Mount CVE routes
apiV1.route('/cve', createCveRoutes());

// Mount stats routes
apiV1.route('/stats', createStatsRoutes());

// Manual sync trigger (requires secret key in production)
apiV1.post('/sync', async (c) => {
    const secretKey = c.req.query('key');
    const isDev = c.env.ENVIRONMENT === 'development';
    const validKey = secretKey === 'myoapi-sync-2024';

    if (!isDev && !validKey) {
        return c.json({ error: 'Sync requires valid key parameter' }, 403);
    }

    const result = await triggerManualSync(c.env);
    return c.json(result, result.success ? 200 : 500);
});

// Mount API v1
app.route('/api/v1', apiV1);

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 handler
app.notFound((c) => {
    return c.json(
        {
            error: {
                code: 'NOT_FOUND',
                message: `Endpoint ${c.req.method} ${c.req.path} not found`,
            },
            meta: {
                requestId: c.var.requestId ?? 'unknown',
                timestamp: new Date().toISOString(),
            },
        },
        404
    );
});

// Global error handler
app.onError((err, c) => {
    console.error('[Error]', err);

    return c.json(
        {
            error: {
                code: 'INTERNAL_ERROR',
                message: c.env.ENVIRONMENT === 'development' ? err.message : 'An internal error occurred',
            },
            meta: {
                requestId: c.var.requestId ?? 'unknown',
                timestamp: new Date().toISOString(),
            },
        },
        500
    );
});

// =============================================================================
// EXPORTS
// =============================================================================

export default {
    /**
     * HTTP request handler
     */
    fetch: app.fetch,

    /**
     * Scheduled event handler (Cron Triggers)
     */
    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        console.log(`[Scheduled] Cron triggered: ${event.cron}`);
        ctx.waitUntil(runDailySync(env));
    },
};
