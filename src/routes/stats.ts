/**
 * =============================================================================
 * MyoAPI - Stats Routes
 * =============================================================================
 *
 * API endpoints for statistics:
 * - GET /api/v1/stats - Overview statistics
 * - GET /api/v1/stats/ecosystems - Stats by ecosystem
 * - GET /api/v1/stats/health - Health check
 */

import { Hono } from 'hono';
import type { ApiStats, SingleResponse } from '../models/cve';
import type { AppType } from '../types';

// =============================================================================
// ROUTES
// =============================================================================

/**
 * Create stats routes
 */
export function createStatsRoutes(): Hono<AppType> {
    const app = new Hono<AppType>();

    // GET /api/v1/stats - Overview statistics
    app.get('/', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const statsData = await c.env.METADATA.get('meta:stats');

        if (!statsData) {
            const emptyStats: ApiStats = {
                totalCves: 0,
                bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
                byEcosystem: {},
                kevCount: 0,
                lastSyncTime: 'Never',
                sources: {
                    osv: { lastSync: 'Never', count: 0 },
                    epss: { lastSync: 'Never', date: 'Never' },
                    kev: { lastSync: 'Never', count: 0 },
                },
            };

            return c.json({
                data: emptyStats,
                meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs: Date.now() - startTime },
            } satisfies SingleResponse<ApiStats>);
        }

        const stats = JSON.parse(statsData) as ApiStats;
        const executionTimeMs = Date.now() - startTime;

        const response: SingleResponse<ApiStats> = {
            data: stats,
            meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs },
        };

        return c.json(response);
    });

    // GET /api/v1/stats/ecosystems - Stats by ecosystem
    app.get('/ecosystems', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const statsData = await c.env.METADATA.get('meta:stats');
        let ecosystemStats: Record<string, number> = {};

        if (statsData) {
            const stats = JSON.parse(statsData) as ApiStats;
            ecosystemStats = stats.byEcosystem;
        }

        const executionTimeMs = Date.now() - startTime;

        return c.json({
            data: ecosystemStats,
            meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs },
        });
    });

    // GET /api/v1/stats/health - Health check endpoint
    app.get('/health', async (c) => {
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            await c.env.METADATA.get('meta:sync');

            return c.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                requestId,
            });
        } catch (error) {
            return c.json(
                {
                    status: 'unhealthy',
                    error: error instanceof Error ? error.message : 'Unknown error',
                    timestamp: new Date().toISOString(),
                    requestId,
                },
                503
            );
        }
    });

    return app;
}
