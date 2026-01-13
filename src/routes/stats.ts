/**
 * =============================================================================
 * MyoAPI - Stats Routes (Supabase Version)
 * =============================================================================
 */

import { Hono } from 'hono';
import type { AppType } from '../types';

// =============================================================================
// ROUTES
// =============================================================================

export function createStatsRoutes(): Hono<AppType> {
    const app = new Hono<AppType>();

    // GET /api/v1/stats - Overview statistics
    app.get('/', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const headers = {
                'apikey': c.env.SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${c.env.SUPABASE_ANON_KEY}`,
                'Prefer': 'count=exact',
            };

            // Count queries - simpler approach
            const [totalRes, criticalRes, highRes, kevRes, osvRes] = await Promise.all([
                fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&limit=0`, { headers }),
                fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&severity=eq.CRITICAL&limit=0`, { headers }),
                fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&severity=eq.HIGH&limit=0`, { headers }),
                fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&kev->>is_known=eq.true&limit=0`, { headers }),
                fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&sources=cs.{osv}&limit=0`, { headers }),
            ]);

            const getCount = (res: Response) => parseInt(res.headers.get('content-range')?.split('/')[1] || '0');

            const stats = {
                totalCves: getCount(totalRes),
                bySeverity: {
                    CRITICAL: getCount(criticalRes),
                    HIGH: getCount(highRes),
                },
                kevCount: getCount(kevRes),
                osvCount: getCount(osvRes),
                sources: ['NVD', 'OSV', 'EPSS', 'CISA KEV'],
                database: 'Supabase PostgreSQL',
            };

            return c.json({
                data: stats,
                meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs: Date.now() - startTime },
            });
        } catch (error) {
            return c.json({
                error: { code: 'STATS_ERROR', message: (error as Error).message },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 500);
        }
    });

    // GET /api/v1/stats/health - Health check
    app.get('/health', async (c) => {
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const response = await fetch(`${c.env.SUPABASE_URL}/rest/v1/cves?select=id&limit=1`, {
                headers: {
                    'apikey': c.env.SUPABASE_ANON_KEY,
                    'Authorization': `Bearer ${c.env.SUPABASE_ANON_KEY}`,
                },
            });

            if (response.ok) {
                return c.json({ status: 'healthy', database: 'connected', timestamp: new Date().toISOString(), requestId });
            }
            throw new Error(`Supabase returned ${response.status}`);
        } catch (error) {
            return c.json({ status: 'unhealthy', error: (error as Error).message, timestamp: new Date().toISOString(), requestId }, 503);
        }
    });

    return app;
}
