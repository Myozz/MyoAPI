/**
 * =============================================================================
 * MyoAPI - CVE Routes (Supabase Version)
 * =============================================================================
 */

import { Hono } from 'hono';
import type { AppType } from '../types';

// =============================================================================
// TYPES
// =============================================================================

interface CveRecord {
    id: string;
    title: string | null;
    description: string;
    severity: string;
    cvss: { nvd: unknown; osv: unknown; vendor: unknown };
    epss: { score: number | null; percentile: number | null };
    kev: { is_known: boolean; date_added: string | null; due_date: string | null };
    affected: { nvd: unknown[]; osv: unknown[] };
    refs: { nvd: string[]; osv: string[]; vendor: string[] };
    aliases: string[];
    priority_score: number;
    published: string | null;
    modified: string | null;
    sources: string[];
}

interface SearchParams {
    q?: string;
    severity?: string[];
    isKev?: boolean;
    hasOsv?: boolean;
    limit: number;
    offset: number;
    sortBy: string;
    sortOrder: 'asc' | 'desc';
}

// =============================================================================
// HELPERS
// =============================================================================

function parseSearchParams(query: Record<string, string | undefined>): SearchParams {
    return {
        q: query['q'],
        severity: query['severity']?.split(',').map(s => s.trim().toUpperCase()),
        isKev: query['isKev'] === 'true' || query['isKev'] === '1',
        hasOsv: query['hasOsv'] === 'true' || query['hasOsv'] === '1',
        limit: Math.min(100, Math.max(1, parseInt(query['limit'] || '20'))),
        offset: Math.max(0, parseInt(query['offset'] || '0')),
        sortBy: query['sortBy'] || 'priority_score',
        sortOrder: query['sortOrder'] === 'asc' ? 'asc' : 'desc',
    };
}

function buildQuery(params: SearchParams): string {
    const filters: string[] = [];

    if (params.severity && params.severity.length > 0) {
        filters.push(`severity=in.(${params.severity.join(',')})`);
    }
    if (params.isKev) {
        filters.push(`kev->>is_known=eq.true`);
    }
    if (params.hasOsv) {
        filters.push(`sources=cs.{osv}`);
    }
    if (params.q) {
        // Simple text search
        filters.push(`or=(id.ilike.*${encodeURIComponent(params.q)}*,description.ilike.*${encodeURIComponent(params.q)}*)`);
    }

    const sortCol = {
        'priority': 'priority_score',
        'cvss': 'priority_score',  // Fallback, JSONB sorting complex
        'epss': 'priority_score',
        'published': 'published',
        'modified': 'modified',
        'priority_score': 'priority_score',
    }[params.sortBy] || 'priority_score';

    const order = `order=${sortCol}.${params.sortOrder}.nullslast`;
    const pagination = `limit=${params.limit}&offset=${params.offset}`;
    const filterStr = filters.length > 0 ? `&${filters.join('&')}` : '';

    return `?select=*${filterStr}&${order}&${pagination}`;
}

async function querySupabase(env: { SUPABASE_URL: string; SUPABASE_ANON_KEY: string }, query: string) {
    const response = await fetch(`${env.SUPABASE_URL}/rest/v1/cves${query}`, {
        headers: {
            'apikey': env.SUPABASE_ANON_KEY,
            'Authorization': `Bearer ${env.SUPABASE_ANON_KEY}`,
            'Prefer': 'count=exact',
        },
    });

    if (!response.ok) {
        throw new Error(`Supabase error: ${response.status}`);
    }

    const data = await response.json() as CveRecord[];
    const count = parseInt(response.headers.get('content-range')?.split('/')[1] || '0');
    return { data, count };
}

// =============================================================================
// ROUTES
// =============================================================================

export function createCveRoutes(): Hono<AppType> {
    const app = new Hono<AppType>();

    // GET /api/v1/cve/search
    app.get('/search', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const params = parseSearchParams(c.req.query());
            const queryStr = buildQuery(params);
            const { data, count } = await querySupabase(c.env, queryStr);

            return c.json({
                data,
                pagination: {
                    total: count,
                    limit: params.limit,
                    offset: params.offset,
                    hasMore: count > params.offset + params.limit,
                },
                meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs: Date.now() - startTime },
            });
        } catch (error) {
            return c.json({
                error: { code: 'DATABASE_ERROR', message: (error as Error).message },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 500);
        }
    });

    // GET /api/v1/cve/recent
    app.get('/recent', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') ?? '20')));
            const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0'));

            const { data, count } = await querySupabase(c.env, `?select=*&order=modified.desc.nullslast&limit=${limit}&offset=${offset}`);

            return c.json({
                data,
                pagination: { total: count, limit, offset, hasMore: count > offset + limit },
                meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs: Date.now() - startTime },
            });
        } catch (error) {
            return c.json({
                error: { code: 'DATABASE_ERROR', message: (error as Error).message },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 500);
        }
    });

    // GET /api/v1/cve/:id
    app.get('/:id', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();
        const cveId = c.req.param('id').toUpperCase();

        if (!cveId.match(/^CVE-\d{4}-\d{4,}$/i)) {
            return c.json({
                error: { code: 'INVALID_CVE_ID', message: `Invalid CVE ID format: ${cveId}` },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 400);
        }

        try {
            const { data } = await querySupabase(c.env, `?select=*&id=eq.${cveId}`);

            if (!data || data.length === 0) {
                return c.json({
                    error: { code: 'CVE_NOT_FOUND', message: `CVE ${cveId} not found` },
                    meta: { requestId, timestamp: new Date().toISOString() },
                }, 404);
            }

            return c.json({
                data: data[0],
                meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs: Date.now() - startTime },
            });
        } catch (error) {
            return c.json({
                error: { code: 'DATABASE_ERROR', message: (error as Error).message },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 500);
        }
    });

    return app;
}
