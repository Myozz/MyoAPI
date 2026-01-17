/**
 * =============================================================================
 * MyoAPI - CVE Routes (Supabase Version v2)
 * =============================================================================
 * Enhanced for MyoSC integration with package search and priority severity
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
    cvss: { nvd: CvssData | null; osv: CvssData | null; ghsa: CvssData | null; vendor: unknown };
    epss: { score: number | null; percentile: number | null };
    kev: { is_known: boolean; date_added: string | null; due_date: string | null };
    affected: { nvd: unknown[]; osv: AffectedPackage[] };
    refs: { nvd: string[]; osv: string[]; ghsa: string[]; vendor: string[] };
    aliases: string[];
    priority_score: number;
    published: string | null;
    modified: string | null;
    sources: string[];
}

interface CvssData {
    score: number;
    vector: string | null;
    version: string;
}

interface AffectedPackage {
    package: string;
    ecosystem: string;
    versions: string[];
}

interface SearchParams {
    q?: string;
    severity?: string[];
    isKev?: boolean;
    hasOsv?: boolean;
    ecosystem?: string;
    package?: string;
    limit: number;
    offset: number;
    sortBy: string;
    sortOrder: 'asc' | 'desc';
}

interface EnhancedCveResponse {
    id: string;
    title: string | null;
    description: string;
    severity: string;
    priority_severity: string;
    priority_score: number;
    cvss_score: number | null;
    epss_score: number | null;
    epss_percentile: number | null;
    is_kev: boolean;
    kev_date_added: string | null;
    ghsa_id: string | null;
    aliases: string[];
    affected_packages: AffectedPackage[];
    refs: string[];
    published: string | null;
    modified: string | null;
    sources: string[];
}

// =============================================================================
// HELPERS
// =============================================================================

function getPrioritySeverity(score: number): string {
    if (score >= 0.7) return 'CRITICAL';
    if (score >= 0.5) return 'HIGH';
    if (score >= 0.3) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'UNKNOWN';
}

function getBestCvssScore(cvss: CveRecord['cvss']): number | null {
    return cvss.nvd?.score ?? cvss.ghsa?.score ?? cvss.osv?.score ?? null;
}

function getGhsaId(aliases: string[]): string | null {
    return aliases.find(a => a.startsWith('GHSA-')) ?? null;
}

function enhanceCveRecord(record: CveRecord): EnhancedCveResponse {
    const allRefs = [
        ...(record.refs.nvd || []),
        ...(record.refs.osv || []),
        ...(record.refs.ghsa || []),
        ...(record.refs.vendor || [])
    ].filter((v, i, a) => a.indexOf(v) === i).slice(0, 20);

    return {
        id: record.id,
        title: record.title,
        description: record.description,
        severity: record.severity,
        priority_severity: getPrioritySeverity(record.priority_score),
        priority_score: record.priority_score,
        cvss_score: getBestCvssScore(record.cvss),
        epss_score: record.epss.score,
        epss_percentile: record.epss.percentile,
        is_kev: record.kev.is_known,
        kev_date_added: record.kev.date_added,
        ghsa_id: getGhsaId(record.aliases),
        aliases: record.aliases,
        affected_packages: record.affected.osv || [],
        refs: allRefs,
        published: record.published,
        modified: record.modified,
        sources: record.sources,
    };
}

function parseSearchParams(query: Record<string, string | undefined>): SearchParams {
    return {
        q: query['q'],
        severity: query['severity']?.split(',').map(s => s.trim().toUpperCase()),
        isKev: query['isKev'] === 'true' || query['kev'] === 'true',
        hasOsv: query['hasOsv'] === 'true' || query['osv'] === 'true',
        ecosystem: query['ecosystem'],
        package: query['package'] || query['name'],
        limit: Math.min(1000, Math.max(1, parseInt(query['limit'] || '50'))),
        offset: Math.max(0, parseInt(query['offset'] || '0')),
        sortBy: query['sortBy'] || query['sort'] || 'priority_score',
        sortOrder: query['sortOrder'] === 'asc' || query['order'] === 'asc' ? 'asc' : 'desc',
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
        filters.push(`or=(id.ilike.*${encodeURIComponent(params.q)}*,description.ilike.*${encodeURIComponent(params.q)}*)`);
    }

    const sortCol = {
        'priority': 'priority_score',
        'priority_score': 'priority_score',
        'cvss': 'priority_score',
        'epss': 'priority_score',
        'published': 'published',
        'modified': 'modified',
        'id': 'id',
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

    // GET /api/v1/cve/search - General search with filters
    app.get('/search', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const params = parseSearchParams(c.req.query());
            const queryStr = buildQuery(params);
            const { data, count } = await querySupabase(c.env, queryStr);

            // Enhance records with computed fields
            const enhanced = data.map(enhanceCveRecord);

            return c.json({
                data: enhanced,
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

    // GET /api/v1/cve/package - Search by package (for MyoSC)
    app.get('/package', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const ecosystem = c.req.query('ecosystem');
        const packageName = c.req.query('name') || c.req.query('package');
        const limit = Math.min(1000, Math.max(1, parseInt(c.req.query('limit') || '100')));
        const offset = Math.max(0, parseInt(c.req.query('offset') || '0'));

        if (!ecosystem || !packageName) {
            return c.json({
                error: {
                    code: 'MISSING_PARAMS',
                    message: 'Required: ecosystem and name (or package)',
                    example: '/api/v1/cve/package?ecosystem=npm&name=lodash'
                },
                meta: { requestId, timestamp: new Date().toISOString() },
            }, 400);
        }

        try {
            // Query for CVEs that have this package in affected.osv
            // PostgREST JSONB array containment query
            const ecosystemNorm = ecosystem.toLowerCase();
            const packageNorm = packageName.toLowerCase();

            // Use text search on affected column (JSONB contains)
            const queryStr = `?select=*&affected->osv=cs.[{"ecosystem":"${ecosystemNorm}","package":"${packageNorm}"}]&order=priority_score.desc&limit=${limit}&offset=${offset}`;

            let data: CveRecord[] = [];
            let count = 0;

            try {
                const result = await querySupabase(c.env, queryStr);
                data = result.data;
                count = result.count;
            } catch {
                // Fallback: fetch OSV-sourced CVEs and filter client-side
                const fallbackQuery = `?select=*&sources=cs.{osv}&order=priority_score.desc&limit=2000`;
                const result = await querySupabase(c.env, fallbackQuery);

                data = result.data.filter(cve => {
                    const affected = cve.affected?.osv || [];
                    return affected.some((pkg: AffectedPackage) =>
                        pkg.ecosystem?.toLowerCase() === ecosystemNorm &&
                        pkg.package?.toLowerCase() === packageNorm
                    );
                });
                count = data.length;
                data = data.slice(offset, offset + limit);
            }

            const enhanced = data.map(enhanceCveRecord);

            return c.json({
                data: enhanced,
                query: { ecosystem, package: packageName },
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

    // GET /api/v1/cve/bulk - Bulk download with pagination (for sync)
    app.get('/bulk', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const limit = Math.min(1000, Math.max(1, parseInt(c.req.query('limit') || '1000')));
        const offset = Math.max(0, parseInt(c.req.query('offset') || '0'));
        const minPriority = parseFloat(c.req.query('minPriority') || '0');
        const sources = c.req.query('sources')?.split(',');

        try {
            let filters = '';
            if (minPriority > 0) {
                filters += `&priority_score=gte.${minPriority}`;
            }
            if (sources && sources.length > 0) {
                for (const src of sources) {
                    filters += `&sources=cs.{${src.trim()}}`;
                }
            }

            const queryStr = `?select=*${filters}&order=id.asc&limit=${limit}&offset=${offset}`;
            const { data, count } = await querySupabase(c.env, queryStr);
            const enhanced = data.map(enhanceCveRecord);

            return c.json({
                data: enhanced,
                pagination: {
                    total: count,
                    limit,
                    offset,
                    hasMore: count > offset + limit,
                    nextOffset: count > offset + limit ? offset + limit : null,
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

    // GET /api/v1/cve/recent - Recently modified CVEs
    app.get('/recent', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        try {
            const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') ?? '20')));
            const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0'));

            const { data, count } = await querySupabase(c.env, `?select=*&order=modified.desc.nullslast&limit=${limit}&offset=${offset}`);
            const enhanced = data.map(enhanceCveRecord);

            return c.json({
                data: enhanced,
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

    // GET /api/v1/cve/:id - Get single CVE by ID
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
                data: enhanceCveRecord(data[0]),
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
