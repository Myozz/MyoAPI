/**
 * =============================================================================
 * MyoAPI - CVE Routes
 * =============================================================================
 *
 * API endpoints for CVE data:
 * - GET /api/v1/cve/:id - Get CVE by ID
 * - GET /api/v1/cve/search - Search CVEs with filters
 * - GET /api/v1/cve/recent - Get recent CVEs
 */

import { Hono } from 'hono';
import type { CveRecord, PaginatedResponse, SearchParams, SingleResponse, Severity, Ecosystem } from '../models/cve';
import { DEFAULT_SEARCH_PARAMS } from '../models/cve';
import type { AppType } from '../types';

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Parse search params from query string
 */
function parseSearchParams(query: Record<string, string | undefined>): SearchParams {
    const params: SearchParams = {
        ...DEFAULT_SEARCH_PARAMS,
    };

    if (query['q']) params.q = query['q'];

    if (query['cveIds']) {
        params.cveIds = query['cveIds'].split(',').map((id) => id.trim());
    }

    if (query['package']) params.package = query['package'];
    if (query['ecosystem']) params.ecosystem = query['ecosystem'] as Ecosystem;

    if (query['severity']) {
        params.severity = query['severity'].split(',').map((s) => s.trim().toUpperCase() as Severity);
    }

    if (query['minCvss']) params.minCvss = parseFloat(query['minCvss']);
    if (query['maxCvss']) params.maxCvss = parseFloat(query['maxCvss']);
    if (query['minEpss']) params.minEpss = parseFloat(query['minEpss']);
    if (query['maxEpss']) params.maxEpss = parseFloat(query['maxEpss']);
    if (query['minPriority']) params.minPriority = parseFloat(query['minPriority']);
    if (query['maxPriority']) params.maxPriority = parseFloat(query['maxPriority']);

    if (query['isKev'] !== undefined) {
        params.isKev = query['isKev'] === 'true' || query['isKev'] === '1';
    }

    if (query['publishedAfter']) params.publishedAfter = query['publishedAfter'];
    if (query['publishedBefore']) params.publishedBefore = query['publishedBefore'];
    if (query['modifiedAfter']) params.modifiedAfter = query['modifiedAfter'];
    if (query['modifiedBefore']) params.modifiedBefore = query['modifiedBefore'];

    if (query['limit']) params.limit = Math.min(100, Math.max(1, parseInt(query['limit'])));
    if (query['offset']) params.offset = Math.max(0, parseInt(query['offset']));

    if (query['sortBy']) {
        const validSorts = ['priority', 'cvss', 'epss', 'published', 'modified'];
        if (validSorts.includes(query['sortBy'])) {
            params.sortBy = query['sortBy'] as SearchParams['sortBy'];
        }
    }
    if (query['sortOrder']) {
        params.sortOrder = query['sortOrder'] === 'asc' ? 'asc' : 'desc';
    }

    return params;
}

/**
 * Filter CVE records based on search params
 */
function filterCveRecords(records: CveRecord[], params: SearchParams): CveRecord[] {
    return records.filter((cve) => {
        if (params.q) {
            const searchText = params.q.toLowerCase();
            const matchTitle = cve.title.toLowerCase().includes(searchText);
            const matchDesc = cve.description.toLowerCase().includes(searchText);
            const matchId = cve.id.toLowerCase().includes(searchText);
            if (!matchTitle && !matchDesc && !matchId) return false;
        }

        if (params.cveIds && params.cveIds.length > 0) {
            if (!params.cveIds.includes(cve.id)) return false;
        }

        if (params.package) {
            const pkgName = params.package.toLowerCase();
            const hasPackage = cve.affected.some((pkg) => pkg.name.toLowerCase().includes(pkgName));
            if (!hasPackage) return false;
        }

        if (params.ecosystem) {
            const hasEcosystem = cve.affected.some((pkg) => pkg.ecosystem === params.ecosystem);
            if (!hasEcosystem) return false;
        }

        if (params.severity && params.severity.length > 0) {
            if (!params.severity.includes(cve.severity)) return false;
        }

        if (params.minCvss !== undefined && (cve.cvss?.score ?? 0) < params.minCvss) return false;
        if (params.maxCvss !== undefined && (cve.cvss?.score ?? 10) > params.maxCvss) return false;
        if (params.minEpss !== undefined && (cve.epss?.score ?? 0) < params.minEpss) return false;
        if (params.maxEpss !== undefined && (cve.epss?.score ?? 1) > params.maxEpss) return false;
        if (params.minPriority !== undefined && cve.priorityScore < params.minPriority) return false;
        if (params.maxPriority !== undefined && cve.priorityScore > params.maxPriority) return false;
        if (params.isKev !== undefined && cve.isKev !== params.isKev) return false;

        if (params.publishedAfter) {
            if (new Date(cve.published) < new Date(params.publishedAfter)) return false;
        }
        if (params.publishedBefore) {
            if (new Date(cve.published) > new Date(params.publishedBefore)) return false;
        }
        if (params.modifiedAfter) {
            if (new Date(cve.modified) < new Date(params.modifiedAfter)) return false;
        }
        if (params.modifiedBefore) {
            if (new Date(cve.modified) > new Date(params.modifiedBefore)) return false;
        }

        return true;
    });
}

/**
 * Sort CVE records based on params
 */
function sortCveRecords(records: CveRecord[], params: SearchParams): CveRecord[] {
    const { sortBy = 'priority', sortOrder = 'desc' } = params;

    return [...records].sort((a, b) => {
        let comparison = 0;

        switch (sortBy) {
            case 'priority':
                comparison = a.priorityScore - b.priorityScore;
                break;
            case 'cvss':
                comparison = (a.cvss?.score ?? 0) - (b.cvss?.score ?? 0);
                break;
            case 'epss':
                comparison = (a.epss?.score ?? 0) - (b.epss?.score ?? 0);
                break;
            case 'published':
                comparison = new Date(a.published).getTime() - new Date(b.published).getTime();
                break;
            case 'modified':
                comparison = new Date(a.modified).getTime() - new Date(b.modified).getTime();
                break;
        }

        return sortOrder === 'desc' ? -comparison : comparison;
    });
}

// =============================================================================
// ROUTES
// =============================================================================

/**
 * Create CVE routes
 */
export function createCveRoutes(): Hono<AppType> {
    const app = new Hono<AppType>();

    // GET /api/v1/cve/:id - Get CVE by ID
    app.get('/:id', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();
        const cveId = c.req.param('id');

        if (!cveId.match(/^CVE-\d{4}-\d{4,}$/i)) {
            return c.json(
                {
                    error: {
                        code: 'INVALID_CVE_ID',
                        message: `Invalid CVE ID format: ${cveId}. Expected format: CVE-YYYY-NNNNN`,
                    },
                    meta: { requestId, timestamp: new Date().toISOString() },
                },
                400
            );
        }

        const cveData = await c.env.CVE_DATA.get(`cve:${cveId.toUpperCase()}`);

        if (!cveData) {
            return c.json(
                {
                    error: {
                        code: 'CVE_NOT_FOUND',
                        message: `CVE ${cveId} not found in database`,
                    },
                    meta: { requestId, timestamp: new Date().toISOString() },
                },
                404
            );
        }

        const cve = JSON.parse(cveData) as CveRecord;
        const executionTimeMs = Date.now() - startTime;

        const response: SingleResponse<CveRecord> = {
            data: cve,
            meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs },
        };

        return c.json(response);
    });

    // GET /api/v1/cve/search - Search CVEs with filters
    app.get('/search', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const query = c.req.query();
        const params = parseSearchParams(query);

        let cveIds: string[] = [];

        if (params.ecosystem) {
            const ecosystemIndex = await c.env.CVE_INDEX.get(`idx:eco:${params.ecosystem}`);
            if (ecosystemIndex) cveIds = JSON.parse(ecosystemIndex) as string[];
        } else if (params.severity && params.severity.length === 1) {
            const severityIndex = await c.env.CVE_INDEX.get(`idx:sev:${params.severity[0]}`);
            if (severityIndex) cveIds = JSON.parse(severityIndex) as string[];
        } else if (params.isKev === true) {
            const kevIndex = await c.env.CVE_INDEX.get('idx:kev');
            if (kevIndex) cveIds = JSON.parse(kevIndex) as string[];
        } else {
            const recentIndex = await c.env.CVE_INDEX.get('idx:recent');
            if (recentIndex) cveIds = JSON.parse(recentIndex) as string[];
        }

        const maxFetch = 500;
        cveIds = cveIds.slice(0, maxFetch);

        const cveRecords: CveRecord[] = [];
        for (const id of cveIds) {
            const cveData = await c.env.CVE_DATA.get(`cve:${id}`);
            if (cveData) cveRecords.push(JSON.parse(cveData) as CveRecord);
        }

        const filtered = filterCveRecords(cveRecords, params);
        const sorted = sortCveRecords(filtered, params);

        const offset = params.offset ?? 0;
        const limit = params.limit ?? 20;
        const paginated = sorted.slice(offset, offset + limit);

        const executionTimeMs = Date.now() - startTime;

        const response: PaginatedResponse<CveRecord> = {
            data: paginated,
            pagination: { total: sorted.length, limit, offset, hasMore: offset + limit < sorted.length },
            meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs },
        };

        return c.json(response);
    });

    // GET /api/v1/cve/recent - Get recent CVEs
    app.get('/recent', async (c) => {
        const startTime = Date.now();
        const requestId = c.var.requestId ?? crypto.randomUUID();

        const limit = Math.min(100, Math.max(1, parseInt(c.req.query('limit') ?? '20')));
        const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0'));

        const recentIndex = await c.env.CVE_INDEX.get('idx:recent');
        const cveIds: string[] = recentIndex ? (JSON.parse(recentIndex) as string[]) : [];

        const totalIds = cveIds.slice(offset, offset + limit);
        const cveRecords: CveRecord[] = [];

        for (const id of totalIds) {
            const cveData = await c.env.CVE_DATA.get(`cve:${id}`);
            if (cveData) cveRecords.push(JSON.parse(cveData) as CveRecord);
        }

        const executionTimeMs = Date.now() - startTime;

        const response: PaginatedResponse<CveRecord> = {
            data: cveRecords,
            pagination: { total: cveIds.length, limit, offset, hasMore: offset + limit < cveIds.length },
            meta: { requestId, timestamp: new Date().toISOString(), executionTimeMs },
        };

        return c.json(response);
    });

    return app;
}
