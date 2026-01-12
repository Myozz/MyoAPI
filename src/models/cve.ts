/**
 * =============================================================================
 * MyoAPI - CVE Data Models
 * =============================================================================
 *
 * Core data structures for CVE records, search parameters, and API responses.
 * Designed for compatibility with multiple data sources (OSV, NVD, EPSS, KEV).
 */

// =============================================================================
// ENUMS & CONSTANTS
// =============================================================================

/**
 * Vulnerability severity level (based on CVSS 3.x)
 */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/**
 * Package ecosystem (compatible with OSV schema)
 */
export type Ecosystem =
    | 'npm'
    | 'PyPI'
    | 'Go'
    | 'Maven'
    | 'NuGet'
    | 'RubyGems'
    | 'Packagist'
    | 'crates.io'
    | 'Pub'
    | 'Hex'
    | 'Linux'
    | 'OSS-Fuzz'
    | 'GIT'
    | 'Unknown';

/**
 * Map CVSS score to Severity level
 * CVSS 3.x standard: https://nvd.nist.gov/vuln-metrics/cvss
 */
export function cvssToSeverity(score: number | null): Severity {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'UNKNOWN';
}

// =============================================================================
// CVE RECORD
// =============================================================================

/**
 * Package/product affected by vulnerability
 */
export interface AffectedPackage {
    /** Package name (e.g., "lodash", "requests") */
    name: string;

    /** Package ecosystem */
    ecosystem: Ecosystem;

    /** Affected version ranges (semver format) */
    versions?: string[];

    /** First affected version */
    introducedIn?: string;

    /** Fixed version */
    fixedIn?: string;
}

/**
 * CVSS scoring information
 */
export interface CvssInfo {
    /** CVSS 3.x base score (0-10) */
    score: number;

    /** CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") */
    vector: string;

    /** CVSS version (3.0 or 3.1) */
    version: '3.0' | '3.1';
}

/**
 * EPSS (Exploit Prediction Scoring System) data
 */
export interface EpssInfo {
    /** Probability score (0-1): likelihood of exploitation in next 30 days */
    score: number;

    /** Percentile (0-1): compared to all other CVEs */
    percentile: number;
}

/**
 * CVE Record - Core data structure
 * Aggregated from multiple sources: OSV, NVD, EPSS, CISA KEV
 */
export interface CveRecord {
    /** CVE ID (e.g., "CVE-2024-1234") */
    id: string;

    /** Short title/summary */
    title: string;

    /** Detailed vulnerability description */
    description: string;

    /** Severity level (derived from CVSS) */
    severity: Severity;

    /** CVSS scoring info */
    cvss: CvssInfo | null;

    /** EPSS scoring info */
    epss: EpssInfo | null;

    /**
     * Priority Score (0-1): Custom scoring combining CVSS + EPSS + KEV
     * Formula: (CVSS/10 * 0.3) + (EPSS * 0.5) + (KEV bonus * 0.2)
     */
    priorityScore: number;

    /** Present in CISA Known Exploited Vulnerabilities catalog */
    isKev: boolean;

    /** Date vulnerability was published */
    published: string;

    /** Date of last modification */
    modified: string;

    /** List of affected packages/products */
    affected: AffectedPackage[];

    /** Reference URLs (advisories, patches, etc.) */
    references: string[];

    /** Aliases (GHSA-xxx, OSV-xxx, etc.) */
    aliases: string[];

    /** Data source metadata */
    sources: {
        osv?: boolean;
        nvd?: boolean;
        ghsa?: boolean;
    };
}

// =============================================================================
// PRIORITY SCORE CALCULATION
// =============================================================================

/**
 * Calculate Priority Score based on CVSS, EPSS, and KEV status.
 *
 * Formula:
 * - CVSS weight: 30% (technical severity)
 * - EPSS weight: 50% (real-world exploit probability - most important)
 * - KEV bonus: 20% (already exploited in the wild)
 *
 * @param cvssScore - CVSS 3.x score (0-10), null if not available
 * @param epssScore - EPSS probability (0-1), null if not available
 * @param isKev - Whether CVE is in CISA KEV catalog
 * @returns Priority score from 0-1
 */
export function calculatePriorityScore(
    cvssScore: number | null,
    epssScore: number | null,
    isKev: boolean
): number {
    // Normalize CVSS from 0-10 to 0-1
    const cvssNormalized = cvssScore !== null ? cvssScore / 10 : 0;

    // EPSS is already on 0-1 scale
    const epssNormalized = epssScore ?? 0;

    // KEV bonus: 1 if in KEV, 0 otherwise
    const kevBonus = isKev ? 1 : 0;

    // Weighted calculation
    const score = cvssNormalized * 0.3 + epssNormalized * 0.5 + kevBonus * 0.2;

    // Clamp to [0, 1] and round to 4 decimal places
    return Math.round(Math.min(1, Math.max(0, score)) * 10000) / 10000;
}

// =============================================================================
// SEARCH & QUERY
// =============================================================================

/**
 * Parameters for CVE search API
 */
export interface SearchParams {
    /** Full-text search query */
    q?: string;

    /** Filter by CVE IDs (comma-separated) */
    cveIds?: string[];

    /** Filter by package name */
    package?: string;

    /** Filter by ecosystem */
    ecosystem?: Ecosystem;

    /** Filter by severity levels */
    severity?: Severity[];

    /** CVSS score range */
    minCvss?: number;
    maxCvss?: number;

    /** EPSS score range */
    minEpss?: number;
    maxEpss?: number;

    /** Priority score range */
    minPriority?: number;
    maxPriority?: number;

    /** Only get CVEs in CISA KEV */
    isKev?: boolean;

    /** Date range (ISO 8601 format) */
    publishedAfter?: string;
    publishedBefore?: string;
    modifiedAfter?: string;
    modifiedBefore?: string;

    /** Pagination */
    limit?: number;
    offset?: number;

    /** Sort options */
    sortBy?: 'priority' | 'cvss' | 'epss' | 'published' | 'modified';
    sortOrder?: 'asc' | 'desc';
}

/**
 * Default values for search params
 */
export const DEFAULT_SEARCH_PARAMS: Required<Pick<SearchParams, 'limit' | 'offset' | 'sortBy' | 'sortOrder'>> = {
    limit: 20,
    offset: 0,
    sortBy: 'priority',
    sortOrder: 'desc',
};

// =============================================================================
// API RESPONSES
// =============================================================================

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        total: number;
        limit: number;
        offset: number;
        hasMore: boolean;
    };
    meta: {
        requestId: string;
        timestamp: string;
        executionTimeMs: number;
    };
}

/**
 * Single item response wrapper
 */
export interface SingleResponse<T> {
    data: T;
    meta: {
        requestId: string;
        timestamp: string;
        executionTimeMs: number;
    };
}

/**
 * Error response
 */
export interface ErrorResponse {
    error: {
        code: string;
        message: string;
        details?: Record<string, unknown>;
    };
    meta: {
        requestId: string;
        timestamp: string;
    };
}

/**
 * API Statistics
 */
export interface ApiStats {
    /** Total CVEs in database */
    totalCves: number;

    /** Distribution by severity */
    bySeverity: Record<Severity, number>;

    /** Distribution by ecosystem (top 10) */
    byEcosystem: Record<string, number>;

    /** Number of CVEs in CISA KEV */
    kevCount: number;

    /** Last sync timestamp */
    lastSyncTime: string;

    /** Data source status */
    sources: {
        osv: { lastSync: string; count: number };
        epss: { lastSync: string; date: string };
        kev: { lastSync: string; count: number };
    };
}

// =============================================================================
// INTERNAL TYPES
// =============================================================================

/**
 * KV storage key format
 */
export type KvKeyType =
    | `cve:${string}` // CVE record by ID
    | `idx:eco:${string}` // Index by ecosystem
    | `idx:sev:${string}` // Index by severity
    | `idx:kev` // Index of KEV CVEs
    | `idx:recent` // Recently modified CVEs
    | `meta:stats` // API statistics
    | `meta:sync` // Sync metadata
    | `rate:${string}`; // Rate limit by IP/key

/**
 * Sync metadata
 */
export interface SyncMetadata {
    lastSyncTime: string;
    lastEpssDate: string;
    lastKevSync: string;
    lastOsvSync: string;
    syncDurationMs: number;
    recordsUpdated: number;
}
