/**
 * =============================================================================
 * MyoAPI - NVD Data Fetcher
 * =============================================================================
 *
 * Fetches CVE data from NVD (National Vulnerability Database) API 2.0.
 * NVD is used as fallback source for CVSS scores when OSV doesn't have them.
 *
 * API: https://services.nvd.nist.gov/rest/json/cves/2.0
 *
 * Rate Limits:
 * - Without API key: 5 requests / 30 seconds
 * - With API key: 50 requests / 30 seconds
 *
 * Note: NVD is only used when CVSS lookup is needed for specific CVE,
 * not for bulk fetch due to low rate limits.
 */

import type { CvssInfo } from '../models/cve';

// =============================================================================
// TYPES
// =============================================================================

/**
 * NVD CVSS V3 data
 */
interface NvdCvssV3 {
    source: string;
    type: 'Primary' | 'Secondary';
    cvssData: {
        version: string;
        vectorString: string;
        attackVector: string;
        attackComplexity: string;
        privilegesRequired: string;
        userInteraction: string;
        scope: string;
        confidentialityImpact: string;
        integrityImpact: string;
        availabilityImpact: string;
        baseScore: number;
        baseSeverity: string;
    };
    exploitabilityScore: number;
    impactScore: number;
}

/**
 * NVD CVE item
 */
interface NvdCveItem {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    descriptions: Array<{
        lang: string;
        value: string;
    }>;
    metrics?: {
        cvssMetricV31?: NvdCvssV3[];
        cvssMetricV30?: NvdCvssV3[];
        cvssMetricV2?: unknown[];
    };
    weaknesses?: unknown[];
    configurations?: unknown[];
    references?: Array<{
        url: string;
        source: string;
        tags?: string[];
    }>;
}

/**
 * NVD API response
 */
interface NvdApiResponse {
    resultsPerPage: number;
    startIndex: number;
    totalResults: number;
    format: string;
    version: string;
    timestamp: string;
    vulnerabilities: Array<{
        cve: NvdCveItem;
    }>;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/**
 * Delay between requests (ms)
 * Without API key: 6000ms (5 req/30s = 1 req/6s)
 * With API key: 600ms (50 req/30s = 1 req/0.6s)
 */
const NVD_RATE_LIMIT_DELAY = 6000;
const NVD_RATE_LIMIT_DELAY_WITH_KEY = 600;

// =============================================================================
// MAIN FETCHER
// =============================================================================

/**
 * Fetch CVSS info for a single CVE from NVD.
 *
 * @param cveId - CVE ID (e.g., "CVE-2024-1234")
 * @param apiKey - Optional NVD API key to increase rate limit
 * @returns CVSS info or null if not found
 */
export async function fetchNvdCvss(cveId: string, apiKey?: string): Promise<CvssInfo | null> {
    const url = `${NVD_API_BASE}?cveId=${encodeURIComponent(cveId)}`;

    const headers: HeadersInit = {
        Accept: 'application/json',
        'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
    };

    if (apiKey) {
        headers['apiKey'] = apiKey;
    }

    try {
        const response = await fetch(url, { headers });

        if (!response.ok) {
            if (response.status === 403) {
                console.warn('[NVD] Rate limit exceeded, waiting...');
                return null;
            }
            if (response.status === 404) {
                return null;
            }
            throw new Error(`NVD fetch failed: ${response.status}`);
        }

        const data = (await response.json()) as NvdApiResponse;

        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            return null;
        }

        const cve = data.vulnerabilities[0]?.cve;
        if (!cve) return null;

        // Extract CVSS V3.1 first, then V3.0
        const cvssV31 = cve.metrics?.cvssMetricV31?.[0];
        const cvssV30 = cve.metrics?.cvssMetricV30?.[0];

        const cvssData = cvssV31 ?? cvssV30;
        if (!cvssData) return null;

        return {
            score: cvssData.cvssData.baseScore,
            vector: cvssData.cvssData.vectorString,
            version: cvssData.cvssData.version === '3.1' ? '3.1' : '3.0',
        };
    } catch (error) {
        console.error(`[NVD] Failed to fetch CVSS for ${cveId}:`, error);
        return null;
    }
}

/**
 * Batch fetch CVSS for multiple CVEs from NVD.
 * Includes automatic rate limiting.
 *
 * @param cveIds - Array of CVE IDs
 * @param apiKey - Optional NVD API key
 * @returns Map from CVE ID -> CVSS info
 */
export async function batchFetchNvdCvss(cveIds: string[], apiKey?: string): Promise<Map<string, CvssInfo>> {
    const results = new Map<string, CvssInfo>();
    const delay = apiKey ? NVD_RATE_LIMIT_DELAY_WITH_KEY : NVD_RATE_LIMIT_DELAY;

    console.log(`[NVD] Batch fetching CVSS for ${cveIds.length} CVEs...`);

    for (let i = 0; i < cveIds.length; i++) {
        const cveId = cveIds[i];
        if (!cveId) continue;

        const cvss = await fetchNvdCvss(cveId, apiKey);
        if (cvss) {
            results.set(cveId, cvss);
        }

        // Progress log
        if ((i + 1) % 10 === 0) {
            console.log(`[NVD] Processed ${i + 1}/${cveIds.length}`);
        }

        // Rate limiting
        if (i < cveIds.length - 1) {
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }

    console.log(`[NVD] Fetched CVSS for ${results.size}/${cveIds.length} CVEs`);
    return results;
}

/**
 * Fetch CVE description from NVD (English)
 */
export async function fetchNvdDescription(cveId: string, apiKey?: string): Promise<string | null> {
    const url = `${NVD_API_BASE}?cveId=${encodeURIComponent(cveId)}`;

    const headers: HeadersInit = {
        Accept: 'application/json',
        'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
    };

    if (apiKey) {
        headers['apiKey'] = apiKey;
    }

    try {
        const response = await fetch(url, { headers });

        if (!response.ok) return null;

        const data = (await response.json()) as NvdApiResponse;

        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            return null;
        }

        const cve = data.vulnerabilities[0]?.cve;
        if (!cve) return null;

        // Find English description
        const enDesc = cve.descriptions.find((d) => d.lang === 'en');
        return enDesc?.value ?? null;
    } catch (error) {
        console.error(`[NVD] Failed to fetch description for ${cveId}:`, error);
        return null;
    }
}
