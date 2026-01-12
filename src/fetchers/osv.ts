/**
 * =============================================================================
 * MyoAPI - OSV.dev Data Fetcher
 * =============================================================================
 *
 * Fetches vulnerability data from OSV.dev (Open Source Vulnerabilities database).
 * OSV is the primary source for CVE data because:
 * - Open source, free
 * - Supports many ecosystems (npm, PyPI, Go, Maven, etc.)
 * - Provides bulk download and incremental updates
 * - Standardized schema, easy to parse
 *
 * Data sources:
 * - Bulk: gs://osv-vulnerabilities/all.zip
 * - Per ecosystem: gs://osv-vulnerabilities/{ECOSYSTEM}/all.zip
 * - Incremental: gs://osv-vulnerabilities/modified_id.csv
 *
 * GCS bucket has public HTTP access:
 * https://osv-vulnerabilities.storage.googleapis.com/...
 */

import type { AffectedPackage, CveRecord, CvssInfo, Ecosystem, Severity } from '../models/cve';
import { calculatePriorityScore, cvssToSeverity } from '../models/cve';

// =============================================================================
// TYPES - OSV Schema
// =============================================================================

/**
 * OSV severity entry
 */
interface OsvSeverity {
    type: 'CVSS_V3' | 'CVSS_V2';
    score: string; // Vector string, e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}

/**
 * OSV affected range
 */
interface OsvRange {
    type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
    events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
        limit?: string;
    }>;
}

/**
 * OSV affected package
 */
interface OsvAffected {
    package: {
        name: string;
        ecosystem: string;
        purl?: string;
    };
    ranges?: OsvRange[];
    versions?: string[];
    severity?: OsvSeverity[];
    database_specific?: Record<string, unknown>;
    ecosystem_specific?: Record<string, unknown>;
}

/**
 * OSV vulnerability record (simplified)
 * Full schema: https://ossf.github.io/osv-schema/
 */
interface OsvRecord {
    id: string; // OSV ID (e.g., "GHSA-xxx" or "CVE-xxx")
    summary?: string;
    details?: string;
    aliases?: string[];
    modified: string; // ISO 8601
    published?: string; // ISO 8601
    withdrawn?: string; // ISO 8601 (if withdrawn)
    severity?: OsvSeverity[];
    affected?: OsvAffected[];
    references?: Array<{
        type: string;
        url: string;
    }>;
    database_specific?: Record<string, unknown>;
}

/**
 * OSV modified_id.csv entry
 */
interface OsvModifiedEntry {
    modifiedDate: string;
    ecosystem: string;
    id: string;
}

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Base URL for OSV GCS bucket (public HTTP access)
 */
const OSV_BASE_URL = 'https://osv-vulnerabilities.storage.googleapis.com';

/**
 * Target ecosystems to fetch
 * Limited to avoid exceeding Workers limits
 */
const TARGET_ECOSYSTEMS: readonly string[] = ['npm', 'PyPI', 'Go', 'Maven', 'NuGet', 'RubyGems', 'crates.io'] as const;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Map OSV ecosystem string to internal Ecosystem type
 */
function mapEcosystem(osvEcosystem: string): Ecosystem {
    const mapping: Record<string, Ecosystem> = {
        npm: 'npm',
        PyPI: 'PyPI',
        Go: 'Go',
        Maven: 'Maven',
        NuGet: 'NuGet',
        RubyGems: 'RubyGems',
        Packagist: 'Packagist',
        'crates.io': 'crates.io',
        Pub: 'Pub',
        Hex: 'Hex',
        Linux: 'Linux',
        'OSS-Fuzz': 'OSS-Fuzz',
        GIT: 'GIT',
    };
    return mapping[osvEcosystem] ?? 'Unknown';
}

/**
 * Parse CVSS vector string to extract base score
 * Format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 */
function parseCvssVector(vector: string): CvssInfo | null {
    if (!vector.startsWith('CVSS:3')) return null;

    // Extract version
    const versionMatch = vector.match(/CVSS:(3\.[01])/);
    const version = versionMatch?.[1] === '3.0' ? '3.0' : '3.1';

    // Calculate base score from vector
    // This is simplified calculation, production should use dedicated library
    const score = calculateCvssScore(vector);

    return {
        score,
        vector,
        version,
    };
}

/**
 * Calculate CVSS 3.x base score from vector string
 * Simplified implementation - only estimate, not 100% accurate
 */
function calculateCvssScore(vector: string): number {
    // Extract metrics from vector
    const metrics: Record<string, string> = {};
    const parts = vector.split('/');

    for (const part of parts) {
        const [key, value] = part.split(':');
        if (key && value) {
            metrics[key] = value;
        }
    }

    // Simplified scoring based on common patterns
    // C:H/I:H/A:H = ~9.8 (Critical)
    // C:H/I:H/A:N = ~9.1 (Critical)
    // C:L/I:L/A:N = ~5.4 (Medium)

    const c = metrics['C'] ?? 'N';
    const i = metrics['I'] ?? 'N';
    const a = metrics['A'] ?? 'N';

    let baseScore = 0;

    // Impact scoring (simplified)
    const impactMap: Record<string, number> = { H: 3.0, L: 1.5, N: 0 };
    baseScore += impactMap[c] ?? 0;
    baseScore += impactMap[i] ?? 0;
    baseScore += impactMap[a] ?? 0;

    // Attack vector modifier
    const av = metrics['AV'];
    if (av === 'N') baseScore += 1.0; // Network = more dangerous
    if (av === 'A') baseScore += 0.5; // Adjacent
    if (av === 'L') baseScore += 0.2; // Local
    if (av === 'P') baseScore += 0.0; // Physical

    // Privileges required modifier
    const pr = metrics['PR'];
    if (pr === 'N') baseScore += 0.5; // None required = worse

    // Scale to 0-10
    return Math.min(10, Math.max(0, baseScore));
}

/**
 * Extract CVE ID from OSV record
 * OSV ID can be GHSA-xxx, CVE-xxx, or other
 */
function extractCveId(osv: OsvRecord): string | null {
    // If ID is CVE, return directly
    if (osv.id.startsWith('CVE-')) return osv.id;

    // Look in aliases
    if (osv.aliases) {
        for (const alias of osv.aliases) {
            if (alias.startsWith('CVE-')) return alias;
        }
    }

    return null;
}

/**
 * Convert OSV record to internal CveRecord format
 */
function convertOsvToCve(
    osv: OsvRecord,
    epssScore: number | null = null,
    epssPercentile: number | null = null,
    isKev: boolean = false
): CveRecord | null {
    const cveId = extractCveId(osv);
    if (!cveId) return null; // Only process records with CVE ID

    // Parse CVSS
    let cvss: CvssInfo | null = null;
    if (osv.severity && osv.severity.length > 0) {
        for (const sev of osv.severity) {
            if (sev.type === 'CVSS_V3') {
                cvss = parseCvssVector(sev.score);
                if (cvss) break;
            }
        }
    }

    // Also check in affected packages
    if (!cvss && osv.affected) {
        for (const aff of osv.affected) {
            if (aff.severity) {
                for (const sev of aff.severity) {
                    if (sev.type === 'CVSS_V3') {
                        cvss = parseCvssVector(sev.score);
                        if (cvss) break;
                    }
                }
            }
            if (cvss) break;
        }
    }

    // Determine severity from CVSS
    const severity: Severity = cvssToSeverity(cvss?.score ?? null);

    // Parse affected packages
    const affected: AffectedPackage[] = [];
    if (osv.affected) {
        for (const aff of osv.affected) {
            const pkg: AffectedPackage = {
                name: aff.package.name,
                ecosystem: mapEcosystem(aff.package.ecosystem),
                versions: aff.versions,
            };

            // Extract version ranges
            if (aff.ranges && aff.ranges.length > 0) {
                for (const range of aff.ranges) {
                    for (const event of range.events) {
                        if (event.introduced) pkg.introducedIn = event.introduced;
                        if (event.fixed) pkg.fixedIn = event.fixed;
                    }
                }
            }

            affected.push(pkg);
        }
    }

    // Parse references
    const references: string[] = [];
    if (osv.references) {
        for (const ref of osv.references) {
            if (ref.url) references.push(ref.url);
        }
    }

    // Parse aliases (excluding main CVE ID)
    const aliases: string[] = [];
    aliases.push(osv.id); // OSV ID is always an alias
    if (osv.aliases) {
        for (const alias of osv.aliases) {
            if (alias !== cveId) aliases.push(alias);
        }
    }

    // Calculate priority score
    const priorityScore = calculatePriorityScore(cvss?.score ?? null, epssScore, isKev);

    return {
        id: cveId,
        title: osv.summary ?? `Vulnerability in ${affected[0]?.name ?? 'unknown package'}`,
        description: osv.details ?? osv.summary ?? '',
        severity,
        cvss,
        epss: epssScore !== null ? { score: epssScore, percentile: epssPercentile ?? 0 } : null,
        priorityScore,
        isKev,
        published: osv.published ?? osv.modified,
        modified: osv.modified,
        affected,
        references,
        aliases,
        sources: { osv: true },
    };
}

// =============================================================================
// MAIN FETCHERS
// =============================================================================

/**
 * Fetch list of recently modified CVE IDs.
 * Used for incremental updates instead of fetching everything.
 *
 * @param since - Only get records modified after this date
 * @returns Array of modified entries
 */
export async function fetchModifiedIds(since?: Date): Promise<OsvModifiedEntry[]> {
    const url = `${OSV_BASE_URL}/modified_id.csv`;

    console.log('[OSV] Fetching modified IDs...');

    const response = await fetch(url, {
        headers: {
            'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
        },
    });

    if (!response.ok) {
        throw new Error(`OSV modified_id fetch failed: ${response.status}`);
    }

    const csvContent = await response.text();
    const lines = csvContent.split('\n');
    const entries: OsvModifiedEntry[] = [];

    for (const line of lines) {
        if (!line.trim()) continue;

        // Format: 2024-01-15T12:00:00Z,PyPI/GHSA-xxx-yyy
        const [dateStr, path] = line.split(',');
        if (!dateStr || !path) continue;

        const modifiedDate = dateStr.trim();
        const pathParts = path.trim().split('/');

        if (pathParts.length < 2) continue;

        const ecosystem = pathParts[0] ?? '';
        const id = pathParts.slice(1).join('/');

        // Filter by date if provided
        if (since) {
            const entryDate = new Date(modifiedDate);
            if (entryDate < since) continue;
        }

        entries.push({
            modifiedDate,
            ecosystem,
            id,
        });
    }

    console.log(`[OSV] Found ${entries.length} modified entries`);
    return entries;
}

/**
 * Fetch single OSV record by ID
 *
 * @param ecosystem - Ecosystem name (e.g., "PyPI")
 * @param id - OSV ID (e.g., "GHSA-xxx-yyy")
 * @returns OSV record or null if not found
 */
export async function fetchOsvRecord(ecosystem: string, id: string): Promise<OsvRecord | null> {
    const url = `${OSV_BASE_URL}/${ecosystem}/${id}.json`;

    try {
        const response = await fetch(url, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) {
            if (response.status === 404) return null;
            throw new Error(`OSV fetch failed: ${response.status}`);
        }

        return (await response.json()) as OsvRecord;
    } catch (error) {
        console.error(`[OSV] Failed to fetch ${ecosystem}/${id}:`, error);
        return null;
    }
}

/**
 * Fetch and convert OSV record to CveRecord
 *
 * @param ecosystem - Ecosystem name
 * @param id - OSV ID
 * @param epssData - Optional EPSS data map
 * @param kevSet - Optional KEV CVE ID set
 * @returns CveRecord or null
 */
export async function fetchAndConvertOsv(
    ecosystem: string,
    id: string,
    epssData?: Map<string, { score: number; percentile: number }>,
    kevSet?: Set<string>
): Promise<CveRecord | null> {
    const osv = await fetchOsvRecord(ecosystem, id);
    if (!osv) return null;

    const cveId = extractCveId(osv);
    if (!cveId) return null;

    const epss = epssData?.get(cveId);
    const isKev = kevSet?.has(cveId) ?? false;

    return convertOsvToCve(osv, epss?.score ?? null, epss?.percentile ?? null, isKev);
}

/**
 * Batch fetch multiple OSV records from modified list
 * Has rate limiting to avoid overwhelming OSV servers
 *
 * @param entries - List of modified entries to fetch
 * @param epssData - EPSS data map
 * @param kevSet - KEV CVE ID set
 * @param batchSize - Number of records to fetch concurrently (default: 10)
 * @returns Array of CveRecords
 */
export async function batchFetchOsv(
    entries: OsvModifiedEntry[],
    epssData: Map<string, { score: number; percentile: number }>,
    kevSet: Set<string>,
    batchSize: number = 10
): Promise<CveRecord[]> {
    const results: CveRecord[] = [];
    const targetEcosystems = new Set(TARGET_ECOSYSTEMS);

    // Filter to only target ecosystems
    const filteredEntries = entries.filter((e) => targetEcosystems.has(e.ecosystem));

    console.log(`[OSV] Batch fetching ${filteredEntries.length} records...`);

    for (let i = 0; i < filteredEntries.length; i += batchSize) {
        const batch = filteredEntries.slice(i, i + batchSize);

        const promises = batch.map((entry) => fetchAndConvertOsv(entry.ecosystem, entry.id, epssData, kevSet));

        const batchResults = await Promise.all(promises);

        for (const result of batchResults) {
            if (result) results.push(result);
        }

        // Progress log
        if ((i + batchSize) % 100 === 0) {
            console.log(`[OSV] Processed ${Math.min(i + batchSize, filteredEntries.length)}/${filteredEntries.length}`);
        }

        // Rate limiting: 50ms delay between batches
        if (i + batchSize < filteredEntries.length) {
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
    }

    console.log(`[OSV] Fetched ${results.length} CVE records`);
    return results;
}

// Export for testing
export { convertOsvToCve, extractCveId, parseCvssVector };
export type { OsvRecord };
