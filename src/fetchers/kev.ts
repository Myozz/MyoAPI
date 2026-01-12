/**
 * =============================================================================
 * MyoAPI - CISA KEV Data Fetcher
 * =============================================================================
 *
 * Fetches Known Exploited Vulnerabilities (KEV) catalog from CISA.
 * KEV contains CVEs that have been confirmed exploited in the wild.
 *
 * Data source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Update frequency: On change (typically weekdays during US Eastern business hours)
 */

// =============================================================================
// TYPES
// =============================================================================

/**
 * CISA KEV entry structure
 */
export interface KevEntry {
    /** CVE ID */
    cveID: string;

    /** Vendor/Project name */
    vendorProject: string;

    /** Product name */
    product: string;

    /** Vulnerability name */
    vulnerabilityName: string;

    /** Date added to KEV catalog (YYYY-MM-DD) */
    dateAdded: string;

    /** Short description */
    shortDescription: string;

    /** Required action */
    requiredAction: string;

    /** Due date for federal agencies (YYYY-MM-DD) */
    dueDate: string;

    /** Known ransomware campaign use */
    knownRansomwareCampaignUse: 'Known' | 'Unknown';

    /** Additional notes */
    notes?: string;
}

/**
 * Full KEV catalog response
 */
interface KevCatalog {
    /** Catalog title */
    title: string;

    /** Catalog version */
    catalogVersion: string;

    /** Date generated */
    dateReleased: string;

    /** Total count */
    count: number;

    /** KEV entries */
    vulnerabilities: KevEntry[];
}

/**
 * KEV data set: CVE ID set
 */
export type KevDataSet = Set<string>;

/**
 * KEV data map with full details: CVE ID -> KEV entry
 */
export type KevDataMap = Map<string, KevEntry>;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Official CISA KEV JSON feed URL
 */
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// =============================================================================
// MAIN FETCHER
// =============================================================================

/**
 * Fetch CISA KEV catalog and return Set of CVE IDs.
 * Uses Set for fast O(1) lookup when checking if CVE is in KEV.
 *
 * @returns Set containing all CVE IDs in KEV catalog
 */
export async function fetchKevData(): Promise<KevDataSet> {
    console.log('[KEV] Fetching CISA KEV catalog...');

    try {
        const response = await fetch(KEV_URL, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) {
            throw new Error(`KEV fetch failed: ${response.status} ${response.statusText}`);
        }

        const catalog = (await response.json()) as KevCatalog;

        const kevSet: KevDataSet = new Set();

        for (const entry of catalog.vulnerabilities) {
            if (entry.cveID && entry.cveID.startsWith('CVE-')) {
                kevSet.add(entry.cveID);
            }
        }

        console.log(`[KEV] Loaded ${kevSet.size} CVEs from KEV catalog (version: ${catalog.catalogVersion})`);
        return kevSet;
    } catch (error) {
        console.error('[KEV] Fetch error:', error);
        throw error;
    }
}

/**
 * Fetch CISA KEV catalog with full details.
 * Use when additional info like vendor, product, due date is needed.
 *
 * @returns Map from CVE ID -> KEV entry details
 */
export async function fetchKevDataFull(): Promise<KevDataMap> {
    console.log('[KEV] Fetching CISA KEV catalog (full details)...');

    try {
        const response = await fetch(KEV_URL, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) {
            throw new Error(`KEV fetch failed: ${response.status} ${response.statusText}`);
        }

        const catalog = (await response.json()) as KevCatalog;

        const kevMap: KevDataMap = new Map();

        for (const entry of catalog.vulnerabilities) {
            if (entry.cveID && entry.cveID.startsWith('CVE-')) {
                kevMap.set(entry.cveID, entry);
            }
        }

        console.log(`[KEV] Loaded ${kevMap.size} KEV entries with full details`);
        return kevMap;
    } catch (error) {
        console.error('[KEV] Fetch error:', error);
        throw error;
    }
}

/**
 * Get metadata about KEV catalog (version, count, release date)
 * Use to check if there are new updates before fetching full catalog.
 */
export async function getKevMetadata(): Promise<{
    version: string;
    count: number;
    releaseDate: string;
} | null> {
    try {
        const response = await fetch(KEV_URL, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) return null;

        const catalog = (await response.json()) as KevCatalog;

        return {
            version: catalog.catalogVersion,
            count: catalog.count,
            releaseDate: catalog.dateReleased,
        };
    } catch {
        return null;
    }
}
