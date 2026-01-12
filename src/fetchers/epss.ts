/**
 * =============================================================================
 * MyoAPI - EPSS Data Fetcher
 * =============================================================================
 *
 * Fetches EPSS (Exploit Prediction Scoring System) scores from FIRST.org.
 * EPSS provides the probability that a CVE will be exploited in the next 30 days.
 *
 * Data source: https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
 * Update frequency: Daily
 */

import type { EpssInfo } from '../models/cve';

// =============================================================================
// TYPES
// =============================================================================

/**
 * Raw EPSS record from CSV file
 */
interface EpssRawRecord {
    cve: string; // CVE-YYYY-NNNNN
    epss: string; // Probability as string (e.g., "0.00043")
    percentile: string; // Percentile as string (e.g., "0.12345")
}

/**
 * Parsed EPSS data map: CVE ID -> EPSS info
 */
export type EpssDataMap = Map<string, EpssInfo>;

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Base URL for EPSS daily CSV files
 * Format: epss_scores-YYYY-MM-DD.csv.gz
 */
const EPSS_BASE_URL = 'https://epss.empiricalsecurity.com';

/**
 * Fallback: FIRST.org API endpoint
 * Used when CSV is not available
 */
const EPSS_API_URL = 'https://api.first.org/data/v1/epss';

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Format date as YYYY-MM-DD string
 */
function formatDate(date: Date): string {
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

/**
 * Parse CSV line (simple parser, does not handle quoted fields)
 */
function parseCsvLine(line: string): string[] {
    return line.split(',').map((field) => field.trim());
}

/**
 * Decompress gzip data
 * Workers support native DecompressionStream
 */
async function decompressGzip(compressedData: ArrayBuffer): Promise<string> {
    const stream = new DecompressionStream('gzip');
    const writer = stream.writable.getWriter();
    writer.write(new Uint8Array(compressedData));
    writer.close();

    const reader = stream.readable.getReader();
    const chunks: Uint8Array[] = [];

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }

    // Merge chunks and decode
    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const merged = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
    }

    return new TextDecoder().decode(merged);
}

// =============================================================================
// MAIN FETCHER
// =============================================================================

/**
 * Fetch EPSS scores for a specific date.
 *
 * EPSS CSV format:
 * ```
 * #model_version:v2023.03.01,score_date:2024-01-15T00:00:00+0000
 * cve,epss,percentile
 * CVE-1999-0001,0.01234,0.56789
 * ...
 * ```
 *
 * @param date - Date to fetch (default: today)
 * @returns Map from CVE ID -> EPSS info
 */
export async function fetchEpssData(date?: Date): Promise<EpssDataMap> {
    const targetDate = date ?? new Date();
    const dateStr = formatDate(targetDate);
    const url = `${EPSS_BASE_URL}/epss_scores-${dateStr}.csv.gz`;

    console.log(`[EPSS] Fetching EPSS data for ${dateStr}...`);

    try {
        const response = await fetch(url, {
            headers: {
                'Accept-Encoding': 'gzip',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) {
            // Try previous day if today's data is not available yet
            if (response.status === 404 && !date) {
                const yesterday = new Date(targetDate);
                yesterday.setDate(yesterday.getDate() - 1);
                console.log(`[EPSS] Today's data not available, trying ${formatDate(yesterday)}...`);
                return fetchEpssData(yesterday);
            }
            throw new Error(`EPSS fetch failed: ${response.status} ${response.statusText}`);
        }

        // Decompress and parse
        const compressedData = await response.arrayBuffer();
        const csvContent = await decompressGzip(compressedData);

        return parseEpssCsv(csvContent);
    } catch (error) {
        console.error('[EPSS] Fetch error:', error);

        // Fallback to API if CSV fails
        console.log('[EPSS] Falling back to FIRST.org API...');
        return fetchEpssFromApi();
    }
}

/**
 * Parse EPSS CSV content into Map
 */
function parseEpssCsv(csvContent: string): EpssDataMap {
    const lines = csvContent.split('\n');
    const epssMap: EpssDataMap = new Map();

    let headerFound = false;

    for (const line of lines) {
        // Skip empty lines and comments
        if (!line.trim() || line.startsWith('#')) continue;

        // Skip header line
        if (!headerFound && line.startsWith('cve,')) {
            headerFound = true;
            continue;
        }

        const fields = parseCsvLine(line);
        if (fields.length < 3) continue;

        const [cve, epssStr, percentileStr] = fields;

        // Validate CVE format
        if (!cve?.startsWith('CVE-')) continue;

        const epssScore = parseFloat(epssStr ?? '0');
        const percentile = parseFloat(percentileStr ?? '0');

        // Skip invalid values
        if (isNaN(epssScore) || isNaN(percentile)) continue;

        epssMap.set(cve, {
            score: epssScore,
            percentile: percentile,
        });
    }

    console.log(`[EPSS] Parsed ${epssMap.size} EPSS records`);
    return epssMap;
}

/**
 * Fallback: Fetch EPSS from FIRST.org API
 * API has rate limits so only use when CSV fails
 */
async function fetchEpssFromApi(): Promise<EpssDataMap> {
    const epssMap: EpssDataMap = new Map();
    let offset = 0;
    const limit = 1000;

    // API pagination
    while (true) {
        const url = `${EPSS_API_URL}?limit=${limit}&offset=${offset}`;

        const response = await fetch(url, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) {
            throw new Error(`EPSS API failed: ${response.status}`);
        }

        interface EpssApiResponse {
            status: string;
            status_code: number;
            total: number;
            data: Array<{
                cve: string;
                epss: string;
                percentile: string;
            }>;
        }

        const data = (await response.json()) as EpssApiResponse;

        if (!data.data || data.data.length === 0) break;

        for (const record of data.data) {
            epssMap.set(record.cve, {
                score: parseFloat(record.epss),
                percentile: parseFloat(record.percentile),
            });
        }

        offset += limit;

        // Stop if all records fetched
        if (offset >= data.total) break;

        // Rate limiting: wait 100ms between requests
        await new Promise((resolve) => setTimeout(resolve, 100));
    }

    console.log(`[EPSS] Fetched ${epssMap.size} records from API`);
    return epssMap;
}

/**
 * Fetch EPSS score for a single CVE (real-time lookup)
 * Use when EPSS is needed for a single CVE not in cache
 */
export async function fetchSingleEpss(cveId: string): Promise<EpssInfo | null> {
    try {
        const url = `${EPSS_API_URL}?cve=${encodeURIComponent(cveId)}`;

        const response = await fetch(url, {
            headers: {
                Accept: 'application/json',
                'User-Agent': 'MyoAPI/1.0 (CVE Aggregator)',
            },
        });

        if (!response.ok) return null;

        interface SingleEpssResponse {
            data: Array<{ epss: string; percentile: string }>;
        }

        const data = (await response.json()) as SingleEpssResponse;

        if (!data.data || data.data.length === 0) return null;

        const record = data.data[0];
        if (!record) return null;

        return {
            score: parseFloat(record.epss),
            percentile: parseFloat(record.percentile),
        };
    } catch (error) {
        console.error(`[EPSS] Failed to fetch single EPSS for ${cveId}:`, error);
        return null;
    }
}
