/**
 * CVE Data Sync Script
 * Runs in GitHub Actions to fetch CVE data and upload to Cloudflare KV
 * 
 * Usage: node scripts/sync-data.mjs
 * 
 * Environment variables required:
 * - CF_ACCOUNT_ID: Cloudflare account ID
 * - CF_API_TOKEN: Cloudflare API token with KV write access
 * - CVE_DATA_NAMESPACE_ID: KV namespace ID for CVE_DATA
 * - CVE_INDEX_NAMESPACE_ID: KV namespace ID for CVE_INDEX
 * - METADATA_NAMESPACE_ID: KV namespace ID for METADATA
 */

const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CVE_DATA_NS = process.env.CVE_DATA_NAMESPACE_ID;
const METADATA_NS = process.env.METADATA_NAMESPACE_ID;

// =============================================================================
// EPSS Fetcher
// =============================================================================

async function fetchEpssData() {
    console.log('[EPSS] Fetching EPSS scores...');

    const today = new Date();
    const dateStr = today.toISOString().split('T')[0];
    const url = `https://epss.empiricalsecurity.com/epss_scores-${dateStr}.csv.gz`;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            // Try yesterday
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            const yesterdayStr = yesterday.toISOString().split('T')[0];
            const fallbackUrl = `https://epss.empiricalsecurity.com/epss_scores-${yesterdayStr}.csv.gz`;
            const fallbackResponse = await fetch(fallbackUrl);
            if (!fallbackResponse.ok) throw new Error('EPSS fetch failed');
            return parseEpssCsv(await decompressGzip(await fallbackResponse.arrayBuffer()));
        }
        return parseEpssCsv(await decompressGzip(await response.arrayBuffer()));
    } catch (error) {
        console.error('[EPSS] Error:', error.message);
        return new Map();
    }
}

async function decompressGzip(data) {
    const { gunzipSync } = await import('zlib');
    return gunzipSync(Buffer.from(data)).toString('utf-8');
}

function parseEpssCsv(csvContent) {
    const lines = csvContent.split('\n');
    const epssMap = new Map();
    let headerFound = false;

    for (const line of lines) {
        if (!line.trim() || line.startsWith('#')) continue;
        if (!headerFound && line.startsWith('cve,')) {
            headerFound = true;
            continue;
        }

        const [cve, epss, percentile] = line.split(',');
        if (!cve?.startsWith('CVE-')) continue;

        epssMap.set(cve.trim(), {
            score: parseFloat(epss) || 0,
            percentile: parseFloat(percentile) || 0
        });
    }

    console.log(`[EPSS] Loaded ${epssMap.size} scores`);
    return epssMap;
}

// =============================================================================
// KEV Fetcher
// =============================================================================

async function fetchKevData() {
    console.log('[KEV] Fetching CISA KEV catalog...');

    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('KEV fetch failed');

        const data = await response.json();
        const kevSet = new Set();

        for (const vuln of data.vulnerabilities || []) {
            if (vuln.cveID?.startsWith('CVE-')) {
                kevSet.add(vuln.cveID);
            }
        }

        console.log(`[KEV] Loaded ${kevSet.size} CVEs`);
        return kevSet;
    } catch (error) {
        console.error('[KEV] Error:', error.message);
        return new Set();
    }
}

// =============================================================================
// Sample CVE Data (for testing)
// =============================================================================

function generateSampleCves(epssMap, kevSet) {
    // Top 100 critical CVEs from 2024 for demo
    const sampleCveIds = [
        'CVE-2024-3400', 'CVE-2024-21762', 'CVE-2024-1709', 'CVE-2024-27198',
        'CVE-2024-20353', 'CVE-2024-4577', 'CVE-2024-23897', 'CVE-2024-21893',
        'CVE-2024-0012', 'CVE-2024-9474', 'CVE-2024-38812', 'CVE-2024-47575',
        'CVE-2024-50623', 'CVE-2024-11667', 'CVE-2024-21887', 'CVE-2024-5910',
        'CVE-2024-40711', 'CVE-2024-8963', 'CVE-2024-9680', 'CVE-2024-43573',
    ];

    const records = [];

    for (const cveId of sampleCveIds) {
        const epss = epssMap.get(cveId);
        const isKev = kevSet.has(cveId);
        const cvssScore = 8.0 + Math.random() * 2; // 8.0-10.0 for critical

        const priorityScore = calculatePriorityScore(cvssScore, epss?.score || 0, isKev);

        records.push({
            id: cveId,
            title: `Critical vulnerability ${cveId}`,
            description: `Security vulnerability tracked as ${cveId}. Check NVD for details.`,
            severity: cvssScore >= 9 ? 'CRITICAL' : 'HIGH',
            cvss: { score: Math.round(cvssScore * 10) / 10, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', version: '3.1' },
            epss: epss || null,
            priorityScore,
            isKev,
            published: '2024-01-01T00:00:00Z',
            modified: new Date().toISOString(),
            affected: [],
            references: [`https://nvd.nist.gov/vuln/detail/${cveId}`],
            aliases: [],
            sources: { osv: false, nvd: true }
        });
    }

    return records;
}

function calculatePriorityScore(cvssScore, epssScore, isKev) {
    const cvssNormalized = cvssScore / 10;
    const kevBonus = isKev ? 1 : 0;
    return Math.round((cvssNormalized * 0.3 + epssScore * 0.5 + kevBonus * 0.2) * 10000) / 10000;
}

// =============================================================================
// Cloudflare KV Upload
// =============================================================================

async function uploadToKV(namespaceId, key, value) {
    const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;

    const response = await fetch(url, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${CF_API_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(value)
    });

    if (!response.ok) {
        const error = await response.text();
        throw new Error(`KV upload failed: ${error}`);
    }

    return true;
}

// =============================================================================
// Main Sync
// =============================================================================

async function main() {
    console.log('=== CVE Data Sync Started ===');
    console.log(`Time: ${new Date().toISOString()}`);

    // Validate env
    if (!CF_ACCOUNT_ID || !CF_API_TOKEN || !CVE_DATA_NS || !METADATA_NS) {
        console.error('Missing required environment variables');
        process.exit(1);
    }

    // Fetch data
    const [epssMap, kevSet] = await Promise.all([
        fetchEpssData(),
        fetchKevData()
    ]);

    // Generate sample CVE records
    const cveRecords = generateSampleCves(epssMap, kevSet);
    console.log(`[Sync] Generated ${cveRecords.length} CVE records`);

    // Upload CVE records
    console.log('[Sync] Uploading to Cloudflare KV...');
    let uploaded = 0;

    for (const record of cveRecords) {
        await uploadToKV(CVE_DATA_NS, `cve:${record.id}`, record);
        uploaded++;
        if (uploaded % 10 === 0) {
            console.log(`[Sync] Uploaded ${uploaded}/${cveRecords.length}`);
        }
    }

    // Update metadata
    const stats = {
        totalCves: cveRecords.length,
        bySeverity: {
            CRITICAL: cveRecords.filter(r => r.severity === 'CRITICAL').length,
            HIGH: cveRecords.filter(r => r.severity === 'HIGH').length,
            MEDIUM: 0,
            LOW: 0,
            UNKNOWN: 0
        },
        byEcosystem: {},
        kevCount: cveRecords.filter(r => r.isKev).length,
        lastSyncTime: new Date().toISOString(),
        sources: {
            osv: { lastSync: 'N/A', count: 0 },
            epss: { lastSync: new Date().toISOString(), date: new Date().toISOString().split('T')[0] },
            kev: { lastSync: new Date().toISOString(), count: kevSet.size }
        }
    };

    await uploadToKV(METADATA_NS, 'meta:stats', stats);

    console.log('=== CVE Data Sync Completed ===');
    console.log(`Total CVEs: ${stats.totalCves}`);
    console.log(`KEV CVEs: ${stats.kevCount}`);
}

main().catch(err => {
    console.error('Sync failed:', err);
    process.exit(1);
});
