/**
 * CVE Data Sync Script - Full Implementation
 * Fetches real vulnerability data from OSV.dev, EPSS, KEV, and NVD
 * 
 * Usage: node scripts/sync-data.mjs
 */

const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const CF_API_TOKEN = process.env.CF_API_TOKEN;
const CVE_DATA_NS = process.env.CVE_DATA_NAMESPACE_ID;
const METADATA_NS = process.env.METADATA_NAMESPACE_ID;
const NVD_API_KEY = process.env.NVD_API_KEY || '';

// Ecosystems to fetch from OSV (prioritized)
const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'NuGet'];
const MAX_CVES_PER_ECOSYSTEM = 50;  // Limit per ecosystem
const MAX_TOTAL_CVES = 200;          // Total limit

// =============================================================================
// OSV.dev Fetcher (from GCS)
// =============================================================================

async function fetchOsvVulnerabilities() {
    console.log('[OSV] Fetching vulnerabilities from GCS...');

    const allVulns = [];

    for (const ecosystem of ECOSYSTEMS) {
        try {
            // Fetch modified_id.csv to get recent vulnerabilities
            const csvUrl = `https://storage.googleapis.com/osv-vulnerabilities/${ecosystem}/modified_id.csv`;
            const response = await fetch(csvUrl);

            if (!response.ok) {
                console.log(`[OSV] Skipping ${ecosystem} (not available)`);
                continue;
            }

            const csvText = await response.text();
            const lines = csvText.trim().split('\n');

            // Get most recent CVEs (skip header if exists)
            const cveIds = [];
            for (const line of lines) {
                const [id] = line.split(',');
                if (id?.startsWith('CVE-')) {
                    cveIds.push(id.trim());
                    if (cveIds.length >= MAX_CVES_PER_ECOSYSTEM) break;
                }
            }

            console.log(`[OSV] Found ${cveIds.length} CVEs in ${ecosystem}`);

            // Fetch vulnerability details for each CVE
            for (const cveId of cveIds) {
                if (allVulns.length >= MAX_TOTAL_CVES) break;

                const vuln = await fetchOsvVulnDetails(cveId);
                if (vuln) {
                    vuln.ecosystem = ecosystem;
                    allVulns.push(vuln);
                }

                // Small delay to avoid rate limiting
                await new Promise(r => setTimeout(r, 50));
            }

            if (allVulns.length >= MAX_TOTAL_CVES) break;

        } catch (error) {
            console.error(`[OSV] Error fetching ${ecosystem}:`, error.message);
        }
    }

    console.log(`[OSV] Total vulnerabilities fetched: ${allVulns.length}`);
    return allVulns;
}

async function fetchOsvVulnDetails(cveId) {
    const url = `https://api.osv.dev/v1/vulns/${cveId}`;

    try {
        const response = await fetch(url, {
            headers: { 'User-Agent': 'MyoAPI/1.0' }
        });

        if (!response.ok) return null;

        const data = await response.json();

        return {
            id: data.id,
            aliases: data.aliases || [],
            summary: data.summary || '',
            details: data.details || '',
            published: data.published,
            modified: data.modified,
            affected: (data.affected || []).map(a => ({
                package: a.package?.name,
                ecosystem: a.package?.ecosystem,
                versions: a.versions?.slice(0, 10) || [],  // Limit versions
                ranges: a.ranges?.slice(0, 3) || []
            })),
            references: (data.references || []).slice(0, 10).map(r => r.url),
            severity: extractSeverityFromOsv(data),
            cvssFromOsv: extractCvssFromOsv(data)
        };
    } catch (error) {
        return null;
    }
}

function extractSeverityFromOsv(data) {
    const severity = data.severity?.[0];
    if (!severity) return null;
    return severity.score || null;
}

function extractCvssFromOsv(data) {
    const severity = data.database_specific?.severity || data.severity?.[0];
    if (!severity) return null;

    if (severity.type === 'CVSS_V3' && severity.score) {
        return {
            score: parseFloat(severity.score) || null,
            vector: severity.vector || null,
            version: '3.1'
        };
    }
    return null;
}

// =============================================================================
// EPSS Fetcher
// =============================================================================

async function fetchEpssData() {
    console.log('[EPSS] Fetching EPSS scores...');

    const today = new Date();
    const dateStr = today.toISOString().split('T')[0];
    const url = `https://epss.empiricalsecurity.com/epss_scores-${dateStr}.csv.gz`;

    try {
        let response = await fetch(url);
        if (!response.ok) {
            // Try yesterday
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            const yesterdayStr = yesterday.toISOString().split('T')[0];
            const fallbackUrl = `https://epss.empiricalsecurity.com/epss_scores-${yesterdayStr}.csv.gz`;
            response = await fetch(fallbackUrl);
            if (!response.ok) throw new Error('EPSS fetch failed');
        }

        const { gunzipSync } = await import('zlib');
        const buffer = Buffer.from(await response.arrayBuffer());
        const csvContent = gunzipSync(buffer).toString('utf-8');

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
    } catch (error) {
        console.error('[EPSS] Error:', error.message);
        return new Map();
    }
}

// =============================================================================
// KEV Fetcher
// =============================================================================

async function fetchKevData() {
    console.log('[KEV] Fetching CISA KEV catalog...');

    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    try {
        const response = await fetch(url, {
            headers: { 'User-Agent': 'MyoAPI/1.0' }
        });
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
// NVD CVSS Fetcher
// =============================================================================

async function fetchCvssFromNvd(cveId) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const headers = { 'User-Agent': 'MyoAPI/1.0' };
    if (NVD_API_KEY) {
        headers['apiKey'] = NVD_API_KEY;
    }

    try {
        const response = await fetch(url, { headers });
        if (!response.ok) return null;

        const data = await response.json();
        const vuln = data.vulnerabilities?.[0]?.cve;
        if (!vuln) return null;

        const metrics = vuln.metrics;
        const cvss31 = metrics?.cvssMetricV31?.[0]?.cvssData;
        const cvss30 = metrics?.cvssMetricV30?.[0]?.cvssData;
        const cvss2 = metrics?.cvssMetricV2?.[0]?.cvssData;

        if (cvss31) return { score: cvss31.baseScore, vector: cvss31.vectorString, version: '3.1' };
        if (cvss30) return { score: cvss30.baseScore, vector: cvss30.vectorString, version: '3.0' };
        if (cvss2) return { score: cvss2.baseScore, vector: cvss2.vectorString, version: '2.0' };

        return null;
    } catch (error) {
        return null;
    }
}

// =============================================================================
// CVE Record Builder
// =============================================================================

function getSeverityFromCvss(score) {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'NONE';
}

function calculatePriorityScore(cvssScore, epssScore, isKev) {
    const kevBonus = isKev ? 1 : 0;

    if (cvssScore === null || cvssScore === undefined) {
        // No CVSS - rely on EPSS and KEV only
        return Math.round((epssScore * 0.7 + kevBonus * 0.3) * 10000) / 10000;
    }

    const cvssNormalized = cvssScore / 10;
    return Math.round((cvssNormalized * 0.3 + epssScore * 0.5 + kevBonus * 0.2) * 10000) / 10000;
}

async function buildCveRecords(osvVulns, epssMap, kevSet) {
    console.log('[Build] Building CVE records with enriched data...');

    const records = [];
    const nvdDelay = NVD_API_KEY ? 100 : 6500;
    let nvdFetched = 0;

    for (const vuln of osvVulns) {
        const cveId = vuln.id;
        const epss = epssMap.get(cveId);
        const isKev = kevSet.has(cveId);

        // Try to get CVSS from OSV first, then NVD
        let cvss = vuln.cvssFromOsv;

        if (!cvss && nvdFetched < 50) {  // Limit NVD API calls
            cvss = await fetchCvssFromNvd(cveId);
            nvdFetched++;
            if (nvdFetched < 50) {
                await new Promise(r => setTimeout(r, nvdDelay));
            }
        }

        const cvssScore = cvss?.score ?? null;
        const epssScore = epss?.score ?? 0;
        const priorityScore = calculatePriorityScore(cvssScore, epssScore, isKev);

        records.push({
            id: cveId,
            title: vuln.summary || `Vulnerability ${cveId}`,
            description: vuln.details?.substring(0, 500) || vuln.summary || '',
            severity: getSeverityFromCvss(cvssScore),
            cvss,
            epss: epss || null,
            priorityScore,
            isKev,
            ecosystem: vuln.ecosystem,
            published: vuln.published || new Date().toISOString(),
            modified: vuln.modified || new Date().toISOString(),
            affected: vuln.affected || [],
            references: vuln.references || [],
            aliases: vuln.aliases || [],
            sources: {
                osv: true,
                nvd: cvss !== null,
                epss: epss !== undefined,
                kev: isKev
            }
        });
    }

    // Sort by priority score (highest first)
    records.sort((a, b) => b.priorityScore - a.priorityScore);

    console.log(`[Build] Built ${records.length} CVE records`);
    return records;
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

    // Fetch all data sources in parallel
    const [osvVulns, epssMap, kevSet] = await Promise.all([
        fetchOsvVulnerabilities(),
        fetchEpssData(),
        fetchKevData()
    ]);

    // Build enriched CVE records
    const cveRecords = await buildCveRecords(osvVulns, epssMap, kevSet);
    console.log(`[Sync] Total CVE records: ${cveRecords.length}`);

    // Upload CVE records
    console.log('[Sync] Uploading to Cloudflare KV...');
    let uploaded = 0;

    for (const record of cveRecords) {
        await uploadToKV(CVE_DATA_NS, `cve:${record.id}`, record);
        uploaded++;
        if (uploaded % 20 === 0) {
            console.log(`[Sync] Uploaded ${uploaded}/${cveRecords.length}`);
        }
    }

    // Build stats
    const stats = {
        totalCves: cveRecords.length,
        bySeverity: {
            CRITICAL: cveRecords.filter(r => r.severity === 'CRITICAL').length,
            HIGH: cveRecords.filter(r => r.severity === 'HIGH').length,
            MEDIUM: cveRecords.filter(r => r.severity === 'MEDIUM').length,
            LOW: cveRecords.filter(r => r.severity === 'LOW').length,
            UNKNOWN: cveRecords.filter(r => r.severity === 'UNKNOWN').length
        },
        byEcosystem: {},
        kevCount: cveRecords.filter(r => r.isKev).length,
        lastSyncTime: new Date().toISOString(),
        sources: {
            osv: { lastSync: new Date().toISOString(), count: osvVulns.length },
            epss: { lastSync: new Date().toISOString(), count: epssMap.size },
            kev: { lastSync: new Date().toISOString(), count: kevSet.size }
        }
    };

    // Count by ecosystem
    for (const record of cveRecords) {
        const eco = record.ecosystem || 'unknown';
        stats.byEcosystem[eco] = (stats.byEcosystem[eco] || 0) + 1;
    }

    await uploadToKV(METADATA_NS, 'meta:stats', stats);

    console.log('=== CVE Data Sync Completed ===');
    console.log(`Total CVEs: ${stats.totalCves}`);
    console.log(`By Severity: CRITICAL=${stats.bySeverity.CRITICAL}, HIGH=${stats.bySeverity.HIGH}, MEDIUM=${stats.bySeverity.MEDIUM}`);
    console.log(`KEV CVEs: ${stats.kevCount}`);
}

main().catch(err => {
    console.error('Sync failed:', err);
    process.exit(1);
});
