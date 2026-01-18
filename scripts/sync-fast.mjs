/**
 * CVE FAST Bulk Sync Script v5 - Full Multi-Source + GHSA
 * Downloads NVD + OSV + GHSA + EPSS + KEV
 * All multi-source fields populated
 */

import { config } from 'dotenv';
config();  // Load .env file

import { createClient } from '@supabase/supabase-js';
import lzma from 'lzma-native';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;  // For higher GHSA rate limits
const BATCH_SIZE = 1000;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// NVD years
const NVD_YEARS = ['2026', '2025', '2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017', '2016', '2015', '2014', '2013', '2012', '2011', '2010', '2009', '2008', '2007', '2006', '2005', '2004', '2003', '2002', '1999'];

// OSV ecosystems (GCS bucket)
const OSV_ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'NuGet', 'Packagist', 'RubyGems'];

// GHSA ecosystems to fetch from GitHub Advisory Database
const GHSA_ECOSYSTEMS = ['composer', 'go', 'maven', 'npm', 'nuget', 'pip', 'pub', 'rubygems', 'rust', 'swift'];

// =============================================================================
// XZ Decompression
// =============================================================================

async function decompressXz(buffer) {
    return new Promise((resolve, reject) => {
        lzma.decompress(buffer, (result, error) => {
            if (error) reject(error);
            else resolve(result);
        });
    });
}

// =============================================================================
// NVD Bulk Download
// =============================================================================

async function fetchNvdBulkData() {
    console.log('[NVD] Downloading bulk JSON feeds...');
    const allCves = new Map();

    for (const year of NVD_YEARS) {
        try {
            const url = `https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-${year}.json.xz`;
            console.log(`[NVD] Fetching ${year}...`);

            const response = await fetch(url, { headers: { 'User-Agent': 'MyoAPI/1.0' } });
            if (!response.ok) continue;

            const buffer = Buffer.from(await response.arrayBuffer());
            const jsonString = await decompressXz(buffer);
            const data = JSON.parse(jsonString.toString());
            const cves = data.cve_items || data.CVE_Items || data.vulnerabilities || [];

            for (const item of cves) {
                const cve = parseNvdItem(item);
                if (cve) allCves.set(cve.id, cve);
            }
            console.log(`[NVD] ${year}: ${cves.length} CVEs (Total: ${allCves.size})`);
        } catch (e) { console.log(`[NVD] ${year}: Error`); }
    }

    console.log(`[NVD] Total: ${allCves.size}`);
    return allCves;
}

// Parse CPE 2.3 string to package info
// Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
function parseCpeToPackage(cpe) {
    if (!cpe || !cpe.startsWith('cpe:2.3:')) return null;

    const parts = cpe.split(':');
    if (parts.length < 5) return null;

    const type = parts[2];  // a=application, o=os, h=hardware
    const vendor = parts[3] !== '*' ? parts[3] : null;
    const product = parts[4] !== '*' ? parts[4] : null;
    const version = parts[5] !== '*' && parts[5] !== '-' ? parts[5] : null;

    if (!product) return null;

    // Map to ecosystem based on vendor/product hints
    let ecosystem = 'unknown';
    const vendorLower = (vendor || '').toLowerCase();
    const productLower = (product || '').toLowerCase();

    if (vendorLower.includes('npm') || productLower.includes('node')) ecosystem = 'npm';
    else if (vendorLower.includes('pypi') || productLower.includes('python')) ecosystem = 'PyPI';
    else if (vendorLower.includes('maven') || productLower.includes('java')) ecosystem = 'Maven';
    else if (vendorLower.includes('nuget') || productLower.includes('dotnet')) ecosystem = 'NuGet';
    else if (vendorLower.includes('rubygems') || productLower.includes('ruby')) ecosystem = 'RubyGems';
    else if (vendorLower.includes('packagist') || productLower.includes('php')) ecosystem = 'Packagist';
    else if (vendorLower.includes('cargo') || productLower.includes('rust')) ecosystem = 'crates.io';
    else if (vendorLower.includes('golang') || productLower.includes('go')) ecosystem = 'Go';
    else if (type === 'o') ecosystem = 'OS';
    else if (type === 'h') ecosystem = 'Hardware';

    return {
        package: product.replace(/_/g, '-'),
        ecosystem,
        vendor: vendor ? vendor.replace(/_/g, '-') : null,
        versions: version ? [version] : [],
        fixed: [],
        status: 'affected'  // From CPE we only know affected, not fixed
    };
}

function parseNvdItem(item) {
    try {
        const cveData = item.cve || item;
        const id = cveData.id || cveData.CVE_data_meta?.ID;
        if (!id?.startsWith('CVE-')) return null;

        let description = '';
        if (cveData.descriptions) {
            description = cveData.descriptions.find(d => d.lang === 'en')?.value || '';
        } else if (cveData.description?.description_data) {
            description = cveData.description.description_data.find(d => d.lang === 'en')?.value || '';
        }

        let cvss = null;
        const metrics = item.metrics || item.impact;
        if (metrics?.cvssMetricV31?.[0]) {
            const d = metrics.cvssMetricV31[0].cvssData;
            cvss = { score: d.baseScore, vector: d.vectorString, version: '3.1' };
        } else if (metrics?.cvssMetricV30?.[0]) {
            const d = metrics.cvssMetricV30[0].cvssData;
            cvss = { score: d.baseScore, vector: d.vectorString, version: '3.0' };
        } else if (metrics?.cvssMetricV2?.[0]) {
            const d = metrics.cvssMetricV2[0].cvssData;
            cvss = { score: d.baseScore, vector: d.vectorString, version: '2.0' };
        } else if (metrics?.baseMetricV3?.cvssV3) {
            const d = metrics.baseMetricV3.cvssV3;
            cvss = { score: d.baseScore, vector: d.vectorString, version: '3.x' };
        } else if (metrics?.baseMetricV2?.cvssV2) {
            const d = metrics.baseMetricV2.cvssV2;
            cvss = { score: d.baseScore, vector: d.vectorString, version: '2.0' };
        }

        // Extract CWE IDs
        let cwe = [];
        if (cveData.weaknesses) {
            for (const w of cveData.weaknesses) {
                for (const desc of w.description || []) {
                    if (desc.value?.startsWith('CWE-')) {
                        cwe.push(desc.value);
                    }
                }
            }
        } else if (item.cwe?.cwe_data_meta) {
            // Legacy format
            const cweId = item.cwe.cwe_data_meta.ID;
            if (cweId) cwe.push(cweId);
        }
        cwe = [...new Set(cwe)].slice(0, 10);  // Deduplicate

        // Extract CPE URIs
        let cpe = [];
        if (cveData.configurations) {
            for (const config of cveData.configurations) {
                for (const node of config.nodes || []) {
                    for (const match of node.cpeMatch || []) {
                        if (match.criteria) {
                            cpe.push(match.criteria);
                        }
                    }
                }
            }
        } else if (item.configurations?.nodes) {
            // Legacy format
            for (const node of item.configurations.nodes) {
                for (const match of node.cpe_match || []) {
                    if (match.cpe23Uri) {
                        cpe.push(match.cpe23Uri);
                    }
                }
            }
        }
        cpe = [...new Set(cpe)].slice(0, 20);  // Deduplicate, limit

        let refs = [];
        if (cveData.references) refs = cveData.references.slice(0, 20).map(r => r.url);

        // Parse CPE to affected packages (fallback when OSV/GHSA have no data)
        const affectedFromCpe = [];
        const seenProducts = new Set();
        for (const cpeUri of cpe) {
            const pkg = parseCpeToPackage(cpeUri);
            if (pkg && !seenProducts.has(pkg.package)) {
                seenProducts.add(pkg.package);
                affectedFromCpe.push(pkg);
            }
        }

        return {
            id,
            description: description?.substring(0, 4000) || '',
            cvss,
            cwe,
            cpe,
            affected: affectedFromCpe.slice(0, 10),  // Limit to 10 packages
            refs,
            published: cveData.published || item.publishedDate,
            modified: cveData.lastModified || item.lastModifiedDate
        };
    } catch { return null; }
}

// =============================================================================
// OSV Bulk Download (from GCS)
// =============================================================================

async function fetchOsvBulkData() {
    console.log('[OSV] Downloading ecosystem data from GCS...');
    const osvMap = new Map();  // cveId -> osvData

    for (const ecosystem of OSV_ECOSYSTEMS) {
        try {
            // Download all.zip for each ecosystem
            const url = `https://storage.googleapis.com/osv-vulnerabilities/${ecosystem}/all.zip`;
            console.log(`[OSV] Fetching ${ecosystem}...`);

            const response = await fetch(url, { headers: { 'User-Agent': 'MyoAPI/1.0' } });
            if (!response.ok) { console.log(`[OSV] ${ecosystem}: Not available`); continue; }

            const buffer = Buffer.from(await response.arrayBuffer());
            const JSZip = (await import('jszip')).default;
            const zip = await JSZip.loadAsync(buffer);

            let count = 0;
            for (const filename of Object.keys(zip.files)) {
                if (!filename.endsWith('.json')) continue;

                try {
                    const content = await zip.files[filename].async('string');
                    const vuln = JSON.parse(content);

                    // Find CVE alias
                    const cveId = vuln.aliases?.find(a => a.startsWith('CVE-')) || (vuln.id?.startsWith('CVE-') ? vuln.id : null);
                    if (!cveId) continue;

                    // Extract OSV data
                    const existing = osvMap.get(cveId) || { cvss: null, affected: [], refs: [], aliases: [] };

                    // CVSS from OSV
                    if (!existing.cvss && vuln.severity?.[0]) {
                        const sev = vuln.severity[0];
                        if (sev.type === 'CVSS_V3' && sev.score) {
                            existing.cvss = { score: parseFloat(sev.score), vector: sev.vector || null, version: '3.x' };
                        }
                    }

                    // Affected packages with fixed versions
                    if (vuln.affected) {
                        for (const aff of vuln.affected) {
                            // Extract fixed versions from ranges (only SEMVER/ECOSYSTEM, skip GIT commits)
                            const fixedVersions = [];
                            if (aff.ranges) {
                                for (const range of aff.ranges) {
                                    // Skip GIT ranges (contain commit hashes, not versions)
                                    if (range.type === 'GIT') continue;

                                    for (const event of range.events || []) {
                                        if (event.fixed && !event.fixed.match(/^[0-9a-f]{40}$/)) {
                                            fixedVersions.push(event.fixed);
                                        }
                                    }
                                }
                            }

                            // Determine patch status
                            let status = 'unknown';
                            if (fixedVersions.length > 0) {
                                status = 'fixed';
                            } else if (aff.database_specific?.last_known_affected_version_range) {
                                status = 'affected';
                            }

                            existing.affected.push({
                                package: aff.package?.name,
                                ecosystem: aff.package?.ecosystem || ecosystem,
                                versions: aff.versions?.slice(0, 10) || [],
                                fixed: [...new Set(fixedVersions)].slice(0, 5),
                                status
                            });
                        }
                    }

                    // References
                    if (vuln.references) {
                        for (const ref of vuln.references.slice(0, 10)) {
                            if (ref.url && !existing.refs.includes(ref.url)) {
                                existing.refs.push(ref.url);
                            }
                        }
                    }

                    // Aliases
                    if (vuln.aliases) {
                        for (const alias of vuln.aliases) {
                            if (!existing.aliases.includes(alias) && alias !== cveId) {
                                existing.aliases.push(alias);
                            }
                        }
                    }
                    if (vuln.id && !existing.aliases.includes(vuln.id) && vuln.id !== cveId) {
                        existing.aliases.push(vuln.id);
                    }

                    osvMap.set(cveId, existing);
                    count++;
                } catch { }
            }

            console.log(`[OSV] ${ecosystem}: ${count} CVEs mapped`);
        } catch (e) {
            console.log(`[OSV] ${ecosystem}: Error - ${e.message}`);
        }
    }

    console.log(`[OSV] Total CVEs with OSV data: ${osvMap.size}`);
    return osvMap;
}

// =============================================================================
// GHSA Bulk Download (via GitHub REST API)
// =============================================================================

async function fetchGhsaBulkData() {
    console.log('[GHSA] Downloading GitHub Advisories via REST API...');
    const ghsaMap = new Map();

    if (!GITHUB_TOKEN) {
        console.log('[GHSA] No GITHUB_TOKEN - limited to 60 requests/hour.');
        return ghsaMap;
    }

    const baseUrl = 'https://api.github.com/advisories';
    let page = 1;
    let totalFetched = 0;
    const maxPages = 100;

    try {
        while (page <= maxPages) {
            const url = `${baseUrl}?per_page=100&page=${page}`;
            const headers = {
                'User-Agent': 'MyoAPI/2.0',
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'Authorization': `Bearer ${GITHUB_TOKEN}`
            };

            const response = await fetch(url, { headers });

            if (!response.ok) {
                if (response.status === 403) {
                    console.log(`[GHSA] Rate limited at page ${page}`);
                    break;
                }
                console.log(`[GHSA] Error: ${response.status}`);
                break;
            }

            const advisories = await response.json();
            if (!advisories.length) break;

            for (const adv of advisories) {
                const cveId = adv.cve_id;
                if (!cveId?.startsWith('CVE-')) continue;

                const existing = ghsaMap.get(cveId) || {
                    cvss: null, refs: [], ghsa_id: null, summary: null,
                    description: null, cwe: [], affected: [], fixed_versions: []
                };

                if (!existing.ghsa_id && adv.ghsa_id) existing.ghsa_id = adv.ghsa_id;
                if (!existing.summary && adv.summary) existing.summary = adv.summary.substring(0, 500);
                if (!existing.description && adv.description) existing.description = adv.description.substring(0, 4000);

                if (!existing.cvss && adv.cvss?.score) {
                    existing.cvss = { score: adv.cvss.score, vector: adv.cvss.vector_string, version: '3.x' };
                }

                if (adv.cwes) {
                    for (const cwe of adv.cwes) {
                        const cweId = cwe.cwe_id;
                        if (cweId && !existing.cwe.includes(cweId)) existing.cwe.push(cweId);
                    }
                }

                if (adv.references) {
                    for (const ref of adv.references.slice(0, 5)) {
                        if (ref.url && !existing.refs.includes(ref.url)) existing.refs.push(ref.url);
                    }
                }

                if (adv.vulnerabilities) {
                    for (const vuln of adv.vulnerabilities) {
                        if (vuln.package?.name && vuln.package?.ecosystem) {
                            // Extract fixed versions from multiple fields
                            const fixedVersions = [];
                            if (vuln.patched_versions) fixedVersions.push(vuln.patched_versions);
                            // first_patched_version can be string or {identifier: string}
                            if (vuln.first_patched_version) {
                                const fpv = typeof vuln.first_patched_version === 'string'
                                    ? vuln.first_patched_version
                                    : vuln.first_patched_version.identifier;
                                if (fpv) fixedVersions.push(fpv);
                            }

                            // Determine patch status
                            let status = 'unknown';
                            if (fixedVersions.length > 0) {
                                status = 'fixed';
                            } else if (vuln.vulnerable_version_range) {
                                status = 'affected';
                            }

                            existing.affected.push({
                                package: vuln.package.name,
                                ecosystem: vuln.package.ecosystem,
                                versions: vuln.vulnerable_version_range ? [vuln.vulnerable_version_range] : [],
                                fixed: [...new Set(fixedVersions)].slice(0, 5),
                                status
                            });

                            for (const fv of fixedVersions) {
                                if (!existing.fixed_versions.includes(fv)) {
                                    existing.fixed_versions.push(fv);
                                }
                            }
                        }
                    }
                }

                ghsaMap.set(cveId, existing);
                totalFetched++;
            }

            if (page % 10 === 0) console.log(`[GHSA] Page ${page}: ${totalFetched} CVEs...`);
            page++;
            await new Promise(r => setTimeout(r, 50));
        }
    } catch (e) {
        console.log(`[GHSA] Error: ${e.message}`);
    }

    console.log(`[GHSA] Total CVEs with GHSA data: ${ghsaMap.size}`);
    return ghsaMap;
}

// =============================================================================
// EPSS Fetcher
// =============================================================================

async function fetchEpssData() {
    console.log('[EPSS] Fetching EPSS scores...');

    // Try multiple EPSS sources
    const urls = [
        'https://epss.cyentia.com/epss_scores-current.csv.gz',
        'https://api.first.org/data/v1/epss?envelope=true&pretty=false'
    ];

    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    const twoDaysAgo = new Date(today);
    twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);

    // Add date-based URLs
    urls.unshift(
        `https://epss.empiricalsecurity.com/epss_scores-${today.toISOString().split('T')[0]}.csv.gz`,
        `https://epss.empiricalsecurity.com/epss_scores-${yesterday.toISOString().split('T')[0]}.csv.gz`,
        `https://epss.empiricalsecurity.com/epss_scores-${twoDaysAgo.toISOString().split('T')[0]}.csv.gz`
    );

    try {
        let response = null;
        let url = '';

        for (const u of urls) {
            try {
                console.log(`[EPSS] Trying ${u.substring(0, 60)}...`);
                response = await fetch(u, { headers: { 'User-Agent': 'MyoAPI/1.0' } });
                if (response.ok) {
                    url = u;
                    break;
                }
            } catch (e) {
                continue;
            }
        }

        if (!response?.ok) {
            console.log('[EPSS] All sources failed, skipping EPSS');
            return new Map();
        }

        const epssMap = new Map();

        // Handle JSON API response
        if (url.includes('first.org')) {
            const data = await response.json();
            for (const item of data.data || []) {
                if (item.cve?.startsWith('CVE-')) {
                    epssMap.set(item.cve, { score: parseFloat(item.epss) || null, percentile: parseFloat(item.percentile) || null });
                }
            }
        } else {
            // Handle CSV response
            const { gunzipSync } = await import('zlib');
            const buffer = Buffer.from(await response.arrayBuffer());
            const csvContent = gunzipSync(buffer).toString('utf-8');

            let headerFound = false;
            for (const line of csvContent.split('\n')) {
                if (!line.trim() || line.startsWith('#')) continue;
                if (!headerFound && line.startsWith('cve,')) { headerFound = true; continue; }
                const [cve, epss, percentile] = line.split(',');
                if (!cve?.startsWith('CVE-')) continue;
                epssMap.set(cve.trim(), { score: parseFloat(epss) || null, percentile: parseFloat(percentile) || null });
            }
        }

        console.log(`[EPSS] Loaded ${epssMap.size} scores`);
        return epssMap;
    } catch (e) {
        console.error('[EPSS] Error:', e.message);
        return new Map();
    }
}

// =============================================================================
// KEV Fetcher
// =============================================================================

async function fetchKevData() {
    console.log('[KEV] Fetching CISA KEV catalog...');
    try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { headers: { 'User-Agent': 'MyoAPI/1.0' } });
        if (!response.ok) throw new Error('KEV fetch failed');
        const data = await response.json();
        const kevMap = new Map();
        for (const vuln of data.vulnerabilities || []) {
            if (vuln.cveID?.startsWith('CVE-')) {
                kevMap.set(vuln.cveID, { is_known: true, date_added: vuln.dateAdded || null, due_date: vuln.dueDate || null });
            }
        }
        console.log(`[KEV] Loaded ${kevMap.size} CVEs`);
        return kevMap;
    } catch (e) { console.error('[KEV] Error:', e.message); return new Map(); }
}

// =============================================================================
// Helpers
// =============================================================================

function getSeverity(cvssScore) {
    if (cvssScore == null) return 'UNKNOWN';
    if (cvssScore >= 9.0) return 'CRITICAL';
    if (cvssScore >= 7.0) return 'HIGH';
    if (cvssScore >= 4.0) return 'MEDIUM';
    if (cvssScore >= 0.1) return 'LOW';
    return 'NONE';
}

function calculatePriority(cvssScore, epssScore, isKev) {
    const kevBonus = isKev ? 1 : 0;
    const epss = epssScore || 0;
    if (cvssScore == null) return Math.round((epss * 0.7 + kevBonus * 0.3) * 100000) / 100000;
    return Math.round((cvssScore / 10 * 0.3 + epss * 0.5 + kevBonus * 0.2) * 100000) / 100000;
}

// =============================================================================
// Main
// =============================================================================

async function main() {
    console.log('=== CVE SYNC v5 (Full Multi-Source + GHSA) ===');
    console.log(`Time: ${new Date().toISOString()}`);

    if (!SUPABASE_URL || !SUPABASE_KEY) { console.error('Missing Supabase credentials'); process.exit(1); }

    // Fetch all sources in parallel
    console.log('\n--- Step 1: Fetching all sources ---');
    const [nvdMap, osvMap, ghsaMap, epssMap, kevMap] = await Promise.all([
        fetchNvdBulkData(),
        fetchOsvBulkData(),
        fetchGhsaBulkData(),
        fetchEpssData(),
        fetchKevData()
    ]);

    // Merge
    console.log('\n--- Step 2: Merging data ---');
    const allCveIds = new Set([...nvdMap.keys(), ...epssMap.keys(), ...osvMap.keys(), ...ghsaMap.keys()]);
    console.log(`[Merge] Total unique CVEs: ${allCveIds.size}`);

    // Build records
    const records = [];
    for (const id of allCveIds) {
        const nvd = nvdMap.get(id);
        const osv = osvMap.get(id);
        const ghsa = ghsaMap.get(id);
        const epss = epssMap.get(id);
        const kev = kevMap.get(id);

        // Best CVSS (NVD > GHSA > OSV priority)
        const cvssScore = nvd?.cvss?.score ?? ghsa?.cvss?.score ?? osv?.cvss?.score ?? null;

        const sources = [];
        if (nvd) sources.push('nvd');
        if (osv) sources.push('osv');
        if (ghsa) sources.push('ghsa');
        if (epss) sources.push('epss');
        if (kev) sources.push('kev');

        // Merge aliases (OSV + GHSA ID) - deduplicated
        const aliases = [...new Set([
            ...(osv?.aliases?.slice(0, 10) || []),
            ...(ghsa?.ghsa_id ? [ghsa.ghsa_id] : [])
        ])];

        // Merge CWE from NVD and GHSA - deduplicated
        const cwe = [...new Set([
            ...(nvd?.cwe || []),
            ...(ghsa?.cwe || [])
        ])].slice(0, 10);

        // CPE from NVD
        const cpe = nvd?.cpe?.slice(0, 20) || [];

        // Description with fallback (NVD > GHSA)
        const description = nvd?.description || ghsa?.description || '';

        records.push({
            id,
            title: ghsa?.summary || null,
            description,
            severity: getSeverity(cvssScore),

            cvss: {
                nvd: nvd?.cvss || null,
                osv: osv?.cvss || null,
                ghsa: ghsa?.cvss || null,
                vendor: null
            },
            epss: epss || { score: null, percentile: null },
            kev: kev || { is_known: false, date_added: null, due_date: null },

            cwe,
            cpe,

            affected: {
                nvd: nvd?.affected?.slice(0, 10) || [],
                osv: osv?.affected?.slice(0, 20) || [],
                ghsa: ghsa?.affected?.slice(0, 20) || []
            },
            refs: {
                nvd: nvd?.refs || [],
                osv: osv?.refs || [],
                ghsa: ghsa?.refs || [],
                vendor: []
            },

            aliases,
            priority_score: calculatePriority(cvssScore, epss?.score, !!kev),
            published: nvd?.published || null,
            modified: nvd?.modified || null,
            sources
        });
    }

    // Upload
    console.log('\n--- Step 3: Uploading to Supabase ---');
    console.log(`[Supabase] Uploading ${records.length} records...`);

    let uploaded = 0;
    for (let i = 0; i < records.length; i += BATCH_SIZE) {
        const batch = records.slice(i, i + BATCH_SIZE);
        await supabase.from('cves').upsert(batch, { onConflict: 'id' });
        uploaded += batch.length;
        if ((i / BATCH_SIZE) % 50 === 0) console.log(`[Supabase] Progress: ${uploaded}/${records.length}`);
    }

    // Stats
    const stats = {
        total: records.length,
        withNvd: records.filter(r => r.cvss.nvd !== null).length,
        withOsv: records.filter(r => r.sources.includes('osv')).length,
        withGhsa: records.filter(r => r.sources.includes('ghsa')).length,
        withEpss: records.filter(r => r.epss.score !== null).length,
        kevCount: records.filter(r => r.kev.is_known).length,
        critical: records.filter(r => r.severity === 'CRITICAL').length,
        high: records.filter(r => r.severity === 'HIGH').length
    };

    console.log('\n=== SYNC COMPLETED ===');
    console.log(`Total CVEs: ${stats.total}`);
    console.log(`With NVD CVSS: ${stats.withNvd}`);
    console.log(`With OSV data: ${stats.withOsv}`);
    console.log(`With GHSA data: ${stats.withGhsa}`);
    console.log(`With EPSS: ${stats.withEpss}`);
    console.log(`KEV CVEs: ${stats.kevCount}`);
    console.log(`CRITICAL: ${stats.critical}, HIGH: ${stats.high}`);
}

main().catch(err => { console.error('Sync failed:', err); process.exit(1); });
