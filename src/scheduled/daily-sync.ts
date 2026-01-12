/**
 * =============================================================================
 * MyoAPI - Daily Sync Handler
 * =============================================================================
 *
 * Scheduled job that runs daily to sync CVE data from multiple sources.
 * Triggered by Cloudflare Cron Triggers (configured in wrangler.toml).
 *
 * Sync order:
 * 1. Fetch EPSS data (daily CSV)
 * 2. Fetch CISA KEV catalog
 * 3. Fetch modified OSV records
 * 4. Merge data and update KV storage
 * 5. Update statistics
 */

import type { ApiStats, CveRecord, Severity, SyncMetadata } from '../models/cve';
import type { Env } from '../types/env';
import { fetchEpssData, type EpssDataMap } from '../fetchers/epss';
import { fetchKevData, type KevDataSet } from '../fetchers/kev';
import { batchFetchOsv, fetchModifiedIds } from '../fetchers/osv';

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Maximum CVE records to process per sync
 * Helps stay within Workers CPU time limits
 */
const MAX_RECORDS_PER_SYNC = 1000;

/**
 * Maximum CVE IDs to store in a single index
 */
const MAX_INDEX_SIZE = 5000;

// =============================================================================
// SYNC FUNCTIONS
// =============================================================================

/**
 * Main sync function called by Cron Trigger
 */
export async function runDailySync(env: Env): Promise<void> {
    const startTime = Date.now();
    console.log('[Sync] Starting daily CVE data sync...');

    try {
        // Step 1: Fetch EPSS data
        console.log('[Sync] Step 1/5: Fetching EPSS data...');
        const epssData = await fetchEpssData();
        console.log(`[Sync] EPSS: Loaded ${epssData.size} scores`);

        // Step 2: Fetch KEV data
        console.log('[Sync] Step 2/5: Fetching CISA KEV catalog...');
        const kevSet = await fetchKevData();
        console.log(`[Sync] KEV: Loaded ${kevSet.size} CVE IDs`);

        // Step 3: Get last sync time to fetch only modified records
        const lastSyncMeta = await env.METADATA.get('meta:sync');
        let lastSyncTime: Date | undefined;

        if (lastSyncMeta) {
            const meta = JSON.parse(lastSyncMeta) as SyncMetadata;
            lastSyncTime = new Date(meta.lastSyncTime);
            console.log(`[Sync] Last sync: ${meta.lastSyncTime}`);
        }

        // Step 4: Fetch modified OSV records
        console.log('[Sync] Step 3/5: Fetching modified CVE records...');
        const modifiedEntries = await fetchModifiedIds(lastSyncTime);
        console.log(`[Sync] OSV: Found ${modifiedEntries.length} modified entries`);

        // Limit to prevent timeout
        const entriesToProcess = modifiedEntries.slice(0, MAX_RECORDS_PER_SYNC);

        // Step 5: Batch fetch and convert OSV records
        console.log('[Sync] Step 4/5: Processing CVE records...');
        const cveRecords = await batchFetchOsv(entriesToProcess, epssData, kevSet, 5);
        console.log(`[Sync] Processed ${cveRecords.length} CVE records`);

        // Step 6: Store records in KV
        console.log('[Sync] Step 5/5: Storing data in KV...');
        await storeRecords(env, cveRecords, kevSet);

        // Update statistics
        await updateStats(env, cveRecords, epssData, kevSet);

        // Update sync metadata
        const syncDuration = Date.now() - startTime;
        const syncMeta: SyncMetadata = {
            lastSyncTime: new Date().toISOString(),
            lastEpssDate: new Date().toISOString().split('T')[0] ?? '',
            lastKevSync: new Date().toISOString(),
            lastOsvSync: new Date().toISOString(),
            syncDurationMs: syncDuration,
            recordsUpdated: cveRecords.length,
        };

        await env.METADATA.put('meta:sync', JSON.stringify(syncMeta));

        console.log(`[Sync] Completed in ${syncDuration}ms. Updated ${cveRecords.length} records.`);
    } catch (error) {
        console.error('[Sync] Failed:', error);
        throw error;
    }
}

/**
 * Store CVE records in KV storage
 */
async function storeRecords(env: Env, records: CveRecord[], kevSet: KevDataSet): Promise<void> {
    // Index structures
    const ecosystemIndex: Record<string, string[]> = {};
    const severityIndex: Record<Severity, string[]> = {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        UNKNOWN: [],
    };
    const kevIndex: string[] = [];
    const recentIndex: string[] = [];

    // Store each record and build indexes
    for (const record of records) {
        // Store CVE record
        await env.CVE_DATA.put(`cve:${record.id}`, JSON.stringify(record), {
            expirationTtl: 86400 * 30, // 30 days TTL
        });

        // Add to recent index
        recentIndex.push(record.id);

        // Add to severity index
        severityIndex[record.severity].push(record.id);

        // Add to KEV index
        if (kevSet.has(record.id)) {
            kevIndex.push(record.id);
        }

        // Add to ecosystem indexes
        for (const pkg of record.affected) {
            const eco = pkg.ecosystem;
            if (!ecosystemIndex[eco]) {
                ecosystemIndex[eco] = [];
            }
            if (!ecosystemIndex[eco].includes(record.id)) {
                ecosystemIndex[eco].push(record.id);
            }
        }
    }

    // Store indexes (merge with existing)
    await mergeAndStoreIndex(env.CVE_INDEX, 'idx:recent', recentIndex);
    await mergeAndStoreIndex(env.CVE_INDEX, 'idx:kev', kevIndex);

    for (const [severity, ids] of Object.entries(severityIndex)) {
        if (ids.length > 0) {
            await mergeAndStoreIndex(env.CVE_INDEX, `idx:sev:${severity}`, ids);
        }
    }

    for (const [ecosystem, ids] of Object.entries(ecosystemIndex)) {
        if (ids.length > 0) {
            await mergeAndStoreIndex(env.CVE_INDEX, `idx:eco:${ecosystem}`, ids);
        }
    }
}

/**
 * Merge new IDs with existing index and store
 */
async function mergeAndStoreIndex(kv: KVNamespace, key: string, newIds: string[]): Promise<void> {
    // Get existing index
    const existing = await kv.get(key);
    let allIds: string[] = existing ? (JSON.parse(existing) as string[]) : [];

    // Merge and dedupe
    const idSet = new Set(allIds);
    for (const id of newIds) {
        idSet.add(id);
    }

    // Convert back to array and limit size
    allIds = Array.from(idSet);
    if (allIds.length > MAX_INDEX_SIZE) {
        // Keep most recent (assuming newer IDs are added at end)
        allIds = allIds.slice(-MAX_INDEX_SIZE);
    }

    // Store
    await kv.put(key, JSON.stringify(allIds), {
        expirationTtl: 86400 * 7, // 7 days TTL
    });
}

/**
 * Update API statistics
 */
async function updateStats(
    env: Env,
    newRecords: CveRecord[],
    epssData: EpssDataMap,
    kevSet: KevDataSet
): Promise<void> {
    // Get existing stats
    const existingStats = await env.METADATA.get('meta:stats');
    let stats: ApiStats;

    if (existingStats) {
        stats = JSON.parse(existingStats) as ApiStats;
    } else {
        stats = {
            totalCves: 0,
            bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
            byEcosystem: {},
            kevCount: 0,
            lastSyncTime: '',
            sources: {
                osv: { lastSync: '', count: 0 },
                epss: { lastSync: '', date: '' },
                kev: { lastSync: '', count: 0 },
            },
        };
    }

    // Update counts from new records
    for (const record of newRecords) {
        stats.totalCves++;
        stats.bySeverity[record.severity]++;

        for (const pkg of record.affected) {
            const eco = pkg.ecosystem;
            stats.byEcosystem[eco] = (stats.byEcosystem[eco] ?? 0) + 1;
        }
    }

    // Update KEV count
    stats.kevCount = kevSet.size;

    // Update timestamps
    const now = new Date().toISOString();
    stats.lastSyncTime = now;
    stats.sources.osv = { lastSync: now, count: newRecords.length };
    stats.sources.epss = {
        lastSync: now,
        date: now.split('T')[0] ?? '',
    };
    stats.sources.kev = { lastSync: now, count: kevSet.size };

    // Store updated stats
    await env.METADATA.put('meta:stats', JSON.stringify(stats));
}

/**
 * Manual sync trigger (for testing)
 */
export async function triggerManualSync(env: Env): Promise<{ success: boolean; message: string }> {
    try {
        await runDailySync(env);
        return { success: true, message: 'Sync completed successfully' };
    } catch (error) {
        return {
            success: false,
            message: error instanceof Error ? error.message : 'Unknown error',
        };
    }
}
