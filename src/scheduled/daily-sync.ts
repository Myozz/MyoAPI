/**
 * =============================================================================
 * MyoAPI - Daily Sync Handler (DEPRECATED)
 * =============================================================================
 *
 * NOTE: CVE sync is now handled by GitHub Actions running scripts/sync-fast.mjs
 * This module is kept for API compatibility but does nothing meaningful.
 * Data is stored in Supabase, not Cloudflare KV.
 */

import type { Env } from '../types/env';

/**
 * Placeholder - actual sync runs via GitHub Actions
 */
export async function runDailySync(_env: Env): Promise<void> {
    console.log('[Sync] Daily sync is now handled by GitHub Actions');
    console.log('[Sync] Data is stored in Supabase PostgreSQL');
    console.log('[Sync] Run: node scripts/sync-fast.mjs');
}

/**
 * Manual sync trigger - returns info message
 */
export async function triggerManualSync(_env: Env): Promise<{ success: boolean; message: string }> {
    return {
        success: true,
        message: 'Sync is now handled by GitHub Actions. Run: node scripts/sync-fast.mjs',
    };
}
