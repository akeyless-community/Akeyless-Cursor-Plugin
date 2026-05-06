/**
 * REST client for Akeyless vault + gateway — mirrors the browser extension's customSecretService.
 *
 * For custom-protection-key (customer fragment) static secrets the flow is:
 *   1. GET  vault/secret-access-creds   → encrypted blob + derivation creds (customer_fragment_id, credential, restricted_dd)
 *   2. GET  vault/get-gw-basic-info?customer_fragment_id=…  → gateways[0].cluster_url
 *   3. POST gateway/api/derived-key     → derived_key (base64)
 *   4. Client-side AES-GCM decryption of the encrypted blob using the derived key
 *
 * For default-key secrets the same flow works (step 2 is KFM-based instead of gateway-based).
 */

import { logger } from '../utils/logger';
import { promisify } from 'util';
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const execFileAsync = promisify(execFile);

const FETCH_TIMEOUT_MS = 35_000;
const DEFAULT_VAULT_ENDPOINT = 'https://vault.akeyless.io';

/**
 * Derive the vault endpoint from an API endpoint.
 * api.akeyless.io → vault.akeyless.io, api.eu.akeyless.io → vault.eu.akeyless.io, etc.
 */
function apiToVaultEndpoint(apiEndpoint: string): string {
    try {
        const u = new URL(apiEndpoint);
        if (u.hostname.startsWith('api.')) {
            u.hostname = 'vault.' + u.hostname.slice(4);
        }
        return u.origin;
    } catch {
        return DEFAULT_VAULT_ENDPOINT;
    }
}

function timeoutSignal(ms: number): AbortSignal {
    const c = new AbortController();
    setTimeout(() => c.abort(), ms);
    return c.signal;
}

// ---------------------------------------------------------------------------
// Token / credential helpers
// ---------------------------------------------------------------------------

interface CachedCreds {
    /** Short CLI token (used for gateway Bearer auth) */
    token: string;
    /** UAM JWT used for vault UAM headers (akeylessuam-accesscreds) */
    uamCreds: string;
    /** Auth creds JWT — fallback for vault if uamCreds is empty */
    authCreds: string;
}

/**
 * Read cached credentials from `~/.akeyless/.tmp_creds/<profile>-<access_id>`.
 * The CLI writes this file on every successful `akeyless auth`.
 * Returns undefined when the file is missing, unreadable, or expired.
 */
function readCachedCreds(profile: string): CachedCreds | undefined {
    const profileName = profile.trim() || 'default';
    const profFile = path.join(os.homedir(), '.akeyless', 'profiles', `${profileName}.toml`);
    let accessId = '';
    try {
        const toml = fs.readFileSync(profFile, 'utf8');
        const m = toml.match(/access_id\s*=\s*['"]([^'"]*)['"]/);
        accessId = m?.[1]?.trim() || '';
    } catch {
        return undefined;
    }
    if (!accessId) {
        return undefined;
    }

    const credsFile = path.join(os.homedir(), '.akeyless', '.tmp_creds', `${profileName}-${accessId}`);
    try {
        const raw = fs.readFileSync(credsFile, 'utf8');
        const data = JSON.parse(raw);
        const expiry = typeof data.expiry === 'number' ? data.expiry : 0;
        if (expiry && expiry < Date.now() / 1000) {
            logger.info('REST: cached credentials expired, will re-authenticate');
            return undefined;
        }
        const token = (data.token || '') as string;
        const uamCreds = (data.uam_creds || '') as string;
        const authCreds = (data.auth_creds || '') as string;
        if (!token && !uamCreds && !authCreds) {
            return undefined;
        }
        return { token, uamCreds, authCreds };
    } catch {
        return undefined;
    }
}

/**
 * Get credentials for the REST flow.
 * Reads the CLI's cached token file first (instant, no subprocess).
 * Falls back to `akeyless auth --profile` only when the cache is missing or expired.
 */
async function getCredsForProfile(profile: string): Promise<CachedCreds> {
    const cached = readCachedCreds(profile);
    if (cached) {
        logger.info('REST: using cached CLI credentials (no re-auth needed)');
        return cached;
    }

    const prof = profile.trim() || 'default';
    logger.info(`REST: cached creds unavailable — running akeyless auth --profile "${prof}"`);
    const { stdout } = await execFileAsync('akeyless', ['auth', '--profile', prof, '--json'], {
        timeout: 60_000,
        maxBuffer: 10 * 1024 * 1024,
    });
    const data = JSON.parse(stdout);

    const fresh = readCachedCreds(profile);
    if (fresh) {
        return fresh;
    }

    const token: string = data.token ?? data.t ?? '';
    if (!token) {
        throw new Error('akeyless auth returned no token and no cached creds found');
    }
    return { token, uamCreds: '', authCreds: '' };
}

// ---------------------------------------------------------------------------
// Vault helpers
// ---------------------------------------------------------------------------

interface SecretAccessCredsResponse {
    secret_enc_val?: string;
    enc_target_details?: string;
    dynamic_secret_enc_details?: string;
    protection_key_derivation_creds?: DerivationCreds;
    customer_fragment_id?: string;
    credential?: string;
    restricted_dd?: string;
    item_size?: number;
    item_version?: number;
    KFMsHostsDNSMap?: Record<string, string>;
    [key: string]: unknown;
}

interface DerivationCreds {
    customer_fragment_id: string;
    credential: string;
    restricted_dd: string;
    item_version: number;
    item_size?: number;
    KFMsHostsDNSMap?: Record<string, string>;
    [key: string]: unknown;
}

interface GatewayInfoResponse {
    gateways: Array<{ cluster_url: string; [key: string]: unknown }>;
    [key: string]: unknown;
}

interface DerivedKeyResponse {
    derived_key: string;
    [key: string]: unknown;
}

async function vaultGetSecretAccessCreds(
    vaultEndpoint: string,
    token: string,
    secretName: string,
    itemAccessibility: number,
    itemId?: number
): Promise<SecretAccessCredsResponse> {
    const url = new URL(`${vaultEndpoint}/secret-access-creds`);
    url.searchParams.append('item_name', secretName);
    url.searchParams.append('item_accessibility', itemAccessibility.toString());
    if (itemId !== undefined && itemId !== null) {
        url.searchParams.append('item_id', String(itemId));
    }

    logger.info(`REST: GET ${url.pathname} for "${secretName}"`);
    const resp = await fetch(url.toString(), {
        method: 'GET',
        headers: {
            'akeylessuam-accesscreds': token,
            'akeyless-product': 'apm',
            'akeylessclienttype': 'extension',
            accept: 'application/json',
        },
        signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(
            `secret-access-creds ${resp.status}: ${body.slice(0, 500)}`
        );
    }
    return (await resp.json()) as SecretAccessCredsResponse;
}

async function vaultGetGwBasicInfo(
    vaultEndpoint: string,
    token: string,
    customerFragmentId: string
): Promise<string> {
    const url = new URL(`${vaultEndpoint}/get-gw-basic-info`);
    url.searchParams.append('customer_fragment_id', customerFragmentId);

    logger.info(`REST: GET ${url.pathname}?customer_fragment_id=…`);
    const resp = await fetch(url.toString(), {
        method: 'GET',
        headers: {
            'akeylessuam-accesscreds': token,
            'akeyless-product': 'apm',
            'akeylessclienttype': 'extension',
            accept: 'application/json',
        },
        signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`get-gw-basic-info ${resp.status}: ${body.slice(0, 500)}`);
    }
    const data = (await resp.json()) as GatewayInfoResponse;
    if (!data.gateways?.length || !data.gateways[0].cluster_url) {
        throw new Error('get-gw-basic-info returned no gateway cluster_url');
    }
    const raw = data.gateways[0].cluster_url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(raw)) {
        throw new Error(`Gateway cluster_url is not an HTTP(S) URL: ${raw}`);
    }
    return raw;
}

async function gatewayDeriveKey(
    gatewayUrl: string,
    derivationCreds: DerivationCreds,
    token: string
): Promise<string> {
    const url = `${gatewayUrl}/api/derived-key`;
    logger.info('REST: POST /api/derived-key on gateway');
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            derivation_creds: derivationCreds,
            key_name: '',
        }),
        signal: timeoutSignal(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`derived-key ${resp.status}: ${body.slice(0, 500)}`);
    }
    const data = (await resp.json()) as DerivedKeyResponse;
    if (!data.derived_key) {
        throw new Error('derived-key response missing derived_key');
    }
    return data.derived_key;
}

// ---------------------------------------------------------------------------
// Client-side AES-GCM decryption (same as web extension's cryptoUtils)
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Buffer {
    return Buffer.from(b64, 'base64');
}

function extractEncryptedData(secretEncValBase64: string): {
    iv: Buffer;
    ciphertext: Buffer;
    tag: Buffer;
} {
    const blob = base64ToBytes(secretEncValBase64);
    let offset = 5; // 1 byte version + 4 bytes key-version
    const ddLength = blob[offset];
    offset += 1; // dd length byte
    offset += 1; // constant 1
    offset += ddLength; // derivation data

    const iv = blob.subarray(offset, offset + 12);
    offset += 12;
    const tag = blob.subarray(blob.length - 16);
    const ciphertext = blob.subarray(offset, blob.length - 16);
    return { iv, ciphertext, tag };
}

async function decryptWithDerivedKey(
    secretEncValBase64: string,
    derivedKeyBase64: string
): Promise<string> {
    const crypto = await import('crypto');
    const key = base64ToBytes(derivedKeyBase64);
    const { iv, ciphertext, tag } = extractEncryptedData(secretEncValBase64);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return dec.toString('utf8');
}

// ---------------------------------------------------------------------------
// Public orchestrator
// ---------------------------------------------------------------------------

export interface RestGetSecretOpts {
    secretName: string;
    profile: string;
    itemAccessibility: number;
    itemId?: number;
    apiEndpoint?: string;
}

/**
 * Fetch a custom-protection-key static secret value entirely via REST,
 * matching the browser extension's `customSecretService.getSecretValueWithCustomKey`.
 */
export async function getSecretValueViaRest(opts: RestGetSecretOpts): Promise<string> {
    const vaultEndpoint = opts.apiEndpoint
        ? apiToVaultEndpoint(opts.apiEndpoint.replace(/\/+$/, ''))
        : DEFAULT_VAULT_ENDPOINT;
    logger.info(`REST: using vault endpoint ${vaultEndpoint}`);
    const creds = await getCredsForProfile(opts.profile);

    // Vault UAM calls use uam_creds (or auth_creds fallback); gateway Bearer uses token
    const vaultToken = creds.uamCreds || creds.authCreds || creds.token;
    const gatewayBearerToken = creds.token || creds.uamCreds || creds.authCreds;

    // Step 1 — encrypted blob + derivation creds (vault, not API)
    const accessCreds = await vaultGetSecretAccessCreds(
        vaultEndpoint,
        vaultToken,
        opts.secretName,
        opts.itemAccessibility,
        opts.itemId
    );

    let derivCreds: DerivationCreds;
    if (accessCreds.protection_key_derivation_creds) {
        derivCreds = accessCreds.protection_key_derivation_creds;
    } else {
        derivCreds = {
            customer_fragment_id: accessCreds.customer_fragment_id || '',
            credential: accessCreds.credential || '',
            restricted_dd: accessCreds.restricted_dd || '',
            item_version: accessCreds.item_version || 1,
            item_size: accessCreds.item_size || 32,
            KFMsHostsDNSMap: accessCreds.KFMsHostsDNSMap || {},
        };
    }

    const encValue =
        accessCreds.secret_enc_val ||
        accessCreds.enc_target_details ||
        accessCreds.dynamic_secret_enc_details ||
        '';
    if (!encValue) {
        throw new Error('secret-access-creds returned no encrypted value (secret_enc_val)');
    }

    if (!derivCreds.customer_fragment_id?.trim()) {
        throw new Error(
            'customer_fragment_id is empty — item may use default key (KFM path not implemented in this plugin; CLI should handle it)'
        );
    }

    // Step 2 — gateway cluster URL via vault
    const gatewayUrl = await vaultGetGwBasicInfo(
        vaultEndpoint,
        vaultToken,
        derivCreds.customer_fragment_id
    );
    logger.info(`REST: gateway cluster URL for fragment: ${gatewayUrl}`);

    // Step 3 — derive key via gateway (Bearer token, not UAM)
    const derivedKey = await gatewayDeriveKey(gatewayUrl, derivCreds, gatewayBearerToken);
    logger.info('REST: derived key obtained from gateway');

    // Step 4 — client-side decryption
    const plaintext = await decryptWithDerivedKey(encValue, derivedKey);
    logger.info(`REST: decrypted secret value (${plaintext.length} chars)`);
    return plaintext;
}
