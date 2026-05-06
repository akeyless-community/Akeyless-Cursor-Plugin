/**
 * Customer-fragment / DFC static secrets are decrypted via the tenant Gateway.
 * The CLI uses the Default Gateway URL stored on the profile (`akeyless configure --gateway-url`).
 */

/**
 * `describe-item` sometimes returns a Console/API proxy URL (e.g. API Gateway), not the Gateway cluster
 * HTTPS endpoint. Passing those to `akeyless configure --gateway-url` can hang or break derived-key.
 */
export function shouldSkipCliGatewayAutoConfigure(url: string): { skip: boolean; reason?: string } {
    const u = url.trim().toLowerCase();
    if (u.includes('execute-api.') && u.includes('.amazonaws.com')) {
        return {
            skip: true,
            reason:
                'URL is an AWS API Gateway host (Console/API proxy), not your Akeyless Gateway cluster URL. In Console → Gateways, copy the cluster HTTPS URL (often *.akeyless.io or your GW custom domain) and run: akeyless configure --profile <profile> --gateway-url "<url>"',
        };
    }
    return { skip: false };
}

/** Prefer a real Gateway cluster host over API Gateway proxy URLs when multiple `cluster_url` values exist */
export function pickPreferredGatewayClusterUrl(candidates: string[]): string | undefined {
    const norm = [...new Set(candidates.map((u) => u.trim().replace(/\/+$/, '')))].filter(Boolean);
    for (const u of norm) {
        if (!shouldSkipCliGatewayAutoConfigure(u).skip) {
            return u;
        }
    }
    return norm[0];
}

function collectUrlsFromGatewayDetails(details: unknown): string[] {
    const out: string[] = [];
    if (!details || typeof details !== 'object') {
        return out;
    }
    const o = details as Record<string, unknown>;
    const push = (s: unknown) => {
        if (typeof s === 'string' && /^https?:\/\//i.test(s.trim())) {
            out.push(s.trim().replace(/\/+$/, ''));
        }
    };
    push(o.cluster_url);
    push(o.gateway_url);
    push(o.gatewayUrl);
    const gw = o.gateways;
    if (Array.isArray(gw)) {
        for (const g of gw) {
            if (g && typeof g === 'object') {
                push((g as Record<string, unknown>).cluster_url);
            }
        }
    }
    return out;
}

/** Best-effort cluster URL from list-items `gateway_details` — prefers non–API-Gateway hosts when multiple */
export function extractGatewayClusterUrl(details: unknown): string | undefined {
    return pickPreferredGatewayClusterUrl(collectUrlsFromGatewayDetails(details));
}

/** Collect every `cluster_url` field in describe-item JSON (tree walk) */
export function collectClusterUrlsFromDescribeItem(data: unknown): string[] {
    const seen = new Set<unknown>();
    const out: string[] = [];

    function walk(x: unknown): void {
        if (!x || typeof x !== 'object' || seen.has(x)) {
            return;
        }
        seen.add(x);
        if (Array.isArray(x)) {
            x.forEach(walk);
            return;
        }
        const o = x as Record<string, unknown>;
        for (const k of Object.keys(o)) {
            const v = o[k];
            if (k === 'cluster_url' && typeof v === 'string' && /^https?:\/\//i.test(v.trim())) {
                out.push(v.trim().replace(/\/+$/, ''));
            } else {
                walk(v);
            }
        }
    }

    walk(data);
    return out;
}

/** Parse describe-item output — when several cluster URLs exist, prefer the Gateway cluster over API Gateway proxy */
export function extractClusterUrlFromDescribeItem(data: unknown): string | undefined {
    return pickPreferredGatewayClusterUrl(collectClusterUrlsFromDescribeItem(data));
}

export function customerFragmentCliHint(profile: string, _gatewayDetails?: unknown): string {
    const prof = profile.trim() || 'default';
    return (
        ` Custom protection key: set VS Code setting **akeyless.gatewayUrl** to your Gateway **cluster** HTTPS URL (Akeyless Console → Gateways), ` +
        `or run: akeyless configure --profile ${prof} --gateway-url https://<your-gateway-cluster>/ — not the API Gateway /execute-api/ URL from describe-item.`
    );
}

/** GW cluster row from `akeyless list-gateways --json` (see Akeyless API GwClusterIdentity). */
type GwClusterRow = {
    cluster_url?: string;
    customer_fragment_ids?: string[];
    customer_fragments?: Array<{ id?: string }>;
};

function parseClustersFromListGateways(data: unknown): GwClusterRow[] {
    if (!data || typeof data !== 'object') {
        return [];
    }
    const o = data as Record<string, unknown>;
    const clusters = o.clusters;
    if (!Array.isArray(clusters)) {
        return [];
    }
    return clusters.filter((c) => c && typeof c === 'object') as GwClusterRow[];
}

/**
 * Best-effort fragment id strings from list-items metadata (and optional describe JSON) for matching
 * `list-gateways` clusters via `customer_fragments` / `customer_fragment_ids`.
 */
export function collectCustomerFragmentIdHints(item: unknown, describeItem?: unknown): string[] {
    const hints = new Set<string>();
    const push = (s: unknown) => {
        if (typeof s === 'string' && s.trim()) {
            hints.add(s.trim());
        }
    };

    function walk(x: unknown, depth: number): void {
        if (depth > 20 || !x || typeof x !== 'object') {
            return;
        }
        if (Array.isArray(x)) {
            for (const el of x) {
                walk(el, depth + 1);
            }
            return;
        }
        const o = x as Record<string, unknown>;
        for (const [k, v] of Object.entries(o)) {
            const kl = k.toLowerCase();
            if (kl.includes('customer_fragment') || kl.includes('fragment_id') || /^cf_/.test(kl)) {
                if (typeof v === 'string') {
                    push(v);
                } else if (Array.isArray(v)) {
                    v.forEach(push);
                }
            }
            if (typeof v === 'object' && v !== null) {
                walk(v, depth + 1);
            }
        }
    }

    walk(item, 0);
    walk(describeItem, 0);
    return [...hints];
}

function clusterReferencesFragment(cluster: GwClusterRow, fragmentId: string): boolean {
    const id = fragmentId.trim();
    if (!id) {
        return false;
    }
    const ids = cluster.customer_fragment_ids;
    if (Array.isArray(ids) && ids.some((x) => x === id)) {
        return true;
    }
    const cfs = cluster.customer_fragments;
    if (Array.isArray(cfs)) {
        return cfs.some((cf) => cf && typeof cf === 'object' && (cf as { id?: string }).id === id);
    }
    return false;
}

/**
 * Pick a Gateway cluster HTTPS URL from `akeyless list-gateways --json` output.
 * Prefers clusters whose customer fragments match hints; if hints are empty or none match,
 * uses the single non–API-Gateway `cluster_url`, or {@link pickPreferredGatewayClusterUrl}.
 */
export function pickClusterUrlFromListGateways(
    listGatewaysJson: unknown,
    fragmentIdHints: string[]
): string | undefined {
    const rows = parseClustersFromListGateways(listGatewaysJson);
    if (!rows.length) {
        return undefined;
    }

    const withUrls = rows
        .map((r) => {
            const u = typeof r.cluster_url === 'string' ? r.cluster_url.trim().replace(/\/+$/, '') : '';
            return { row: r, url: u };
        })
        .filter((x) => x.url && /^https?:\/\//i.test(x.url));

    const nonProxy = withUrls.filter((x) => !shouldSkipCliGatewayAutoConfigure(x.url).skip);
    const pool = nonProxy.length ? nonProxy : withUrls;

    if (fragmentIdHints.length) {
        for (const hint of fragmentIdHints) {
            for (const { row, url } of pool) {
                if (clusterReferencesFragment(row, hint)) {
                    return url;
                }
            }
        }
    }

    if (pool.length === 1) {
        return pool[0].url;
    }

    return pickPreferredGatewayClusterUrl(pool.map((p) => p.url));
}
