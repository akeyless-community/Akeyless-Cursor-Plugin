/**
 * Read/write Default Gateway URL from ~/.akeyless/profiles/<profile>.toml (CLI stores it there).
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export function normalizeGatewayBase(url: string): string {
    return url.trim().replace(/\/+$/, '');
}

export function readProfileGatewayUrl(profile: string): string | undefined {
    const p = path.join(os.homedir(), '.akeyless', 'profiles', `${profile}.toml`);
    if (!fs.existsSync(p)) {
        return undefined;
    }
    const toml = fs.readFileSync(p, 'utf8');
    const m = toml.match(/gateway_url\s*=\s*['"]([^'"]*)['"]/);
    const raw = m?.[1]?.trim();
    if (!raw) {
        return undefined;
    }
    return normalizeGatewayBase(raw);
}
