/**
 * Centralizes Akeyless CLI command variants for backward compatibility across CLI versions
 * and improves errors when the binary cannot parse API responses (upgrade hint).
 */

import { logger } from './logger';

/** First CLI release known to handle current list-items payloads without unmarshaling errors for typical tenants. */
export const MIN_CLI_VERSION_LIST_ITEMS: [number, number, number] = [1, 141, 0];

let listItemsVersionWarningShown = false;

export function escapeShellDoubleQuotedArg(s: string): string {
    return s
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\$/g, '\\$')
        .replace(/`/g, '\\`');
}

export function parseVersionOutput(output: string): [number, number, number] | null {
    const m = output.match(/Version:\s*(\d+)\.(\d+)\.(\d+)/i);
    if (!m) {
        return null;
    }
    return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

export function compareVersions(a: [number, number, number], b: [number, number, number]): number {
    for (let i = 0; i < 3; i++) {
        if (a[i] !== b[i]) {
            return a[i] - b[i];
        }
    }
    return 0;
}

/**
 * Warn once per session if CLI is older than recommended for list-items.
 */
export async function warnIfCliBelowListItemsMinimum(
    execVersion: () => Promise<string>
): Promise<void> {
    if (listItemsVersionWarningShown) {
        return;
    }
    try {
        const out = await execVersion();
        const v = parseVersionOutput(out);
        if (!v || compareVersions(v, MIN_CLI_VERSION_LIST_ITEMS) >= 0) {
            return;
        }
        listItemsVersionWarningShown = true;
        logger.warn(
            `Akeyless CLI ${v.join('.')} is below ${MIN_CLI_VERSION_LIST_ITEMS.join('.')}. ` +
                'list-items may fail with parse errors; run `akeyless update` or upgrade the CLI.'
        );
    } catch {
        // ignore
    }
}

export function normalizeListItemsNextPage(data: Record<string, unknown>): string | null {
    const n = data.next_page ?? data.next_page_token;
    if (typeof n === 'string' && n.length > 0) {
        return n;
    }
    return null;
}

export function isListItemsStaleCliError(message: string): boolean {
    const m = message.toLowerCase();
    return (
        m.includes('cannot unmarshal array') ||
        m.includes('item_targets_assoc') ||
        m.includes('itemtargetassociation')
    );
}

export function augmentListItemsFailureMessage(message: string): string {
    if (!isListItemsStaleCliError(message)) {
        return message;
    }
    return (
        `${message}\n\n` +
        'This usually means the Akeyless CLI is older than the API response format. ' +
        'Update the CLI: run `akeyless update` or `brew upgrade akeylesslabs/tap/akeyless`, ' +
        `then retry (recommended: CLI ${MIN_CLI_VERSION_LIST_ITEMS.join('.')}+).`
    );
}

export type ExecOut = { stdout: string; stderr: string };

export async function execFirstSuccessful(
    execAsync: (command: string) => Promise<ExecOut>,
    commands: string[],
    operationLabel: string
): Promise<ExecOut> {
    let lastErr: Error | undefined;
    for (const cmd of commands) {
        try {
            return await execAsync(cmd);
        } catch (e) {
            lastErr = e instanceof Error ? e : new Error(String(e));
            logger.info(`${operationLabel}: CLI variant failed, trying next if any (${lastErr.message.slice(0, 120)})`);
        }
    }
    throw lastErr ?? new Error(`${operationLabel}: all CLI variants failed`);
}

export function buildGetSecretValueCommands(akeylessPath: string, itemPath: string): string[] {
    const e = escapeShellDoubleQuotedArg(itemPath);
    // Current Akeyless CLI uses --name/-n only; --path is not supported for get-secret-value
    return [`${akeylessPath} get-secret-value --name "${e}" --json`];
}

export function buildCreateSecretCommands(akeylessPath: string, itemPath: string, value: string): string[] {
    const pe = escapeShellDoubleQuotedArg(itemPath);
    const ve = escapeShellDoubleQuotedArg(value);
    // Matches `akeyless create-secret --help`: -n/--name, -v/--value, --type (default generic), --json
    return [
        `${akeylessPath} create-secret --name "${pe}" --value "${ve}" --type generic --json`,
        `${akeylessPath} create-secret --name "${pe}" --value "${ve}" --json`,
    ];
}

export function buildUpdateSecretCommands(akeylessPath: string, itemPath: string, value: string): string[] {
    const pe = escapeShellDoubleQuotedArg(itemPath);
    const ve = escapeShellDoubleQuotedArg(value);
    // CLI defines `update-secret-val`, not `update-secret-value` (see `akeyless update-secret-val --help`)
    return [`${akeylessPath} update-secret-val --name "${pe}" --value "${ve}" --json`];
}

export function buildDeleteItemCommands(akeylessPath: string, itemPath: string): string[] {
    const e = escapeShellDoubleQuotedArg(itemPath);
    // `akeyless delete-item --help`: item is `-n, --name` only (no `--path` in current CLI)
    return [`${akeylessPath} delete-item --name "${e}" --json`];
}
