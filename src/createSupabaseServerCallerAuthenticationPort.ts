import type {
  ServerCallerAuthenticationPort,
  ServerCallerAuthenticationResult,
} from '@ankhorage/auth';

import type { SupabaseAuthFetch, SupabaseServerCallerAuthenticationConfig } from './types.js';

/*** Create a server-only Supabase adapter that asks the provider to verify each opaque credential. */
export function createSupabaseServerCallerAuthenticationPort(
  config: SupabaseServerCallerAuthenticationConfig,
): ServerCallerAuthenticationPort {
  const url = normalizeUrl(config.url);
  const anonKey = requireAnonKey(config.anonKey);
  const fetch = config.fetch ?? globalThis.fetch;

  return {
    authenticateCaller: (input) => authenticateCaller(fetch, url, anonKey, input.credential),
  };
}

/*** Verify a credential through Supabase Auth and return only a normalized provider-verified caller. */
async function authenticateCaller(
  fetch: SupabaseAuthFetch,
  url: string,
  anonKey: string,
  credential: string | undefined,
): Promise<ServerCallerAuthenticationResult> {
  if (credential === undefined || credential.trim().length === 0)
    return { status: 'missing_credential' };

  try {
    const response = await fetch(`${url}/auth/v1/user`, {
      headers: { apikey: anonKey, Authorization: `Bearer ${credential}` },
    });
    const body: unknown = await response.json().catch(() => undefined);
    if (!response.ok) return authenticationFailure(response.status, body);
    const caller = normalizeCaller(body);
    return caller === undefined
      ? { status: 'unverifiable_credential' }
      : { status: 'authenticated', caller };
  } catch {
    return { status: 'unverifiable_credential' };
  }
}

/*** Translate provider rejection into a stable failure without returning provider details or the credential. */
function authenticationFailure(status: number, body: unknown): ServerCallerAuthenticationResult {
  if (containsExpiredMarker(body)) return { status: 'expired_credential' };
  return status >= 400 && status < 500
    ? { status: 'invalid_credential' }
    : { status: 'unverifiable_credential' };
}

/*** Normalize only portable primitive identity claims from a provider-verified Supabase user document. */
function normalizeCaller(body: unknown) {
  if (body === null || typeof body !== 'object') return undefined;
  const fields = body as {
    readonly email?: unknown;
    readonly id?: unknown;
    readonly role?: unknown;
  };
  const { id } = fields;
  if (typeof id !== 'string' || id.length === 0) return undefined;
  const claims = {
    ...(typeof fields.email === 'string' ? { email: fields.email } : {}),
    ...(typeof fields.role === 'string' ? { role: fields.role } : {}),
  };
  return Object.keys(claims).length === 0 ? { id } : { id, claims };
}

/*** Detect Supabase's expiry indication without exposing its error payload to the caller. */
function containsExpiredMarker(body: unknown): boolean {
  return JSON.stringify(body).toLowerCase().includes('expired');
}

/*** Normalize a configured Supabase base URL once at adapter construction. */
function normalizeUrl(value: string): string {
  const url = value.trim().replace(/\/+$/u, '');
  if (url.length === 0) throw new TypeError('Supabase Auth URL is required.');
  new URL(url);
  return url;
}

/*** Require the configured public Supabase API key without accepting blank credentials. */
function requireAnonKey(value: string): string {
  const anonKey = value.trim();
  if (anonKey.length === 0) throw new TypeError('Supabase anon key is required.');
  return anonKey;
}
