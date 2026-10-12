import { CAPABILITIES } from '@ankhorage/auth/capabilities';
import { expect, it } from 'bun:test';

import { createSupabaseAuthAdapter } from './createSupabaseAuthAdapter.js';

const OPERATION_NAMES = {
  'auth.signIn': 'signIn',
  'auth.signUp': 'signUp',
  'auth.signOut': 'signOut',
  'auth.getSession': 'getSession',
  'auth.refreshSession': 'refreshSession',
  'auth.requestPasswordReset': 'requestPasswordReset',
  'auth.verifyOtp': 'verifyOtp',
  'auth.oauth.startAuthorization': 'startAuthorization',
  'auth.oauth.completeAuthorization': 'completeAuthorization',
} as const;

/*** Prove that every canonical auth operation is implemented by the Supabase adapter. */
it('implements every canonical auth capability without provider-owned capability IDs', () => {
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
  });
  const capabilityIds = CAPABILITIES.map((capability) => capability.id);

  expect(capabilityIds).toEqual(Object.keys(OPERATION_NAMES));
  expect(capabilityIds.some((capabilityId) => capabilityId.startsWith('supabase.'))).toBe(false);
  for (const capabilityId of capabilityIds) {
    expect(CAPABILITIES.find((capability) => capability.id === capabilityId)?.owner).toBe(
      '@ankhorage/auth',
    );
  }
  expect(Object.keys(adapter).sort()).toEqual(Object.values(OPERATION_NAMES).sort());
});

/*** Prove that an unconfigured OAuth provider is rejected by configuration-driven operations. */
it('does not imply OAuth provider support when no provider is configured', async () => {
  const adapter = createSupabaseAuthAdapter({
    url: 'https://example.supabase.co',
    anonKey: 'anon',
  });

  const result = await adapter.startAuthorization({
    provider: 'google',
    redirectUri: 'ankh-app://auth/callback',
  });

  expect(result).toMatchObject({ ok: false, error: { code: 'provider_misconfigured' } });
});
