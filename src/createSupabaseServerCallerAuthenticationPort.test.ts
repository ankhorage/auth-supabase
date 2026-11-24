import { expect, test } from 'bun:test';

import { createSupabaseServerCallerAuthenticationPort } from './createSupabaseServerCallerAuthenticationPort.js';

const createVerifier = (response: Response) =>
  createSupabaseServerCallerAuthenticationPort({
    url: 'https://example.supabase.co',
    anonKey: 'anon-key',
    fetch: () => Promise.resolve(response),
  });

test('returns a normalized caller only after Supabase verifies the supplied credential', async () => {
  const verifier = createVerifier(
    Response.json({ id: 'user-1', email: 'user@example.com', role: 'authenticated' }),
  );

  expect(await verifier.authenticateCaller({ credential: 'raw-access-token' })).toEqual({
    status: 'authenticated',
    caller: { id: 'user-1', claims: { email: 'user@example.com', role: 'authenticated' } },
  });
});

test('fails closed for missing, invalid, expired, and unverifiable credentials without leakage', async () => {
  const missing = createVerifier(Response.json({}));
  const invalid = createVerifier(Response.json({ message: 'JWT malformed' }, { status: 401 }));
  const expired = createVerifier(Response.json({ message: 'JWT expired' }, { status: 401 }));
  const unavailable = createVerifier(new Response(null, { status: 503 }));

  expect(await missing.authenticateCaller({})).toEqual({ status: 'missing_credential' });
  expect(await invalid.authenticateCaller({ credential: 'forged' })).toEqual({
    status: 'invalid_credential',
  });
  expect(await expired.authenticateCaller({ credential: 'expired-token' })).toEqual({
    status: 'expired_credential',
  });
  const result = await unavailable.authenticateCaller({ credential: 'secret-token' });
  expect(result).toEqual({ status: 'unverifiable_credential' });
  expect(JSON.stringify(result)).not.toContain('secret-token');
});
