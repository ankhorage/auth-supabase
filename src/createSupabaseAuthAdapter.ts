import type { AuthPort } from '@ankhorage/auth';
import type { AuthSession } from '@ankhorage/contracts/auth';

import {
  type RequiredSupabaseAuthConfig,
  validateSupabaseAuthConfig,
} from './authConfiguration.js';
import {
  createPasswordResetOperation,
  createSignInOperation,
  createSignUpOperation,
  createVerifyOtpOperation,
} from './authPasswordOperations.js';
import { type AuthOperationContext, createAuthOperationContext } from './authSessionContext.js';
import {
  createGetSessionOperation,
  createRefreshSessionOperation,
  createSignOutOperation,
} from './authSessionOperations.js';
import { createSupabaseOAuthAdapter } from './oauth.js';
import { oauthCompletionError, oauthStartError } from './oauthErrors.js';
import { createSupabaseOAuthProfileVerifier } from './profileVerification.js';
import type { SupabaseAuthConfig, SupabaseOAuthProfileVerifier } from './types.js';

/*** Create a Supabase implementation of the provider-neutral authentication port. */
export function createSupabaseAuthAdapter(config: SupabaseAuthConfig): AuthPort {
  const normalizedConfig = validateSupabaseAuthConfig(config);
  const context = createAuthOperationContext(normalizedConfig);
  const oauth = createOAuthOperations(context);
  return {
    signIn: createSignInOperation(context),
    signUp: createSignUpOperation(context),
    signOut: createSignOutOperation(context),
    getSession: createGetSessionOperation(context),
    refreshSession: createRefreshSessionOperation(context),
    requestPasswordReset: createPasswordResetOperation(context),
    verifyOtp: createVerifyOtpOperation(context),
    startAuthorization: oauth.startAuthorization,
    completeAuthorization: oauth.completeAuthorization,
  };
}

/*** Create OAuth port operations from the configured Supabase provider set. */
function createOAuthOperations(context: AuthOperationContext) {
  const { config } = context;
  if (config.oauthProviders.length === 0) return createDisabledOAuthOperations();
  const profileVerifier = createProfileVerifier(config);
  return createSupabaseOAuthAdapter({
    url: config.url,
    anonKey: config.anonKey,
    fetch: config.fetch,
    storage: requireOAuthStorage(config),
    storageKey: config.storageKey,
    providers: config.oauthProviders,
    randomBytes: config.oauthRandomBytes,
    persistSession: createOAuthSessionPersistence(context),
    ...(profileVerifier === undefined ? {} : { verifyProfile: profileVerifier }),
    ...(config.onOAuthLifecycleEvent === undefined
      ? {}
      : { onLifecycleEvent: config.onOAuthLifecycleEvent }),
  });
}

/*** Return explicit unsupported OAuth results when no OAuth provider was configured. */
function createDisabledOAuthOperations(): Pick<
  AuthPort,
  'startAuthorization' | 'completeAuthorization'
> {
  return {
    startAuthorization: (input) =>
      Promise.resolve(
        oauthStartError(
          'provider_misconfigured',
          'No OAuth providers are configured for this Supabase Auth adapter.',
          input.provider,
          false,
        ),
      ),
    completeAuthorization: () =>
      Promise.resolve(
        oauthCompletionError(
          'authorization_attempt_not_found',
          'callback',
          'No OAuth authorization attempt can exist without a configured OAuth provider.',
          undefined,
          false,
        ),
      ),
  };
}

function createOAuthSessionPersistence(context: AuthOperationContext) {
  return async (session: AuthSession): Promise<void> => {
    const error = await context.persistSessionSafely(session);
    if (error !== null) throw new Error(error.message);
  };
}

function createProfileVerifier(
  config: RequiredSupabaseAuthConfig,
): SupabaseOAuthProfileVerifier | undefined {
  if (config.profileVerification === undefined) return undefined;
  return createSupabaseOAuthProfileVerifier({
    url: config.url,
    anonKey: config.anonKey,
    fetch: config.fetch,
    config: config.profileVerification,
  });
}

function requireOAuthStorage(config: RequiredSupabaseAuthConfig) {
  if (config.storage === undefined) {
    throw new TypeError('Supabase OAuth PKCE requires persistent auth storage.');
  }
  return config.storage;
}
