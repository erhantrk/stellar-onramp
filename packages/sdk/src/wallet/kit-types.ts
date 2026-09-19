/**
 * Types extracted STRUCTURALLY from passkey-kit's public surface.
 *
 * Why not `import type { WebAuthnClient } from 'passkey-kit'`: 0.16.5's export map exposes only
 * `.`, `./storage` and `./server`, and its index barrel re-exports the error/result types but NOT
 * `WebAuthnClient` (it lives in dist/kit/webauthn-ops.d.ts, unreachable under NodeNext without a
 * deep-relative import). The kit's own CONSTRUCTOR parameter carries the type, so extracting it
 * keeps us on the public surface while staying exactly in sync with whatever the installed
 * version declares — if upstream renames or reshapes it, this file fails to compile rather than
 * drifting.
 */

import type { PasskeyKit } from 'passkey-kit';

type PasskeyKitCtorConfig = ConstructorParameters<typeof PasskeyKit>[0];

/** The WebAuthn seam (`PasskeyKitConfig.WebAuthn`) — two methods, injectable for tests. */
export type KitWebAuthnClient = NonNullable<PasskeyKitCtorConfig['WebAuthn']>;

/** The full kit config, for constructing one with exact-optional-property discipline. */
export type PasskeyKitOptions = PasskeyKitCtorConfig;
