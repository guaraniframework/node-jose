import { Buffer } from 'buffer';

import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Flattened JSON Web Encryption serialization options.
 */
export interface FlattenedJsonWebEncryptionSerializationOptions {
  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly aad?: Buffer;

  /**
   * JSON Web Key.
   */
  readonly jwk?: JsonWebKey;

  /**
   * Detached Ciphertext.
   *
   * @default false
   */
  readonly detached?: boolean;
}
