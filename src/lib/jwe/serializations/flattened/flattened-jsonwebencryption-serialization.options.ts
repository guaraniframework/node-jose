import { Buffer } from 'buffer';

import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Flattened JSON Web Encryption serialization options.
 */
export interface FlattenedJsonWebEncryptionSerializationOptions {
  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly additionalAuthenticatedData?: Buffer;

  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;

  /**
   * Detached Ciphertext.
   *
   * @default false
   */
  readonly detached?: boolean;
}
