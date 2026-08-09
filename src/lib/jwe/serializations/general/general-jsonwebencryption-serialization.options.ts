import { Buffer } from 'buffer';

import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * General JSON Web Encryption serialization options.
 */
export interface GeneralJsonWebEncryptionSerializationOptions {
  /**
   * JSON Web Encryption Additional Authenticated Data.
   */
  readonly aad?: Buffer;

  /**
   * JSON Web Keys.
   */
  readonly jwks?: JsonWebKey[];

  /**
   * Detached Ciphertext.
   *
   * @default false
   */
  readonly detached?: boolean;
}
