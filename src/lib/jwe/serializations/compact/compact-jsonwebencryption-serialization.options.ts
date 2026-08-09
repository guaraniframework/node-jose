import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Compact JSON Web Encryption serialization options.
 */
export interface CompactJsonWebEncryptionSerializationOptions {
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
