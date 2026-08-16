import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Encrypted JSON Web Token serialization options.
 */
export interface EncryptedJsonWebTokenSerializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey;
}
