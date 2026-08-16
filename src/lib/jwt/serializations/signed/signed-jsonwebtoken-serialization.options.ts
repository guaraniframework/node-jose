import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Signed JSON Web Token serialization options.
 */
export interface SignedJsonWebTokenSerializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;
}
