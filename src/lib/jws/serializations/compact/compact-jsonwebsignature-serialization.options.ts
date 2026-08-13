import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Compact JSON Web Signature serialization options.
 */
export interface CompactJsonWebSignatureSerializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Detached Payload.
   *
   * @default false
   */
  readonly detached?: boolean;
}
