import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Flattened JSON Web Signature serialization options.
 */
export interface FlattenedJsonWebSignatureSerializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jwk?: JsonWebKey | null;

  /**
   * Detached Payload.
   *
   * @default false
   */
  readonly detached?: boolean;
}
