import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Flattened JSON Web Signature serialization options.
 */
export interface FlattenedJsonWebSignatureSerializationOptions {
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
