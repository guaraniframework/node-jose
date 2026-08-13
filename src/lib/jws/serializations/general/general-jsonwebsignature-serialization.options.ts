import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * General JSON Web Signature serialization options.
 */
export interface GeneralJsonWebSignatureSerializationOptions {
  /**
   * JSON Web Keys.
   */
  readonly jsonWebKeys?: (JsonWebKey | null)[];

  /**
   * Detached Payload.
   *
   * @default false
   */
  readonly detached?: boolean;
}
