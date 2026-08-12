import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * Flattened JSON Web Signature Headers.
 */
export interface FlattenedJsonWebSignatureHeaders {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebSignatureHeaderParameters>;
}
