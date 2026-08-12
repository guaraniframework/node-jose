import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * General JSON Web Signature Headers.
 */
export interface GeneralJsonWebSignatureHeaders {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebSignatureHeaderParameters>;
}
