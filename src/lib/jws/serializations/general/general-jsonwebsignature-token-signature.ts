import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * General JSON Web Signature Token Signature Parameters.
 */
export interface GeneralJsonWebSignatureTokenSignature {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protected?: string;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly header?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: string;
}
