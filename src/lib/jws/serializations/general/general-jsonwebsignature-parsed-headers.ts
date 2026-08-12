import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * General JSON Web Signature Parsed Headers.
 */
export interface GeneralJsonWebSignatureParsedHeaders {
  /**
   * JSON Web Signature Protected Header.
   */
  readonly protectedHeader?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Unprotected Header.
   */
  readonly unprotectedHeader?: Partial<JsonWebSignatureHeaderParameters>;

  /**
   * JSON Web Signature Header.
   */
  readonly header: JsonWebSignatureHeader;
}
