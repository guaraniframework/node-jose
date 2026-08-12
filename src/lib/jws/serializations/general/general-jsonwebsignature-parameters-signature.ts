import { Buffer } from 'buffer';

import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * General JSON Web Signature Parameters Signature.
 */
export interface GeneralJsonWebSignatureParametersSignature {
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

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: Buffer;
}
