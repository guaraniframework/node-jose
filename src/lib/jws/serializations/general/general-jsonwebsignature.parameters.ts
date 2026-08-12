import { Buffer } from 'buffer';

import { GeneralJsonWebSignatureParametersSignature } from './general-jsonwebsignature-parameters-signature';

/**
 * General JSON Web Signature Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1|RFC 7515 General JWS JSON Serialization Syntax}
 */
export interface GeneralJsonWebSignatureParameters {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload?: Buffer;

  /**
   * JSON Web Signature Signatures.
   */
  readonly signatures: GeneralJsonWebSignatureParametersSignature[];
}
