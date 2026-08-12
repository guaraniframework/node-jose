import { Buffer } from 'buffer';

import { GeneralJsonWebSignatureParsedHeaders } from './general-jsonwebsignature-parsed-headers';

/**
 * General JSON Web Signature.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1|RFC 7515 General JWS JSON Serialization Syntax}
 */
export interface GeneralJsonWebSignature {
  /**
   * JSON Web Signature Payload.
   */
  readonly payload: Buffer;

  /**
   * JSON Web Signature Headers.
   */
  readonly headers: GeneralJsonWebSignatureParsedHeaders[];
}
