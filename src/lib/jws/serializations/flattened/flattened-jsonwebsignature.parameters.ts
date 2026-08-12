import { Buffer } from 'buffer';

import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';

/**
 * Flattened JSON Web Signature Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.2|RFC 7515 Flattened JWS JSON Serialization Syntax}
 */
export interface FlattenedJsonWebSignatureParameters {
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
   * JSON Web Signature Payload.
   */
  readonly payload?: Buffer;

  /**
   * JSON Web Signature Signature.
   */
  readonly signature: Buffer;
}
