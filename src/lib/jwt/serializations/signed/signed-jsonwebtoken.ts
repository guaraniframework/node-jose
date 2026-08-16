import { JsonWebSignatureHeader } from '../../../jws/jsonwebsignature-header';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';

/**
 * Signed JSON Web Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface SignedJsonWebToken {
  /**
   * JSON Web Token Signature Header.
   */
  readonly header: JsonWebSignatureHeader;

  /**
   * JSON Web Token Claims.
   */
  readonly claims: JsonWebTokenClaims;
}
