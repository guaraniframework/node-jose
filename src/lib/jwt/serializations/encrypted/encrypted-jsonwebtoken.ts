import { JsonWebEncryptionHeader } from '../../../jwe/jsonwebencryption-header';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';

/**
 * Encrypted JSON Web Token.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7519.html|RFC 7519 JSON Web Token (JWT)}
 */
export interface EncryptedJsonWebToken {
  /**
   * JSON Web Token Encrypted Header.
   */
  readonly header: JsonWebEncryptionHeader;

  /**
   * JSON Web Token Claims.
   */
  readonly claims: JsonWebTokenClaims;
}
