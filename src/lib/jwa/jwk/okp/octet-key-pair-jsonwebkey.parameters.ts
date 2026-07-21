import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';
import { EdwardsMontgomeryCurve } from './edwards-montgomery-curve.type';

/**
 * Octet Key Pair JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
 */
export interface OctetKeyPairJsonWebKeyParameters extends JsonWebKeyParameters {
  /**
   * Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
   */
  readonly kty: 'OKP';

  /**
   * Curve.
   *
   * Contains the subtype of the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   */
  readonly crv: EdwardsMontgomeryCurve;

  /**
   * Public Key.
   *
   * Contains the public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
   */
  readonly x: string;

  /**
   * Private Key.
   *
   * Contains the private key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 Key Type "OKP"}
   */
  readonly d?: string;
}
