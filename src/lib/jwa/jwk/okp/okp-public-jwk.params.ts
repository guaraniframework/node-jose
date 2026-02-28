import { JwkParams } from '../../../jwk/jwk.params';
import { JwkCrv } from '../jwk-crv.type';

/**
 * OKP Public JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html|RFC 8037 Parameters for Octet Key Pair Keys}
 */
export interface OkpPublicJwkParams extends JwkParams {
  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "kty" parameter}
   */
  readonly kty: 'OKP';

  /**
   * JWK Curve.
   *
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "crv" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 EdDSA "crv" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES "crv" parameter}
   */
  readonly crv: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>;

  /**
   * JWK OKP Public Key.
   *
   * Contains the public key encoded using the base64url encoding.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "x" parameter}
   */
  readonly x: string;
}
