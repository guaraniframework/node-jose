import { OkpPublicJwkParams } from './okp-public-jwk.params';

/**
 * OKP Private JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html|RFC 8037 Parameters for Octet Key Pair Keys}
 */
export interface OkpPrivateJwkParams extends OkpPublicJwkParams {
  /**
   * JWK OKP Private Key.
   *
   * Contains the private key encoded using the base64url encoding.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2|RFC 8037 "d" parameter}
   */
  readonly d: string;
}
