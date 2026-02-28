import { EcPublicJwkParams } from './ec-public-jwk.params';

/**
 * EC Private JWK Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2|RFC 7518 Parameters for Elliptic Curve Private Keys}
 */
export interface EcPrivateJwkParams extends EcPublicJwkParams {
  /**
   * JWK ECC Private Key.
   *
   * Contains the Elliptic Curve private key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2.1|RFC 7518 "d" parameter}
   */
  readonly d: string;
}
