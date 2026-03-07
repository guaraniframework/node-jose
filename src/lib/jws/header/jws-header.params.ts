import { JoseHeaderParams } from '../../jose/jose-header.params';
import { JwsAlg } from '../../jwa/jws/jws-alg.type';

/**
 * Base JWS Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 */
export interface JwsHeaderParams extends JoseHeaderParams {
  /**
   * JOSE Header Algorithm.
   *
   * Identifies the cryptographic algorithm used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" parameter}
   */
  readonly alg: JwsAlg;
}
