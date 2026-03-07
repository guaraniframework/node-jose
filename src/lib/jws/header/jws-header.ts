import { removeNullishValues } from '@guarani/primitives';

import { JoseHeader } from '../../jose/jose-header';
import { JwsAlg } from '../../jwa/jws/jws-alg.type';
import { JwsBackend } from '../../jwa/jws/jws-backend';
import { JWS_BACKEND_REGISTRY } from '../../jwa/jws/jws-backend.registry';
import { JwsHeaderParams } from './jws-header.params';

/**
 * Implementation of the JWS Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JWS JOSE Header}
 */
export class JwsHeader extends JoseHeader implements JwsHeaderParams {
  /**
   * Supported JOSE Header Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" parameter}
   */
  protected static override readonly JOSE_HEADER_ALGS: JwsAlg[] = [
    'ES256',
    'ES384',
    'ES512',
    'HS256',
    'HS384',
    'HS512',
    'PS256',
    'PS384',
    'PS512',
    'RS256',
    'RS384',
    'RS512',
    'none',
  ];

  /**
   * JOSE Header Algorithm.
   *
   * Identifies the cryptographic algorithm used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" parameter}
   */
  public readonly alg!: JwsAlg;

  /**
   * JWS Backend.
   */
  #backend!: JwsBackend;

  /**
   * JWS Backend.
   */
  public get backend(): JwsBackend {
    return this.#backend;
  }

  /**
   * Instantiates a new JWS Header.
   *
   * @param params JWS Header Parameters.
   * @throws {TypeError} The provided JWS Header Parameters argument is invalid.
   * @throws {InvalidJoseHeaderException} The provided JWS Header Parameters are invalid.
   */
  public constructor(params: JwsHeaderParams) {
    super(params);
    Object.assign(this, removeNullishValues(params));
    this.#backend = JWS_BACKEND_REGISTRY[params.alg];
  }

  /**
   * Checks if the provided data is a valid JWS Header.
   *
   * @param data Data to be checked.
   * @returns Boolean indicating if the data is a valid JWS Header.
   */
  public static override isJoseHeader(data: unknown): data is JwsHeaderParams {
    return super.isJoseHeader(data);
  }
}
