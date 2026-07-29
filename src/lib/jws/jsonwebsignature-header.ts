import { isNonEmptyString } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JoseHeader } from '../jose/jose-header';
import { DigitalSignatureAlgorithm } from '../jwa/jws/digital-signature-algorithm.type';
import { ECDSAJsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/ecdsa/ecdsa-jsonwebsignature-digital-signature.backend';
import { EdDSAJsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/eddsa/eddsa-jsonwebsignature-digital-signature.backend';
import { HMACJsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/hmac/hmac-jsonwebsignature-digital-signature.backend';
import { JsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/jsonwebsignature-digital-signature.backend';
import { NoneJsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/none/none-jsonwebsignature-digital-signature.backend';
import { RSASSAJsonWebSignatureDigitalSignatureBackend } from '../jwa/jws/rsassa/rsassa-jsonwebsignature-digital-signature.backend';
import { JsonWebSignatureHeaderParameters } from './jsonwebsignature-header.parameters';

/**
 * Implementation of the JSON Web Signature Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 */
export class JsonWebSignatureHeader extends JoseHeader {
  /**
   * Supported JSON Web Signature Digital Signature Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  static readonly #digitalSignatureAlgorithms: DigitalSignatureAlgorithm[] = [
    'ES256',
    'ES256K',
    'ES384',
    'ES512',
    'EdDSA',
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
   * JSON Web Signature Header Parameters.
   */
  declare public readonly parameters: JsonWebSignatureHeaderParameters;

  /**
   * JSON Web Signature Digital Signature Backend.
   */
  public readonly digitalSignatureBackend: JsonWebSignatureDigitalSignatureBackend;

  /**
   * Instantiates a new JSON Web Signature Header.
   *
   * @param parameters JSON Web Signature Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters are invalid.
   */
  public constructor(parameters: JsonWebSignatureHeaderParameters) {
    super(parameters);

    this.digitalSignatureBackend = JsonWebSignatureHeader.getDigitalSignatureBackend(parameters);
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters are invalid.
   */
  protected static override validateJoseHeaderParameters(parameters: JsonWebSignatureHeaderParameters): void {
    super.validateJoseHeaderParameters(parameters);

    if (!isNonEmptyString(parameters.alg) || !this.#digitalSignatureAlgorithms.includes(parameters.alg)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
    }

    if ('b64' in parameters && (typeof parameters.b64 !== 'boolean' || parameters.crit?.includes('b64') !== true)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "b64".');
    }
  }

  // #region Private Methods.
  private static getDigitalSignatureBackend(
    parameters: JsonWebSignatureHeaderParameters,
  ): JsonWebSignatureDigitalSignatureBackend {
    switch (parameters.alg) {
      case 'ES256':
      case 'ES256K':
      case 'ES384':
      case 'ES512':
        return new ECDSAJsonWebSignatureDigitalSignatureBackend(parameters.alg);

      case 'EdDSA':
        return new EdDSAJsonWebSignatureDigitalSignatureBackend();

      case 'HS256':
      case 'HS384':
      case 'HS512':
        return new HMACJsonWebSignatureDigitalSignatureBackend(parameters.alg);

      case 'PS256':
      case 'PS384':
      case 'PS512':
      case 'RS256':
      case 'RS384':
      case 'RS512':
        return new RSASSAJsonWebSignatureDigitalSignatureBackend(parameters.alg);

      case 'none':
        return new NoneJsonWebSignatureDigitalSignatureBackend();
    }
  }
  // #endregion
}
