import { Buffer } from 'buffer';
import { X509Certificate } from 'crypto';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { isDeepStrictEqual } from 'util';

import { isPlainObject, jsonParse } from '@guarani/primitives';

import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { JweAlg } from '../jwa/jwe/jwe-alg.type';
import { EcPublicJwk } from '../jwa/jwk/ec/ec-public-jwk';
import { EcPublicJwkParams } from '../jwa/jwk/ec/ec-public-jwk.params';
import { OctJwk } from '../jwa/jwk/oct/oct-jwk';
import { OctJwkParams } from '../jwa/jwk/oct/oct-jwk.params';
import { OkpPublicJwk } from '../jwa/jwk/okp/okp-public-jwk';
import { OkpPublicJwkParams } from '../jwa/jwk/okp/okp-public-jwk.params';
import { RsaPublicJwk } from '../jwa/jwk/rsa/rsa-public-jwk';
import { RsaPublicJwkParams } from '../jwa/jwk/rsa/rsa-public-jwk.params';
import { JwsAlg } from '../jwa/jws/jws-alg.type';
import { Jwk } from '../jwk/jwk';
import { JwkParams } from '../jwk/jwk.params';
import { Jwks } from '../jwks/jwks';
import { JwksParams } from '../jwks/jwks.params';
import { JoseHeaderParams } from './jose-header.params';

/**
 * Jose Header Base Class.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export abstract class JoseHeader implements JoseHeaderParams {
  /**
   * Supported JOSE Header Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" parameter}
   */
  protected static readonly JOSE_HEADER_ALGS: (JwsAlg | JweAlg)[] = [
    'A128GCMKW',
    'A128KW',
    'A192GCMKW',
    'A192KW',
    'A256GCMKW',
    'A256KW',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
    'ES256',
    'ES384',
    'ES512',
    'HS256',
    'HS384',
    'HS512',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW',
    'PS256',
    'PS384',
    'PS512',
    'RS256',
    'RS384',
    'RS512',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'RSA-OAEP-384',
    'RSA-OAEP-512',
    'RSA1_5',
    'dir',
    'none',
  ];

  /**
   * JOSE Header Algorithm.
   *
   * Identifies the cryptographic algorithm used to secure the JWS,
   * or to encrypt or determine the value of the CEK.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" parameter}
   */
  public abstract readonly alg: JwsAlg | JweAlg;

  /**
   * JOSE Header JWK Set URL.
   *
   * URI that refers to a resource for a set of JSON-encoded public keys,
   * one of which corresponds to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2|RFC 7515 "jku" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.4|RFC 7516 "jku" parameter}
   */
  public readonly jku?: string;

  /**
   * JOSE Header JSON Web Key.
   *
   * Public key that corresponds to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3|RFC 7515 "jwk" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.5|RFC 7516 "jwk" parameter}
   */
  public readonly jwk?: JwkParams;

  /**
   * JOSE Header Key ID.
   *
   * Hint indicating which key was used to secure the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4|RFC 7515 "kid" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6|RFC 7516 "kid" parameter}
   */
  public readonly kid?: string;

  /**
   * JOSE Header X.509 URL.
   *
   * URI that refers to a resource for the X.509 public key certificate
   * or certificate chain corresponding to the key used to digitally sign the JWS,
   * or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5|RFC 7515 "x5u" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7|RFC 7516 "x5u" parameter}
   */
  public readonly x5u?: string;

  /**
   * JOSE Header X.509 Certificate Chain.
   *
   * X.509 public key certificate or certificate chain corresponding
   * to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6|RFC 7515 "x5c" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8|RFC 7516 "x5c" parameter}
   */
  public readonly x5c?: string[];

  /**
   * JOSE Header X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7|RFC 7515 "x5t" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9|RFC 7516 "x5t" parameter}
   */
  public readonly x5t?: string;

  /**
   * JOSE Header X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8|RFC 7515 "x5t#S256" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10|RFC 7516 "x5t#S256" parameter}
   */
  public readonly 'x5t#S256'?: string;

  /**
   * JOSE Header Type.
   *
   * Used by JWS applications to declare the media type of this complete JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9|RFC 7515 "typ" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.11|RFC 7516 "typ" parameter}
   */
  public readonly typ?: string;

  /**
   * JOSE Header Content Type.
   *
   * Used by JWS applications to declare the media type of the secured content (payload/plaintext).
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10|RFC 7515 "cty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.12|RFC 7516 "cty" parameter}
   */
  public readonly cty?: string;

  /**
   * JOSE Header Critical.
   *
   * Indicates that extensions to this specification and/or JWA are being used
   * that MUST be understood and processed.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11|RFC 7515 "crit" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.13|RFC 7516 "crit" parameter}
   */
  public readonly crit?: string[];

  /**
   * Additional JOSE Header Parameters.
   */
  readonly [parameter: string]: unknown;

  /**
   * Instantiates a new Jose Header.
   *
   * @param params Jose Header Parameters.
   * @throws {TypeError} The provided Jose Header Parameters argument is invalid.
   * @throws {InvalidJoseHeaderException} The provided Jose Header Parameters are invalid.
   */
  public constructor(params: JoseHeaderParams) {
    if (!isPlainObject(params)) {
      throw new TypeError('Invalid parameter "params".');
    }

    JoseHeader.validateJoseHeaderParameters(params);
    Object.assign(this, params);
  }

  /**
   * Checks if the provided data is a valid Jose Header.
   *
   * @param data Data to be checked.
   * @returns Boolean indicating if the data is a valid Jose Header.
   */
  public static isJoseHeader(data: unknown): data is JoseHeaderParams {
    if (!isPlainObject(data)) {
      return false;
    }

    try {
      JoseHeader.validateJoseHeaderParameters(data as JoseHeaderParams);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validates the provided Jose Header Parameters.
   *
   * @param params Jose Header Parameters.
   * @throws {InvalidJoseHeaderException} The provided Jose Header Parameters are invalid.
   */
  protected static validateJoseHeaderParameters(params: JoseHeaderParams): void {
    if (!JoseHeader.JOSE_HEADER_ALGS.includes(params.alg)) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "alg".');
    }

    if (typeof params.jku !== 'undefined' && (typeof params.jku !== 'string' || !URL.canParse(params.jku))) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "jku".');
    }

    if (typeof params.jwk !== 'undefined' && !isPlainObject(params.jwk)) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "jwk".');
    }

    if (typeof params.jku !== 'undefined' && typeof params.jwk !== 'undefined') {
      throw new InvalidJoseHeaderException('Cannot have both "jku" and "jwk" jose header parameters.');
    }

    if (typeof params.kid !== 'undefined' && typeof params.kid !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "kid".');
    }

    let key: Jwk | null = null;

    if (typeof params.jku !== 'undefined' || typeof params.jwk !== 'undefined') {
      if (typeof params.jku !== 'undefined') {
        if (typeof params.kid === 'undefined') {
          throw new InvalidJoseHeaderException('Missing jose header parameter "kid" when providing "jku".');
        }

        const jwks = this.getJwkSetFromUrl(params.jku);

        try {
          key = jwks.get((jwk) => jwk.kid === params.kid);
        } catch (exception: unknown) {
          throw new InvalidJoseHeaderException(`Could not find the jwk "${String(params.kid)}" in the jwks.`, {
            cause: exception,
          });
        }
      }

      if (typeof params.jwk !== 'undefined') {
        try {
          switch (params.jwk.kty) {
            case 'EC':
              key = new EcPublicJwk(params.jwk as EcPublicJwkParams);
              break;

            case 'OKP':
              key = new OkpPublicJwk(params.jwk as OkpPublicJwkParams);
              break;

            case 'RSA':
              key = new RsaPublicJwk(params.jwk as RsaPublicJwkParams);
              break;

            case 'oct':
              key = new OctJwk(params.jwk as OctJwkParams);
              break;

            default:
              throw new Error(); // TODO: Move this to JWK.
          }
        } catch (exception: unknown) {
          throw new InvalidJoseHeaderException('The jwk provided in the jose header is invalid.', { cause: exception });
        }

        if (typeof params.kid !== 'undefined' && key.kid !== params.kid) {
          throw new InvalidJoseHeaderException('Mismatching jose header parameter "kid" and "jwk.kid".');
        }
      }
    }

    if (
      (typeof params.x5t !== 'undefined' || typeof params['x5t#S256'] !== 'undefined') &&
      typeof params.x5u === 'undefined' &&
      typeof params.x5c === 'undefined'
    ) {
      throw new InvalidJoseHeaderException('Cannot have a certificate thumbprint without a certificate chain.');
    }

    if (typeof params.x5u !== 'undefined' || typeof params.x5c !== 'undefined') {
      if (key === null) {
        throw new InvalidJoseHeaderException('Missing jwk for the provided certificate chain.');
      }

      if (typeof params.x5u !== 'undefined' && typeof params.x5c !== 'undefined') {
        throw new InvalidJoseHeaderException('Cannot have both "x5u" and "x5c" jose header parameters.');
      }

      if (
        typeof params.x5u !== 'undefined' &&
        (typeof params.x5u !== 'string' ||
          !URL.canParse(params.x5u) ||
          (typeof key.x5u !== 'undefined' && params.x5u !== key.x5u))
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "x5u".');
      }

      if (
        typeof params.x5c !== 'undefined' &&
        (!Array.isArray(params.x5c) ||
          params.x5c.length === 0 ||
          params.x5c.some((cert) => typeof cert !== 'string') ||
          (typeof key.x5c !== 'undefined' && !isDeepStrictEqual(params.x5c, key.x5c)))
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "x5c".');
      }

      if (
        typeof params.x5t !== 'undefined' &&
        (typeof params.x5t !== 'string' || (typeof key.x5t !== 'undefined' && params.x5t !== key.x5t))
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "x5t".');
      }

      if (
        typeof params['x5t#S256'] !== 'undefined' &&
        (typeof params['x5t#S256'] !== 'string' ||
          (typeof key['x5t#S256'] !== 'undefined' && params['x5t#S256'] !== key['x5t#S256']))
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "x5t#S256".');
      }

      let certificateChain!: X509Certificate[];

      if (typeof params.x5c !== 'undefined') {
        certificateChain = this.validateX509PemCertificateChain(params.x5c, key);
      }

      if (typeof params.x5u !== 'undefined') {
        const pemCertificateChain = this.getX509PemCertificateChainFromUrl(params.x5u);
        certificateChain = this.validateX509PemCertificateChain(pemCertificateChain, key);
      }

      if (typeof params.x5t !== 'undefined' && params.x5t !== certificateChain[0]!.fingerprint) {
        throw new InvalidJoseHeaderException('Mismatching certificate sha-1 thumbprint.');
      }

      if (typeof params['x5t#S256'] !== 'undefined' && params['x5t#S256'] !== certificateChain[0]!.fingerprint256) {
        throw new InvalidJoseHeaderException('Mismatching certificate sha-256 thumbprint.');
      }
    }

    if (typeof params.typ !== 'undefined' && typeof params.typ !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "typ".');
    }

    if (typeof params.cty !== 'undefined' && typeof params.cty !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "cty".');
    }

    if (typeof params.crit !== 'undefined') {
      if (
        !Array.isArray(params.crit) ||
        params.crit.length === 0 ||
        params.crit.some((param) => typeof param !== 'string' || param.length === 0)
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "crit".');
      }

      params.crit.forEach((param) => {
        if (!Object.hasOwn(params, param)) {
          throw new InvalidJoseHeaderException(`Missing required jose header parameter "${String(param)}".`);
        }
      });
    }
  }

  /**
   * Fetches a JWK Set from the provided URL.
   *
   * @param url JWK Set URL.
   * @throws {InvalidJoseHeaderException} The request to the jku fails or returns an invalid jwks.
   * @returns JWK Set.
   */
  private static getJwkSetFromUrl(url: string): Jwks {
    let jwks!: Jwks;

    const { get } = url.startsWith('https') ? https : http;

    get(url, (res) => {
      let data = '';
      res.on('data', (chunk: string) => (data += chunk.replaceAll('\n', '')));
      res.on('end', () => {
        try {
          const jwksParams = jsonParse(data) as JwksParams;
          jwks = new Jwks(
            jwksParams.keys
              .filter((key) => ['EC', 'OKP', 'RSA', 'oct'].includes(key.kty))
              .map((key) => {
                // TODO: Move this check to JWK.
                switch (key.kty) {
                  case 'EC':
                    return new EcPublicJwk(key as EcPublicJwkParams);

                  case 'OKP':
                    return new OkpPublicJwk(key as OkpPublicJwkParams);

                  case 'RSA':
                    return new RsaPublicJwk(key as RsaPublicJwkParams);

                  case 'oct':
                    return new OctJwk(key as OctJwkParams);

                  default:
                    throw new Error('This never happens.'); // appeasing array-callback-return
                }
              }),
          );
        } catch (exception: unknown) {
          throw new InvalidJoseHeaderException('Invalid jku url.');
        }
      });
      res.on('error', (err) => {
        throw new InvalidJoseHeaderException('Error reading the jwks from the url.', { cause: err });
      });
    });

    return jwks;
  }

  /**
   * Validates an X.509 PEM Certificate Chain and returns its parsed values.
   *
   * @param pemCertChain X.509 PEM Certificate Chain.
   * @param params JWK Parameters.
   * @throws {InvalidJoseHeaderException} X.509 Certificate Chain validation error.
   * @returns X.509 Certificate Chain.
   */
  private static validateX509PemCertificateChain(pemCertChain: string[], params: JwkParams): X509Certificate[] {
    let certChain!: X509Certificate[];

    try {
      certChain = pemCertChain.map((pemCert) => new X509Certificate(Buffer.from(pemCert, 'base64')));
    } catch (exception: unknown) {
      throw new InvalidJoseHeaderException('One or more certificates are invalid.', { cause: exception });
    }

    // TODO: Check keyUsage and signatureAlgorithm
    const now = new Date();

    if (certChain.some((cert) => now < cert.validFromDate)) {
      throw new InvalidJoseHeaderException('One or more certificates are not yet valid.');
    }

    if (certChain.some((cert) => now >= cert.validToDate)) {
      throw new InvalidJoseHeaderException('One or more certificates are expired.');
    }

    if (
      Object.entries(certChain[0]!.publicKey.export({ format: 'jwk' })).some(([key, value]) => params[key] !== value)
    ) {
      throw new InvalidJoseHeaderException('The provided certificate does not match the jwk.');
    }

    for (let i = 0; i < certChain.length - 1; i++) {
      const currentCert = certChain[i]!;
      const nextCert = certChain[i + 1]!;

      if (!currentCert.verify(nextCert.publicKey)) {
        throw new InvalidJoseHeaderException('Invalid certificate chain.');
      }
    }

    return certChain;
  }

  /**
   * Fetches an X.509 PEM Certificate Chain from the provided URL.
   *
   * @param url X.509 PEM Certificate Chain URL.
   * @throws {InvalidJoseHeaderException} The request to the x5u fails or returns an invalid certificate chain.
   * @returns X.509 PEM Certificate Chain.
   */
  private static getX509PemCertificateChainFromUrl(url: string): string[] {
    let certificates: string[] = [];

    const { get } = url.startsWith('https') ? https : http;

    get(url, (res) => {
      let data = '';
      res.on('data', (chunk: string) => (data += chunk.replaceAll('\n', '')));
      res.on('end', () => {
        const pemCerts = data.match(/-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----/gm);

        if (pemCerts === null) {
          throw new InvalidJoseHeaderException('Invalid X.509 URL.');
        }

        certificates = pemCerts.map((pemCert) =>
          pemCert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', ''),
        );
      });
      res.on('error', (err) => {
        throw new InvalidJoseHeaderException('Error reading the certificate chain from the url.', { cause: err });
      });
    });

    return certificates;
  }
}
