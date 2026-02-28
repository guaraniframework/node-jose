import { Buffer } from 'buffer';
import { createHash, KeyObject, X509Certificate } from 'crypto';
import http from 'http';
import https from 'https';
import { URL } from 'url';

import { isPlainObject, removeNullishValues } from '@guarani/primitives';

import { InvalidJwkException } from '../exceptions/invalid-jwk.exception';
import { JweAlg } from '../jwa/jwe/jwe-alg.type';
import { JwkKeyOp } from '../jwa/jwk/jwk-key-op.type';
import { JwkKty } from '../jwa/jwk/jwk-kty.type';
import { JwkUse } from '../jwa/jwk/jwk-use.type';
import { JwsAlg } from '../jwa/jws/jws-alg.type';
import { JwkParams } from './jwk.params';

/**
 * JWK Base Class.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JWK}
 */
export abstract class Jwk<T extends JwkParams = JwkParams> implements JwkParams {
  /**
   * Supported JWK Public Key Uses.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 "use" parameter}
   */
  private static readonly JWK_USES: JwkUse[] = ['enc', 'sig'];

  /**
   * Supported JWK Key Operations.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 "key_ops" parameter}
   */
  private static readonly JWK_KEY_OPS: JwkKeyOp[] = [
    'decrypt',
    'deriveBits',
    'deriveKey',
    'encrypt',
    'sign',
    'unwrapKey',
    'verify',
    'wrapKey',
  ];

  /**
   * JWK Key Type.
   *
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" parameter}
   */
  public abstract readonly kty: JwkKty;

  /**
   * JWK Public Key Use.
   *
   * Identifies the intended use of the public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 "use" parameter}
   */
  public use?: JwkUse;

  /**
   * JWK Key Operations.
   *
   * Identifies the operation(s) for which the key is intended to be used.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 "key_ops" parameter}
   */
  public key_ops?: JwkKeyOp[];

  /**
   * JWK Algorithm.
   *
   * Identifies the algorithm intended for use with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4|RFC 7517 "alg" parameter}
   */
  public alg?: JwsAlg | JweAlg;

  /**
   * JWK Key ID.
   *
   * Used to match a specific key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5|RFC 7517 "kid" parameter}
   */
  public kid?: string;

  /**
   * JWK X.509 URL.
   *
   * URI that refers to a resource for an X.509 public key certificate or certificate chain.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6|RFC 7517 "x5u" parameter}
   */
  public x5u?: string;

  /**
   * JWK X.509 Certificate Chain.
   *
   * Contains a chain of one or more PKIX certificates.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7|RFC 7517 "x5c" parameter}
   */
  public x5c?: string[];

  /**
   * JWK X.509 Certificate SHA-1 Thumbprint.
   *
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8|RFC 7517 "x5t" parameter}
   */
  public x5t?: string;

  /**
   * JWK X.509 Certificate SHA-256 Thumbprint.
   *
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.9|RFC 7517 "x5t#S256" parameter}
   */
  public 'x5t#S256'?: string;

  /**
   * Additional JWK Parameters.
   */
  [parameter: string]: unknown;

  /**
   * NodeJS Crypto Key.
   */
  #cryptoKey!: KeyObject;

  /**
   * NodeJS Crypto Key.
   */
  public get cryptoKey(): KeyObject {
    return this.#cryptoKey;
  }

  /**
   * NodeJS Crypto Key.
   */
  protected set cryptoKey(cryptoKey: KeyObject) {
    this.#cryptoKey = cryptoKey;
  }

  /**
   * Instantiates a new JWK.
   *
   * @param params JWK Parameters.
   * @throws {TypeError} The provided JWK Parameters argument is invalid.
   * @throws {InvalidJwkException} The provided JWK Parameters are invalid.
   */
  public constructor(params: T) {
    if (!isPlainObject(params)) {
      throw new TypeError('Invalid parameter "params".');
    }

    this.validateJwkParameters(params);
    Object.assign(this, params);
  }

  /**
   * Calculates the jwk thumbprint according to **RFC 7638 JSON Web Key (JWK) Thumbprint**.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7638.html|RFC 7638}
   *
   * @param hash Hash function supported by OpenSSL used to generate the thumbprint.
   * @default hash sha256
   * @returns Generated thumbprint buffer.
   */
  public getThumbprint(hash: string = 'sha256'): Buffer {
    return createHash(hash).update(JSON.stringify(this.getThumbprintParameters()), 'utf8').digest();
  }

  /**
   * Returns the JWK Parameters.
   */
  public toJSON(): T {
    return removeNullishValues(
      <T>(
        Object.fromEntries(
          Object.entries(this).filter(
            ([key]) => typeof key !== 'bigint' && typeof key !== 'function' && typeof key !== 'symbol',
          ),
        )
      ),
    );
  }

  /**
   * Returns the parameters used to calculate the JWK Thumbprint in lexicographic order.
   */
  protected abstract getThumbprintParameters(): T;

  /**
   * Validates the provided JWK Parameters.
   *
   * @param params JWK Parameters.
   */
  protected validateJwkParameters(params: T): void {
    if (typeof params.use !== 'undefined' && !Jwk.JWK_USES.includes(params.use)) {
      throw new InvalidJwkException('Invalid jwk parameter "use".');
    }

    if (typeof params.key_ops !== 'undefined') {
      if (
        !Array.isArray(params.key_ops) ||
        params.key_ops.length === 0 ||
        params.key_ops.some((keyOp) => !Jwk.JWK_KEY_OPS.includes(keyOp))
      ) {
        throw new InvalidJwkException('Invalid jwk parameter "key_ops".');
      }

      if (new Set(params.key_ops).size !== params.key_ops.length) {
        throw new InvalidJwkException('The jwk parameter "key_ops" cannot have repeated operations.');
      }
    }

    const encOps: JwkKeyOp[] = ['decrypt', 'deriveBits', 'deriveKey', 'encrypt', 'unwrapKey', 'wrapKey'];
    const sigOps: JwkKeyOp[] = ['sign', 'verify'];

    if (
      typeof params.use !== 'undefined' &&
      typeof params.key_ops !== 'undefined' &&
      ((params.use === 'enc' && params.key_ops.some((keyOp) => !encOps.includes(keyOp))) ||
        (params.use === 'sig' && params.key_ops.some((keyOp) => !sigOps.includes(keyOp))))
    ) {
      throw new InvalidJwkException('Invalid combination of "use" and "key_ops".');
    }

    // TODO: Check against jws/jwe registry.
    if (typeof params.alg !== 'undefined' && typeof params.alg !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "alg".');
    }

    if (typeof params.kid !== 'undefined' && typeof params.kid !== 'string') {
      throw new InvalidJwkException('Invalid jwk parameter "kid".');
    }

    if (
      (typeof params.x5t !== 'undefined' || typeof params['x5t#S256'] !== 'undefined') &&
      typeof params.x5u === 'undefined' &&
      typeof params.x5c === 'undefined'
    ) {
      throw new InvalidJwkException('Cannot have a certificate thumbprint without a certificate chain.');
    }

    if (typeof params.x5u !== 'undefined' || typeof params.x5c !== 'undefined') {
      if (typeof params.x5u !== 'undefined' && typeof params.x5c !== 'undefined') {
        throw new InvalidJwkException('Cannot have both "x5u" and "x5c" jwk parameters.');
      }

      if (typeof params.x5u !== 'undefined' && (typeof params.x5u !== 'string' || !URL.canParse(params.x5u))) {
        throw new InvalidJwkException('Invalid jwk parameter "x5u".');
      }

      if (
        typeof params.x5c !== 'undefined' &&
        (!Array.isArray(params.x5c) || params.x5c.length === 0 || params.x5c.some((cert) => typeof cert !== 'string'))
      ) {
        throw new InvalidJwkException('Invalid jwk parameter "x5c".');
      }

      if (typeof params.x5t !== 'undefined' && typeof params.x5t !== 'string') {
        throw new InvalidJwkException('Invalid jwk parameter "x5t".');
      }

      if (typeof params['x5t#S256'] !== 'undefined' && typeof params['x5t#S256'] !== 'string') {
        throw new InvalidJwkException('Invalid jwk parameter "x5t#S256".');
      }

      let certificateChain!: X509Certificate[];

      if (typeof params.x5c !== 'undefined') {
        certificateChain = this.validateX509PemCertificateChain(params.x5c, params);
      }

      if (typeof params.x5u !== 'undefined') {
        const pemCertificateChain = this.getX509PemCertificateChainFromUrl(params.x5u);
        certificateChain = this.validateX509PemCertificateChain(pemCertificateChain, params);
      }

      if (typeof params.x5t !== 'undefined' && params.x5t !== certificateChain[0]!.fingerprint) {
        throw new InvalidJwkException('Mismatching certificate sha-1 thumbprint.');
      }

      if (typeof params['x5t#S256'] !== 'undefined' && params['x5t#S256'] !== certificateChain[0]!.fingerprint256) {
        throw new InvalidJwkException('Mismatching certificate sha-256 thumbprint.');
      }
    }
  }

  /**
   * Validates an X.509 PEM Certificate Chain and returns its parsed values.
   *
   * @param pemCertChain X.509 PEM Certificate Chain.
   * @param params JWK Parameters.
   * @returns X.509 Certificate Chain.
   */
  private validateX509PemCertificateChain(pemCertChain: string[], params: JwkParams): X509Certificate[] {
    let certChain!: X509Certificate[];

    try {
      certChain = pemCertChain.map((pemCert) => new X509Certificate(Buffer.from(pemCert, 'base64')));
    } catch (exception: unknown) {
      throw new InvalidJwkException('One or more certificates are invalid.', { cause: exception });
    }

    // TODO: Check keyUsage and signatureAlgorithm
    const now = new Date();

    if (certChain.some((cert) => now < cert.validFromDate)) {
      throw new InvalidJwkException('One or more certificates are not yet valid.');
    }

    if (certChain.some((cert) => now >= cert.validToDate)) {
      throw new InvalidJwkException('One or more certificates are expired.');
    }

    if (
      Object.entries(certChain[0]!.publicKey.export({ format: 'jwk' })).some(([key, value]) => params[key] !== value)
    ) {
      throw new InvalidJwkException('The provided certificate does not match the jwk.');
    }

    for (let i = 0; i < certChain.length - 1; i++) {
      const currentCert = certChain[i]!;
      const nextCert = certChain[i + 1]!;

      if (!currentCert.verify(nextCert.publicKey)) {
        throw new InvalidJwkException('Invalid certificate chain.');
      }
    }

    return certChain;
  }

  /**
   * Fetches an X.509 PEM Certificate Chain from the provided URL.
   *
   * @param url X.509 PEM Certificate Chain URL.
   * @returns X.509 PEM Certificate Chain.
   */
  private getX509PemCertificateChainFromUrl(url: string): string[] {
    let certificates: string[] = [];

    const { get } = url.startsWith('https') ? https : http;

    get(url, (res) => {
      let data = '';
      res.on('data', (chunk: string) => (data += chunk.replaceAll('\n', '')));
      res.on('end', () => {
        const pemCerts = data.match(/-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----/gm);

        if (pemCerts === null) {
          throw new InvalidJwkException('Invalid X.509 URL.');
        }

        certificates = pemCerts.map((pemCert) =>
          pemCert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', ''),
        );
      });
      res.on('error', (err) => {
        throw new InvalidJwkException('Error reading the certificate chain from the url.', { cause: err });
      });
    });

    return certificates;
  }
}
