import { Buffer } from 'buffer';
import { createHash, KeyObject, X509Certificate } from 'crypto';
import { URL } from 'url';

import { isNonEmptyString, isPlainObject, jsonStringify, removeNullishValues } from '@guarani/primitives';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { JoseAlgorithm } from '../jwa/jose/jose-algorithm.type';
import { KeyOperation } from '../jwa/jwk/key-operation.type';
import { PublicKeyUse } from '../jwa/jwk/public-key-use.type';
import { JsonWebKeyParameters } from './jsonwebkey.parameters';

/**
 * Implementation of the JSON Web Key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JSON Web Key (JWK)}
 */
export abstract class JsonWebKey {
  /**
   * Supported JSON Web Key Public Key Uses.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 Public Key Use Parameter}
   */
  static readonly #publicKeyUses: PublicKeyUse[] = ['enc', 'sig'];

  /**
   * Supported JSON Web Key Key Operations.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 Key Operations Parameter}
   */
  static readonly #keyOperations: KeyOperation[] = [
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
   * Supported JOSE Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  static readonly #algorithms: JoseAlgorithm[] = [
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
    'ES256K',
    'ES384',
    'ES512',
    'EdDSA',
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
   * NodeJS Crypto Key.
   */
  #cryptoKey!: KeyObject;

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  #certificateChain!: X509Certificate[] | null;

  /**
   * NodeJS Crypto Key.
   */
  public get cryptoKey(): KeyObject {
    if (typeof this.#cryptoKey === 'undefined') {
      this.#cryptoKey = this.getCryptoKey();
    }

    return this.#cryptoKey;
  }

  /**
   * NodeJS Crypto Key.
   */
  public set cryptoKey(cryptoKey: KeyObject) {
    if (typeof this.#cryptoKey === 'undefined') {
      this.#cryptoKey = cryptoKey;
    }
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public get certificateChain(): X509Certificate[] | null {
    if (typeof this.#certificateChain === 'undefined') {
      this.#certificateChain = null;
    }

    return this.#certificateChain;
  }

  /**
   * JSON Web Key X.509 Certificate Chain.
   */
  public set certificateChain(certificateChain: X509Certificate[] | null) {
    if (typeof this.#certificateChain === 'undefined') {
      this.#certificateChain = certificateChain;
    }
  }

  /**
   * JSON Web Key Parameters.
   */
  public readonly parameters: JsonWebKeyParameters;

  /**
   * Instantiates a new JSON Web Key Backend.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  public constructor(parameters: JsonWebKeyParameters) {
    (<typeof JsonWebKey>this.constructor).validateJsonWebKeyParameters(parameters);
    this.parameters = removeNullishValues(parameters);
  }

  /**
   * Checks if the provided data is a valid JSON Web Key Parameters object.
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Whether or not the provided data is a valid JSON Web Key Parameters object.
   */
  public static isJsonWebKeyParameters(parameters: unknown): parameters is JsonWebKeyParameters {
    if (!isPlainObject(parameters)) {
      return false;
    }

    try {
      this.validateJsonWebKeyParameters(parameters as JsonWebKeyParameters);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Calculates the JSON Web Key Thumbprint according to
   * {@link https://www.rfc-editor.org/rfc/rfc7638.html|RFC 7638 JSON Web Key (JWK) Thumbprint}.
   *
   * @param hash Hash function supported by OpenSSL used to generate the Thumbprint.
   * @default hash sha-256
   * @returns Generated Thumbprint.
   */
  public getThumbprint(hash: string = 'sha-256'): Buffer {
    return createHash(hash).update(jsonStringify(this.getThumbprintParameters()), 'utf8').digest();
  }

  /**
   * Calculates the JSON Web Key Thumbprint URI according to
   * {@link https://www.rfc-editor.org/rfc/rfc9278.html|RFC 9278 JWK Thumbprint URI}.
   *
   * @param hash Hash function supported by OpenSSL used to generate the Thumbprint.
   * @default hash sha-256
   * @returns Generated Thumbprint URI.
   */
  public getThumbprintURI(hash: string = 'sha-256'): string {
    return `urn:ietf:params:oauth:jwk-thumbprint:${hash}:${this.getThumbprint(hash).toString('base64url')}`;
  }

  /**
   * Returns the JSON Web Key Parameters.
   *
   * @param exportPrivate Exports the private parameters of the JSON Web key.
   * @default exportPrivate false
   * @returns JSON Web Key Parameters.
   */
  public toJSON(exportPrivate: boolean = false): JsonWebKeyParameters {
    const privateParameters = this.getPrivateParameters();
    let entries = Object.entries(this.parameters);

    if (!exportPrivate) {
      entries = entries.filter(([parameter]) => !privateParameters.includes(parameter));
    }

    return Object.fromEntries(entries) as JsonWebKeyParameters;
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
   */
  protected static validateJsonWebKeyParameters(parameters: JsonWebKeyParameters): void {
    if ('use' in parameters && !this.checkIfUseIsAValidPublicKeyUse(parameters.use)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "use".');
    }

    if (
      'key_ops' in parameters &&
      (!this.checkIfKeyOpsIsANonEmptyArrayOfDistinctKeyOperations(parameters.key_ops) ||
        !this.checkIfKeyOpsCombinationIsValid(parameters.key_ops))
    ) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "key_ops".');
    }

    if (
      'key_ops' in parameters &&
      'use' in parameters &&
      !this.checkIfUseAndKeyOpsCombinationIsValid(parameters.use, parameters.key_ops)
    ) {
      throw new InvalidJsonWebKeyError('Invalid combination of JSON Web Key Parameters "use" and "key_ops".');
    }

    if ('alg' in parameters && !this.checkIfAlgIsAValidJoseAlgorithm(parameters.alg)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "alg".');
    }

    if ('kid' in parameters && !isNonEmptyString(parameters.kid)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kid".');
    }

    if ('x5u' in parameters && (!isNonEmptyString(parameters.x5u) || !URL.canParse(parameters.x5u))) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5u".');
    }

    if ('x5c' in parameters && !this.checkIfX5CIsANonEmptyArrayOfStrings(parameters.x5c)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5c".');
    }

    if ('x5t' in parameters && !isNonEmptyString(parameters.x5t)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5t".');
    }

    if ('x5t#S256' in parameters && !isNonEmptyString(parameters['x5t#S256'])) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5t#S256".');
    }

    if ('x5u' in parameters && 'x5c' in parameters) {
      throw new InvalidJsonWebKeyError('Cannot have both "x5u" and "x5c" JSON Web Key Parameters.');
    }

    if (('x5t' in parameters || 'x5t#S256' in parameters) && !('x5u' in parameters) && !('x5c' in parameters)) {
      throw new InvalidJsonWebKeyError(
        'Cannot have an X.509 Certificate Thumbprint without an X.509 Certificate Chain.',
      );
    }
  }

  /**
   * Creates a native Crypto Key.
   *
   * @returns Native Crypto Key.
   */
  protected abstract getCryptoKey(): KeyObject;

  /**
   * Returns the Private Parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  protected abstract getPrivateParameters(): string[];

  /**
   * Returns the JSON Web Key Thumbprint Parameters in lexicographic order.
   *
   * @returns JSON Web Key Thumbprint Parameters.
   */
  protected abstract getThumbprintParameters(): JsonWebKeyParameters;

  // #region Helper Methods
  private static checkIfUseIsAValidPublicKeyUse(use: unknown): use is PublicKeyUse {
    return typeof use === 'string' && JsonWebKey.#publicKeyUses.includes(use as PublicKeyUse);
  }

  private static checkIfKeyOpsIsANonEmptyArrayOfDistinctKeyOperations(keyOps: unknown): keyOps is KeyOperation[] {
    return (
      Array.isArray(keyOps) &&
      keyOps.length !== 0 &&
      keyOps.every((keyOp) => JsonWebKey.#keyOperations.includes(keyOp)) &&
      new Set(keyOps).size === keyOps.length
    );
  }

  private static checkIfKeyOpsCombinationIsValid(keyOps: KeyOperation[]): boolean {
    if (keyOps.length === 1) {
      return true;
    }

    if (keyOps.length > 2) {
      return false;
    }

    const combinations: KeyOperation[][] = [
      ['sign', 'verify'],
      ['encrypt', 'decrypt'],
      ['wrapKey', 'unwrapKey'],
      ['deriveBits', 'deriveKey'],
    ];

    return combinations.some((combination) => keyOps.every((keyOp) => combination.includes(keyOp)));
  }

  private static checkIfUseAndKeyOpsCombinationIsValid(use: PublicKeyUse, keyOps: KeyOperation[]): boolean {
    const encOps: KeyOperation[] = ['decrypt', 'deriveBits', 'deriveKey', 'encrypt', 'unwrapKey', 'wrapKey'];
    const sigOps: KeyOperation[] = ['sign', 'verify'];

    return (
      (use === 'enc' && keyOps.every((keyOp) => encOps.includes(keyOp))) ||
      (use === 'sig' && keyOps.every((keyOp) => sigOps.includes(keyOp)))
    );
  }

  private static checkIfAlgIsAValidJoseAlgorithm(alg: unknown): alg is JoseAlgorithm {
    return typeof alg === 'string' && JsonWebKey.#algorithms.includes(alg as JoseAlgorithm);
  }

  private static checkIfX5CIsANonEmptyArrayOfStrings(x5c: unknown): x5c is string[] {
    return Array.isArray(x5c) && x5c.length !== 0 && x5c.every((certificate) => isNonEmptyString(certificate));
  }
  // #endregion
}
