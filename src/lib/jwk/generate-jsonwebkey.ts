import { EllipticCurveJsonWebKey } from '../jwa/jwk/ec/elliptic-curve.jsonwebkey';
import { EllipticCurveJsonWebKeyParameters } from '../jwa/jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { GenerateEllipticCurveJsonWebKeyOptions } from '../jwa/jwk/ec/generate-elliptic-curve-jsonwebkey.options';
import { KeyType } from '../jwa/jwk/key-type.type';
import { GenerateOctetSequenceJsonWebKeyOptions } from '../jwa/jwk/oct/generate-octet-sequence-jsonwebkey.options';
import { OctetSequenceJsonWebKey } from '../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { OctetSequenceJsonWebKeyParameters } from '../jwa/jwk/oct/octet-sequence-jsonwebkey.parameters';
import { GenerateOctetKeyPairJsonWebKeyOptions } from '../jwa/jwk/okp/generate-octet-key-pair-jsonwebkey.options';
import { OctetKeyPairJsonWebKey } from '../jwa/jwk/okp/octet-key-pair.jsonwebkey';
import { OctetKeyPairJsonWebKeyParameters } from '../jwa/jwk/okp/octet-key-pair-jsonwebkey.parameters';
import { GenerateRsaJsonWebKeyOptions } from '../jwa/jwk/rsa/generate-rsa-jsonwebkey.options';
import { RsaJsonWebKey } from '../jwa/jwk/rsa/rsa.jsonwebkey';
import { RsaJsonWebKeyParameters } from '../jwa/jwk/rsa/rsa-jsonwebkey.parameters';
import { JsonWebKey } from './jsonwebkey';

/**
 * Generates an Elliptic Curve JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Key Type.
 * @param options Elliptic Curve JSON Web Key Generation Options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @returns Generated Elliptic Curve JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'EC',
  options: GenerateEllipticCurveJsonWebKeyOptions,
): Promise<JsonWebKey>;

/**
 * Generates an Octet Key Pair JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Key Type.
 * @param options Octet Key Pair JSON Web Key Generation Options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @returns Generated Octet Key Pair JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'OKP',
  options: GenerateOctetKeyPairJsonWebKeyOptions,
): Promise<JsonWebKey>;

/**
 * Generates an RSA JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Key Type.
 * @param options RSA JSON Web Key Generation Options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @returns Generated RSA JSON Web Key.
 */
export async function generateJsonWebKey(kty: 'RSA', options: GenerateRsaJsonWebKeyOptions): Promise<JsonWebKey>;

/**
 * Generates an Octet Sequence JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Key Type.
 * @param options Octet Sequence JSON Web Key Generation Options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @returns Generated Octet Sequence JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'oct',
  options: GenerateOctetSequenceJsonWebKeyOptions,
): Promise<JsonWebKey>;

/**
 * Generates a JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Key Type.
 * @param options JSON Web Key Generation Options.
 * @throws {TypeError} One of the provided arguments is invalid.
 * @returns Generated JSON Web Key.
 */
export async function generateJsonWebKey(kty: KeyType, options: Record<string, any>): Promise<JsonWebKey> {
  switch (kty) {
    case 'EC': {
      const cryptoKey = await EllipticCurveJsonWebKey.generate(options as GenerateEllipticCurveJsonWebKeyOptions);
      const jwk = new EllipticCurveJsonWebKey(cryptoKey.export({ format: 'jwk' }) as EllipticCurveJsonWebKeyParameters);

      jwk.cryptoKey = cryptoKey;

      return jwk;
    }

    case 'OKP': {
      const cryptoKey = await OctetKeyPairJsonWebKey.generate(options as GenerateOctetKeyPairJsonWebKeyOptions);
      const jwk = new OctetKeyPairJsonWebKey(cryptoKey.export({ format: 'jwk' }) as OctetKeyPairJsonWebKeyParameters);

      jwk.cryptoKey = cryptoKey;

      return jwk;
    }

    case 'RSA': {
      const cryptoKey = await RsaJsonWebKey.generate(options as GenerateRsaJsonWebKeyOptions);
      const jwk = new RsaJsonWebKey(cryptoKey.export({ format: 'jwk' }) as RsaJsonWebKeyParameters);

      jwk.cryptoKey = cryptoKey;

      return jwk;
    }

    case 'oct': {
      const cryptoKey = await OctetSequenceJsonWebKey.generate(options as GenerateOctetSequenceJsonWebKeyOptions);
      const jwk = new OctetSequenceJsonWebKey(cryptoKey.export({ format: 'jwk' }) as OctetSequenceJsonWebKeyParameters);

      jwk.cryptoKey = cryptoKey;

      return jwk;
    }

    default:
      throw new TypeError('The provided JSON Web Key Key Type is invalid.');
  }
}
