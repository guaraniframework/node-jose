import { X509Certificate } from 'crypto';

import { isNonEmptyString, isPlainObject } from '@guarani/primitives';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { EllipticCurveJsonWebKey } from '../jwa/jwk/ec/elliptic-curve.jsonwebkey';
import { OctetSequenceJsonWebKey } from '../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { OctetKeyPairJsonWebKey } from '../jwa/jwk/okp/octet-key-pair.jsonwebkey';
import { RsaJsonWebKey } from '../jwa/jwk/rsa/rsa.jsonwebkey';
import { getX509CertificateChain } from '../utils/get-x509-certificate-chain';
import { validateJsonWebKeyAndX509CertificateChain } from '../utils/validate-jsonwebkey-and-x509-certificate-chain';
import { JsonWebKey } from './jsonwebkey';
import { JsonWebKeyParameters } from './jsonwebkey.parameters';

/**
 * Creates a JSON Web Key based on the provided Parameters.
 *
 * @param parameters JSON Web Key Parameters.
 * @throws {TypeError} The provided JSON Web Key Parameters is invalid.
 * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters are invalid.
 * @returns JSON Web Key.
 */
export async function createJsonWebKey(parameters: JsonWebKeyParameters): Promise<JsonWebKey> {
  if (!isPlainObject(parameters)) {
    throw new TypeError('The provided JSON Web Key Parameters is invalid.');
  }

  if (!('kty' in parameters) || !isNonEmptyString(parameters.kty)) {
    throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
  }

  let jwk: JsonWebKey;

  switch (parameters.kty) {
    case 'EC':
      jwk = new EllipticCurveJsonWebKey(parameters);
      break;

    case 'OKP':
      jwk = new OctetKeyPairJsonWebKey(parameters);
      break;

    case 'RSA':
      jwk = new RsaJsonWebKey(parameters);
      break;

    case 'oct':
      jwk = new OctetSequenceJsonWebKey(parameters);
      break;

    default:
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kty".');
  }

  jwk.certificateChain = await getJsonWebKeyX509CertificateChain(parameters);

  return jwk;
}

async function getJsonWebKeyX509CertificateChain(parameters: JsonWebKeyParameters): Promise<X509Certificate[] | null> {
  const certificateChain = await getX509CertificateChain(parameters);

  if (certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(parameters, certificateChain);
  }

  return certificateChain;
}
