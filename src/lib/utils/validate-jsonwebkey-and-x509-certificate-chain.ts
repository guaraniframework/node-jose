import { X509Certificate } from 'crypto';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';

/**
 * Checks if the provided X.509 Certificate Chain validates the provided JSON Web Key.
 *
 * @param jsonWebKeyParameters JSON Web Key Parameters to be checked.
 * @param certificateChain X.509 Certificate Chain to be checked.
 * @throws {InvalidJsonWebKeyError} The provided X.509 Certificate Chain does not match the provided JSON Web Key Parameters.
 */
export function validateJsonWebKeyAndX509CertificateChain(
  jsonWebKeyParameters: JsonWebKeyParameters,
  certificateChain: X509Certificate[],
): void {
  // not checking the parameters since two distinct chains could have the same jwk.
  const certificateParameters = certificateChain[0]!.publicKey.export({ format: 'jwk' }) as JsonWebKeyParameters;

  if (Object.entries(certificateParameters).some(([key, value]) => jsonWebKeyParameters[key] !== value)) {
    throw new InvalidJsonWebKeyError(
      'The provided X.509 Certificate Chain does not match the provided JSON Web Key Parameters.',
    );
  }
}
