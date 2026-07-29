import { isPlainObject } from '@guarani/primitives';

import { getJsonWebKeyFromJoseHeader } from '../utils/get-jsonwebkey-from-jose-header';
import { getX509CertificateChain } from '../utils/get-x509-certificate-chain';
import { validateJsonWebKeyAndX509CertificateChain } from '../utils/validate-jsonwebkey-and-x509-certificate-chain';
import { JsonWebSignatureHeader } from './jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from './jsonwebsignature-header.parameters';

/**
 * Creates a JSON Web Signature Header based on the provided JSON Web Signature Header Parameters.
 *
 * @param parameters JSON Web Signature Header Parameters.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters are invalid.
 * @returns JSON Web Signature Header.
 */
export async function createJsonWebSignatureHeader(
  parameters: JsonWebSignatureHeaderParameters,
): Promise<JsonWebSignatureHeader> {
  if (!isPlainObject(parameters)) {
    throw new TypeError('The provided JSON Web Signature Header Parameters is invalid.');
  }

  const header = new JsonWebSignatureHeader(parameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(parameters);
  const certificateChain = await getX509CertificateChain(parameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header;
}
